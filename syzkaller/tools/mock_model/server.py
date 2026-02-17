"""gRPC server for the BiGRU syscall sequence prediction model.

Serves PredictNext, Health, and Retrain RPCs for the Go fuzzer client.
"""

import os
import sys
import time
import logging
import threading
from concurrent import futures

import grpc
import torch

# Add proto directory to path.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "proto"))

import mock_pb2
import mock_pb2_grpc
from model import SyscallBiGRU, Vocabulary
from train import train_model

logger = logging.getLogger(__name__)

DEFAULT_PORT = 50051
DEFAULT_MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pt")
DEFAULT_VOCAB_PATH = os.path.join(os.path.dirname(__file__), "vocab.pt")
DEFAULT_TRAINING_DATA_PATH = os.path.join(os.path.dirname(__file__), "training_data.jsonl")


class MockModelServicer(mock_pb2_grpc.MockModelServicer):
    """Implements the MockModel gRPC service."""

    def __init__(self, model_path: str = DEFAULT_MODEL_PATH,
                 vocab_path: str = DEFAULT_VOCAB_PATH,
                 device: str = None,
                 training_data_path: str = DEFAULT_TRAINING_DATA_PATH):
        self.model_path = model_path
        self.vocab_path = vocab_path
        self.training_data_path = training_data_path
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.model = None
        self.vocab = None
        self.training_samples = 0
        self.model_version = "0.0"
        self.lock = threading.Lock()
        self.inference_count = 0
        self.collect_training_data = True  # Phase 14 D25: enable training data collection

        self._load_model()

    def _load_model(self):
        """Load model and vocabulary from disk (if available)."""
        if not os.path.exists(self.model_path) or not os.path.exists(self.vocab_path):
            logger.info("No pre-trained model found, starting cold")
            return

        try:
            vocab_data = torch.load(self.vocab_path, map_location="cpu", weights_only=True)
            self.vocab = Vocabulary()
            self.vocab.word2idx = vocab_data["word2idx"]
            self.vocab.idx2word = {int(k): v for k, v in vocab_data["idx2word"].items()}
            self.vocab.next_idx = vocab_data["next_idx"]

            self.model = SyscallBiGRU(vocab_size=len(self.vocab)).to(self.device)
            self.model.load_state_dict(
                torch.load(self.model_path, map_location=self.device, weights_only=True)
            )
            self.model.eval()
            self.model_version = f"1.{int(time.time()) % 10000}"
            logger.info("Model loaded: vocab=%d, device=%s", len(self.vocab), self.device)
        except Exception as e:
            logger.error("Failed to load model: %s", e)
            self.model = None
            self.vocab = None

    def PredictNext(self, request, context):
        """Predict the next syscall given a context sequence."""
        with self.lock:
            if self.model is None or self.vocab is None:
                context.set_code(grpc.StatusCode.UNAVAILABLE)
                context.set_details("Model not loaded")
                return mock_pb2.PredictResponse()

            if len(request.calls) == 0:
                return mock_pb2.PredictResponse(predicted_call="", confidence=0.0)

            # Encode input sequence.
            indices = [self.vocab.encode(c) for c in request.calls[-20:]]  # max 20 context
            x = torch.tensor([indices], dtype=torch.long).to(self.device)

            # Predict.
            top_k = self.model.predict_top_k(x, k=5)

            if not top_k:
                return mock_pb2.PredictResponse(predicted_call="", confidence=0.0)

            best_idx, best_conf = top_k[0]
            best_name = self.vocab.decode(best_idx)

            # Skip PAD/UNK.
            if best_name in (Vocabulary.PAD, Vocabulary.UNK) and len(top_k) > 1:
                best_idx, best_conf = top_k[1]
                best_name = self.vocab.decode(best_idx)

            candidates = []
            for idx, score in top_k:
                name = self.vocab.decode(idx)
                if name not in (Vocabulary.PAD, Vocabulary.UNK):
                    candidates.append(mock_pb2.CandidateCall(name=name, score=score))

            # Phase 14 D25: Log inference data for future training (1/100 sampling).
            self.inference_count += 1
            if self.collect_training_data and self.inference_count % 100 == 0:
                self._log_training_sample(request.calls, best_name)

            return mock_pb2.PredictResponse(
                predicted_call=best_name,
                confidence=best_conf,
                top_k=candidates,
            )

    def _log_training_sample(self, calls: list, predicted: str):
        """Log inference sample for future training (Phase 14 D25)."""
        try:
            import json
            sample = {"context": list(calls[-20:]), "predicted": predicted}
            with open(self.training_data_path, "a") as f:
                f.write(json.dumps(sample) + "\n")
        except Exception as e:
            logger.debug("Failed to log training sample: %s", e)

    def Health(self, request, context):
        """Health check."""
        return mock_pb2.HealthResponse(
            healthy=self.model is not None,
            vocab_size=len(self.vocab) if self.vocab else 0,
            training_samples=self.training_samples,
            model_version=self.model_version,
        )

    def Retrain(self, request, context):
        """Retrain model from fresh corpus data."""
        corpus_dir = request.corpus_dir
        if not corpus_dir or not os.path.isdir(corpus_dir):
            return mock_pb2.RetrainResponse(
                success=False,
                message=f"Invalid corpus directory: {corpus_dir}",
                samples_used=0,
            )

        logger.info("Retraining from corpus: %s", corpus_dir)
        try:
            result = train_model(
                corpus_dir, self.model_path, self.vocab_path,
                epochs=10, device=self.device,
            )
            if result["success"]:
                with self.lock:
                    self._load_model()
                    self.training_samples = result["samples"]
            return mock_pb2.RetrainResponse(
                success=result["success"],
                message=result["message"],
                samples_used=result["samples"],
            )
        except Exception as e:
            logger.error("Retrain failed: %s", e)
            return mock_pb2.RetrainResponse(
                success=False,
                message=str(e),
                samples_used=0,
            )


class JSONTCPHandler:
    """JSON-over-TCP handler that wraps the gRPC servicer logic."""

    def __init__(self, servicer: MockModelServicer):
        self.servicer = servicer

    def handle_request(self, data: bytes) -> bytes:
        import json as _json
        try:
            req = _json.loads(data.strip())
        except _json.JSONDecodeError:
            return _json.dumps({"error": "invalid JSON"}).encode() + b"\n"

        method = req.get("method", "")
        if method == "health":
            with self.servicer.lock:
                resp = {
                    "healthy": self.servicer.model is not None,
                    "vocab_size": len(self.servicer.vocab) if self.servicer.vocab else 0,
                    "training_samples": self.servicer.training_samples,
                }
            return _json.dumps(resp).encode() + b"\n"
        elif method == "predict":
            calls = req.get("calls", [])
            if not calls or self.servicer.model is None:
                return _json.dumps({"call": "", "confidence": 0.0}).encode() + b"\n"
            with self.servicer.lock:
                indices = [self.servicer.vocab.encode(c) for c in calls[-20:]]
                x = torch.tensor([indices], dtype=torch.long).to(self.servicer.device)
                top_k = self.servicer.model.predict_top_k(x, k=5)
            if not top_k:
                return _json.dumps({"call": "", "confidence": 0.0}).encode() + b"\n"
            best_idx, best_conf = top_k[0]
            best_name = self.servicer.vocab.decode(best_idx)
            if best_name in (Vocabulary.PAD, Vocabulary.UNK) and len(top_k) > 1:
                best_idx, best_conf = top_k[1]
                best_name = self.servicer.vocab.decode(best_idx)
            # Phase 14 D25: Log training data (1/100 sampling) via JSON-TCP path too.
            with self.servicer.lock:
                self.servicer.inference_count += 1
                if self.servicer.collect_training_data and self.servicer.inference_count % 100 == 0:
                    self.servicer._log_training_sample(calls, best_name)
            return _json.dumps({"call": best_name, "confidence": best_conf}).encode() + b"\n"
        elif method == "retrain":
            corpus_dir = req.get("dir", "")
            if not corpus_dir or not os.path.isdir(corpus_dir):
                return _json.dumps({"error": f"invalid dir: {corpus_dir}"}).encode() + b"\n"
            result = train_model(corpus_dir, self.servicer.model_path,
                                 self.servicer.vocab_path, epochs=10,
                                 device=self.servicer.device)
            if result["success"]:
                with self.servicer.lock:
                    self.servicer._load_model()
                    self.servicer.training_samples = result["samples"]
            return _json.dumps({"error": "" if result["success"] else result["message"]}).encode() + b"\n"
        else:
            return _json.dumps({"error": f"unknown method: {method}"}).encode() + b"\n"


def _run_json_tcp(handler: JSONTCPHandler, port: int):
    """Run a simple JSON-over-TCP server for the Go fuzzer client."""
    import socket
    import selectors

    sel = selectors.DefaultSelector()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.listen(32)
    sock.setblocking(False)
    sel.register(sock, selectors.EVENT_READ)
    logger.info("JSON-TCP listener started on port %d", port)

    while True:
        for key, _ in sel.select(timeout=1.0):
            if key.fileobj is sock:
                conn, addr = sock.accept()
                conn.setblocking(True)
                conn.settimeout(2.0)
                threading.Thread(target=_handle_conn, args=(handler, conn), daemon=True).start()


def _handle_conn(handler: JSONTCPHandler, conn):
    """Handle a persistent TCP connection with JSON-line protocol."""
    try:
        conn.settimeout(300.0)  # 5-min idle timeout for persistent connections
        buf = b""
        while True:
            data = conn.recv(4096)
            if not data:
                break  # client closed
            buf += data
            # Process all complete lines (JSON-line protocol).
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if line.strip():
                    resp = handler.handle_request(line)
                    conn.sendall(resp)
            # Also handle single request without trailing newline.
            if buf.strip() and b"\n" not in buf:
                # Check if it looks like complete JSON (ends with }).
                stripped = buf.strip()
                if stripped.endswith(b"}"):
                    resp = handler.handle_request(stripped)
                    conn.sendall(resp)
                    buf = b""
    except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
        pass
    except Exception:
        pass
    finally:
        conn.close()


def serve(port: int = DEFAULT_PORT, model_path: str = DEFAULT_MODEL_PATH,
          vocab_path: str = DEFAULT_VOCAB_PATH):
    """Start the gRPC server + JSON-TCP listener."""
    servicer = MockModelServicer(model_path=model_path, vocab_path=vocab_path)

    # Start JSON-TCP listener for Go fuzzer client (same port).
    handler = JSONTCPHandler(servicer)
    tcp_thread = threading.Thread(target=_run_json_tcp, args=(handler, port), daemon=True)
    tcp_thread.start()

    # Start gRPC on port+1 (for backward compat with any gRPC clients).
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    mock_pb2_grpc.add_MockModelServicer_to_server(servicer, server)
    server.add_insecure_port(f"[::]:{port + 1}")
    server.start()
    logger.info("MOCK model server: JSON-TCP on port %d, gRPC on port %d", port, port + 1)
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        server.stop(5)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    serve(port=port)
