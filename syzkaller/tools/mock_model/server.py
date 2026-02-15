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


class MockModelServicer(mock_pb2_grpc.MockModelServicer):
    """Implements the MockModel gRPC service."""

    def __init__(self, model_path: str = DEFAULT_MODEL_PATH,
                 vocab_path: str = DEFAULT_VOCAB_PATH,
                 device: str = None):
        self.model_path = model_path
        self.vocab_path = vocab_path
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.model = None
        self.vocab = None
        self.training_samples = 0
        self.model_version = "0.0"
        self.lock = threading.Lock()

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

            return mock_pb2.PredictResponse(
                predicted_call=best_name,
                confidence=best_conf,
                top_k=candidates,
            )

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


def serve(port: int = DEFAULT_PORT, model_path: str = DEFAULT_MODEL_PATH,
          vocab_path: str = DEFAULT_VOCAB_PATH):
    """Start the gRPC server."""
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    servicer = MockModelServicer(model_path=model_path, vocab_path=vocab_path)
    mock_pb2_grpc.add_MockModelServicer_to_server(servicer, server)
    server.add_insecure_port(f"[::]:{port}")
    server.start()
    logger.info("MOCK model server started on port %d", port)
    try:
        server.wait_for_termination()
    except KeyboardInterrupt:
        server.stop(5)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    serve(port=port)
