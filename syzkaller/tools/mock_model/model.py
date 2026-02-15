"""BiGRU language model for syscall sequence prediction (MOCK/SeqFuzz inspired).

Learns transition probabilities between syscall types to predict contextually
appropriate next-syscall choices for insertCall() in the fuzzer.
"""

import torch
import torch.nn as nn
import torch.nn.functional as F


class SyscallBiGRU(nn.Module):
    """Bidirectional GRU model for syscall sequence prediction.

    Architecture: Embedding(64) → BiGRU(128) → Linear → softmax over vocab.
    """

    def __init__(self, vocab_size: int, embed_dim: int = 64, hidden_dim: int = 128,
                 num_layers: int = 2, dropout: float = 0.1):
        super().__init__()
        self.vocab_size = vocab_size
        self.embed_dim = embed_dim
        self.hidden_dim = hidden_dim

        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=0)
        self.gru = nn.GRU(
            embed_dim, hidden_dim,
            num_layers=num_layers,
            bidirectional=True,
            dropout=dropout if num_layers > 1 else 0,
            batch_first=True,
        )
        self.fc = nn.Linear(hidden_dim * 2, vocab_size)  # *2 for bidirectional
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """Forward pass.

        Args:
            x: (batch, seq_len) integer tensor of syscall indices.

        Returns:
            (batch, vocab_size) logits for next syscall prediction.
        """
        emb = self.dropout(self.embedding(x))  # (batch, seq, embed)
        output, _ = self.gru(emb)               # (batch, seq, hidden*2)
        # Use the last timestep output for prediction.
        last = output[:, -1, :]                  # (batch, hidden*2)
        logits = self.fc(self.dropout(last))     # (batch, vocab)
        return logits

    def predict_top_k(self, x: torch.Tensor, k: int = 5) -> list:
        """Predict top-k next syscalls.

        Returns:
            List of (index, probability) tuples.
        """
        with torch.no_grad():
            logits = self.forward(x)
            probs = F.softmax(logits, dim=-1)
            top_probs, top_indices = torch.topk(probs[0], k)
            return [(idx.item(), prob.item()) for idx, prob in zip(top_indices, top_probs)]


class Vocabulary:
    """Maps syscall names to integer indices and back."""

    PAD = "<PAD>"
    UNK = "<UNK>"

    def __init__(self):
        self.word2idx = {self.PAD: 0, self.UNK: 1}
        self.idx2word = {0: self.PAD, 1: self.UNK}
        self.next_idx = 2

    def add(self, word: str) -> int:
        if word not in self.word2idx:
            self.word2idx[word] = self.next_idx
            self.idx2word[self.next_idx] = word
            self.next_idx += 1
        return self.word2idx[word]

    def encode(self, word: str) -> int:
        return self.word2idx.get(word, self.word2idx[self.UNK])

    def decode(self, idx: int) -> str:
        return self.idx2word.get(idx, self.UNK)

    def __len__(self):
        return self.next_idx
