"""
instruction_lm.py — Instruction Language Model for gadget semantic embeddings.

Trains a Word2Vec skip-gram model on assembly instruction token sequences,
producing a fixed-size embedding per gadget (mean-pooling over token vectors).

The embedding captures semantic similarity between gadgets that share instruction
patterns (e.g., 'pop rdi ; ret' ≈ 'pop rsi ; ret') — structural information
that hand-crafted boolean features cannot encode.

Architecture
------------
    Corpus  : all gadget instruction sequences from the training dataset
    Token   : mnemonic or operand subtoken (e.g., "pop", "rdi", "[rsp+8]" → "rsp")
    Model   : Word2Vec skip-gram (window=3, vector_size=LM_DIM)
    Gadget  : mean of token vectors → LM_DIM-dimensional embedding
    Features: lm_emb_0 … lm_emb_{LM_DIM-1}  added to FEATURE_NAMES

Usage
-----
    # Training (run once; saves model to lm_model.pkl)
    python -m lcsajdump_dbg.ml.instruction_lm \\
        --csv gadget_dataset_v4.csv \\
        --binaries-dir /path/to/binaries \\
        --out lm_model.pkl

    # In code
    from lcsajdump_dbg.ml.instruction_lm import InstructionLM
    lm = InstructionLM.load('lm_model.pkl')
    emb = lm.embed_gadget(instructions)   # list of {'mnemonic': ..., 'op_str': ...}
"""
from __future__ import annotations

import json
import os
import pickle
import re
import subprocess
import sys
from pathlib import Path
from typing import Optional

import numpy as np

# ── Constants ─────────────────────────────────────────────────────────────────

LM_DIM = 16          # embedding dimensions per gadget
LM_WINDOW = 3        # Word2Vec context window
LM_MIN_COUNT = 2     # ignore tokens that appear fewer than this many times
LM_EPOCHS = 20       # training epochs

# Feature names exposed to LightGBM
LM_FEATURE_NAMES = [f'lm_emb_{i}' for i in range(LM_DIM)]

# ── Tokenisation ──────────────────────────────────────────────────────────────

_OPERAND_SEP = re.compile(r'[,\[\]+\-\*#\s]+')
_HEX_RE      = re.compile(r'^0x[0-9a-fA-F]+$')
_INT_RE      = re.compile(r'^-?\d+$')


def _normalise_token(tok: str) -> Optional[str]:
    """
    Normalise a single operand token.

    - Hex literals     → '<imm>'
    - Decimal literals → '<imm>'
    - Empty strings    → None (discarded)
    - Registers / mnemonics: lowercase, kept as-is
    """
    tok = tok.strip().lower()
    if not tok:
        return None
    if _HEX_RE.match(tok) or _INT_RE.match(tok):
        return '<imm>'
    return tok


def tokenise_instruction(mnemonic: str, op_str: str) -> list[str]:
    """
    Convert a single instruction to a list of tokens.

    Examples
    --------
    'pop', 'rdi'          → ['pop', 'rdi']
    'ldr', 'x0, [sp, #8]' → ['ldr', 'x0', 'sp', '<imm>']
    'call', '0x401163'    → ['call', '<imm>']
    """
    tokens = [mnemonic.lower().strip()]
    for part in _OPERAND_SEP.split(op_str):
        tok = _normalise_token(part)
        if tok:
            tokens.append(tok)
    return tokens


def gadget_to_tokens(instructions: list[dict]) -> list[str]:
    """
    Flatten a gadget's instruction list into a single token sequence.

    A special '<SEP>' token is inserted between instructions so the model
    learns instruction boundaries.
    """
    all_tokens: list[str] = []
    for i, insn in enumerate(instructions):
        if isinstance(insn, dict):
            mnem = insn.get('mnemonic', '')
            op   = insn.get('op_str', '')
        else:
            mnem = getattr(insn, 'mnemonic', '')
            op   = getattr(insn, 'op_str', '')
        all_tokens.extend(tokenise_instruction(mnem, op))
        if i < len(instructions) - 1:
            all_tokens.append('<SEP>')
    return all_tokens


# ── Corpus builder from lcsajdump JSON ────────────────────────────────────────

def _run_lcsajdump(binary_path: str, arch: str = 'auto',
                   all_exec: bool = False) -> dict:
    cmd = [
        sys.executable, '-m', 'lcsajdump_dbg.cli',
        binary_path, '--json', '--limit', '999999',
        '--depth', '20', '--darkness', '5', '--instructions', '15',
    ]
    if arch != 'auto':
        cmd += ['--arch', arch]
    if all_exec:
        cmd += ['--all-exec']
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"lcsajdump failed for {binary_path}: {result.stderr[-500:]}")
    stdout = result.stdout
    start = stdout.find('{')
    if start == -1:
        raise RuntimeError(f"No JSON output for {binary_path}")
    return json.loads(stdout[start:])


def build_corpus_from_samples(samples: list[dict], verbose: bool = True) -> list[list[str]]:
    """
    Build a Word2Vec training corpus from lcsajdump samples.

    Each sentence = token sequence of one gadget.
    Returns a list of sentences (list of lists of tokens).
    """
    sentences: list[list[str]] = []

    for s in samples:
        binary = s['binary']
        arch   = s.get('arch', 'auto')
        all_exec = s.get('all_exec', False)

        if not os.path.exists(binary):
            if verbose:
                print(f"[instruction_lm] SKIP (not found): {binary}", file=sys.stderr)
            continue

        if verbose:
            print(f"[instruction_lm] Extracting tokens: {os.path.basename(binary)} ({arch})")

        try:
            data = _run_lcsajdump(binary, arch=arch, all_exec=all_exec)
        except Exception as e:
            print(f"[instruction_lm] ERROR {binary}: {e}", file=sys.stderr)
            continue

        for key in ('sequential', 'jump_based'):
            for entry in data.get(key, []):
                instrs = entry.get('instructions', [])
                if instrs:
                    sentences.append(gadget_to_tokens(instrs))

    if verbose:
        n_tok = sum(len(s) for s in sentences)
        print(f"[instruction_lm] Corpus: {len(sentences)} gadgets, {n_tok} tokens")

    return sentences


# ── InstructionLM ─────────────────────────────────────────────────────────────

class InstructionLM:
    """
    Word2Vec-based instruction language model.

    Produces a fixed-size embedding for any gadget instruction sequence.
    Unknown tokens (not seen during training) are mapped to a zero vector.
    """

    def __init__(self, vector_size: int = LM_DIM, window: int = LM_WINDOW,
                 min_count: int = LM_MIN_COUNT, epochs: int = LM_EPOCHS):
        self.vector_size = vector_size
        self.window      = window
        self.min_count   = min_count
        self.epochs      = epochs
        self._model      = None   # gensim Word2Vec

    # ── Training ──────────────────────────────────────────────────────────────

    def train(self, sentences: list[list[str]], verbose: bool = True) -> None:
        """Train Word2Vec on a pre-built corpus of token sentences."""
        from gensim.models import Word2Vec

        if verbose:
            print(f"[instruction_lm] Training Word2Vec "
                  f"(dim={self.vector_size}, window={self.window}, "
                  f"epochs={self.epochs}, sentences={len(sentences)})...")

        self._model = Word2Vec(
            sentences   = sentences,
            vector_size = self.vector_size,
            window      = self.window,
            min_count   = self.min_count,
            sg          = 1,          # skip-gram (better for rare tokens)
            workers     = 4,
            epochs      = self.epochs,
            seed        = 42,
        )

        if verbose:
            vocab_size = len(self._model.wv)
            print(f"[instruction_lm] Vocabulary: {vocab_size} tokens")

    # ── Embedding ─────────────────────────────────────────────────────────────

    def embed_gadget(self, instructions: list) -> np.ndarray:
        """
        Embed a gadget from its instruction list.

        Returns a (vector_size,) float32 array.
        If the model is not trained or all tokens are unknown, returns zeros.
        """
        if self._model is None:
            return np.zeros(self.vector_size, dtype=np.float32)

        tokens = gadget_to_tokens(instructions)
        wv = self._model.wv
        vecs = [wv[t] for t in tokens if t in wv]
        if not vecs:
            return np.zeros(self.vector_size, dtype=np.float32)
        return np.mean(vecs, axis=0).astype(np.float32)

    def embed_to_dict(self, instructions: list) -> dict[str, float]:
        """Return embedding as a dict {lm_emb_0: ..., lm_emb_1: ...} for CSV rows."""
        emb = self.embed_gadget(instructions)
        return {f'lm_emb_{i}': float(emb[i]) for i in range(self.vector_size)}

    # ── Persist ───────────────────────────────────────────────────────────────

    def save(self, path: str) -> None:
        data = {
            'vector_size': self.vector_size,
            'window':      self.window,
            'min_count':   self.min_count,
            'epochs':      self.epochs,
            'model':       self._model,
        }
        with open(path, 'wb') as f:
            pickle.dump(data, f)
        print(f"[instruction_lm] Saved to {path}")

    @classmethod
    def load(cls, path: str) -> 'InstructionLM':
        with open(path, 'rb') as f:
            data = pickle.load(f)
        lm = cls(
            vector_size = data['vector_size'],
            window      = data['window'],
            min_count   = data['min_count'],
            epochs      = data['epochs'],
        )
        lm._model = data['model']
        return lm

    # ── Vocabulary inspection ─────────────────────────────────────────────────

    def most_similar_tokens(self, token: str, topn: int = 10) -> list[tuple[str, float]]:
        """Return semantically similar tokens (useful for thesis analysis)."""
        if self._model is None or token not in self._model.wv:
            return []
        return self._model.wv.most_similar(token, topn=topn)

    def vocab_size(self) -> int:
        return len(self._model.wv) if self._model else 0


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='Train instruction language model on lcsajdump gadget corpus'
    )
    parser.add_argument('--out',  default='lm_model.pkl', help='Output model path')
    parser.add_argument('--dim',  type=int, default=LM_DIM,    help='Embedding dimensions')
    parser.add_argument('--epochs', type=int, default=LM_EPOCHS, help='Training epochs')
    parser.add_argument('--show-similar', metavar='TOKEN', default=None,
                        help='After training, show tokens most similar to TOKEN')
    args = parser.parse_args()

    # Import sample list from dataset_builder
    from lcsajdump_dbg.ml.dataset_builder import ALL_SAMPLES

    lm = InstructionLM(vector_size=args.dim, epochs=args.epochs)
    corpus = build_corpus_from_samples(ALL_SAMPLES, verbose=True)
    lm.train(corpus, verbose=True)
    lm.save(args.out)

    if args.show_similar:
        print(f"\nTokens most similar to '{args.show_similar}':")
        for tok, score in lm.most_similar_tokens(args.show_similar):
            print(f"  {tok:<20} {score:.4f}")
