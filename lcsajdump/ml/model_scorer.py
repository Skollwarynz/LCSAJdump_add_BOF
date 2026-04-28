"""
model_scorer.py — Drop-in ML scorer for RainbowFinder.score_gadget().

Integrates the trained LightGBM model into the lcsajdump scoring pipeline.
Falls back transparently to the heuristic scorer if the model is unavailable.

Usage
-----
    # In rainbowBFS.py __init__:
    from lcsajdump.ml.model_scorer import MLScorer
    self._ml_scorer = MLScorer.load('chainfinder_v5_hybrid.pkl', arch=arch)

    # Replace score_gadget body:
    def score_gadget(self, path):
        heuristic = self._heuristic_score(path)      # existing logic
        return self._ml_scorer.score(path, self.gm, heuristic) if self._ml_scorer else heuristic

Monkey-patch helper
-------------------
    from lcsajdump.ml.model_scorer import patch_rainbowfinder
    patch_rainbowfinder(finder_instance, model_path='chainfinder_v5_hybrid.pkl', arch='arm64')
"""
from __future__ import annotations

import pickle
import sys
from typing import Optional

from lcsajdump.ml.features import extract_features, FEATURE_NAMES

# ── MLScorer class ─────────────────────────────────────────────────────────────

class MLScorer:
    """
    Wraps a trained LightGBM LambdaRank model for use inside RainbowFinder.

    The scorer converts a BFS path (list of addresses) to a feature vector,
    runs inference, and returns an integer score on the same approximate scale
    as the heuristic (0–300+) so existing filters / limits still work.

    Optionally loads an InstructionLM to produce semantic embedding features
    alongside the 22 structural features (38 total when lm_model_path is given).
    """

    _OUTPUT_SCALE = 200.0   # model outputs ≈ [-inf, +inf]; we map to ~[0, 300]

    def __init__(self, model_data: dict, arch: str, lm=None):
        self._model       = model_data['model']
        self._feat_names  = model_data.get('feature_names', FEATURE_NAMES)
        self._arch        = arch
        self._lm          = lm   # optional InstructionLM for semantic embeddings
        self._gadget_pool: set = set()   # populated via set_gadget_pool()

    def set_gadget_pool(self, pool: set):
        """Register the full set of gadget addresses for is_chained computation."""
        self._gadget_pool = pool

    # ── Factory methods ────────────────────────────────────────────────────────

    @classmethod
    def load(cls, model_path: str, arch: str,
             lm_path: Optional[str] = None) -> Optional['MLScorer']:
        """
        Load from a pickle file produced by trainer.py. Returns None on failure.

        Parameters
        ----------
        model_path : str  — path to the pickled LightGBM model
        arch : str        — 'x86_64', 'arm64', or 'riscv64'
        lm_path : str, optional — path to InstructionLM pickle (lm_model.pkl)
                  If provided and the model was trained with LM features (38 dims),
                  semantic embeddings are added at inference time.
        """
        try:
            with open(model_path, 'rb') as f:
                data = pickle.load(f)

            lm = None
            if lm_path:
                try:
                    from lcsajdump.ml.instruction_lm import InstructionLM
                    lm = InstructionLM.load(lm_path)
                    print(f"[model_scorer] Loaded InstructionLM from {lm_path} "
                          f"(vocab={lm.vocab_size()}, dim={lm.vector_size})")
                except Exception as e:
                    print(f"[model_scorer] InstructionLM load failed: {e} — using 22 features",
                          file=sys.stderr)

            scorer = cls(data, arch, lm=lm)
            n_feats = len(scorer._feat_names)
            print(f"[model_scorer] Loaded ML scorer from {model_path} "
                  f"(arch={arch}, features={n_feats})")
            return scorer
        except FileNotFoundError:
            print(f"[model_scorer] Model not found at {model_path} — using heuristic",
                  file=sys.stderr)
        except Exception as e:
            print(f"[model_scorer] Failed to load model: {e} — using heuristic",
                  file=sys.stderr)
        return None

    # ── Scoring ───────────────────────────────────────────────────────────────

    def set_majority_term_is_ret(self, value: int):
        """
        Set the binary-level majority_term_is_ret context flag.
        Call this once per binary before scoring its gadgets.
        1 = most gadgets in this binary are ret-terminated (normal ROP binary).
        0 = JOP/COP binary where most gadgets are indirect-jmp terminated.
        Defaults to 1 (safe for ROP binaries).
        """
        self._majority_term_is_ret = int(value)

    def score(self, path: tuple, graph_manager, heuristic_score: int = 0) -> int:
        """
        Score a gadget path using the ML model.

        Parameters
        ----------
        path : tuple of addresses (BFS path from rainbowBFS)
        graph_manager : RainbowFinder.gm — provides addr_to_node
        heuristic_score : int — the existing heuristic score (used as a feature)

        Returns
        -------
        int — score on the same scale as the heuristic (~0–300)
        """
        instructions = self._collect_instructions(path, graph_manager)
        if not instructions:
            return heuristic_score

        return self.score_from_instructions(
            instructions=instructions,
            gadget_type='Sequential',
            heuristic_score=heuristic_score,
            address=path[0] if path else 0,
            gadget_pool=self._gadget_pool if self._gadget_pool else None,
            majority_term_is_ret=getattr(self, '_majority_term_is_ret', 1),
            binary_path=getattr(graph_manager, "binary_path", None),
        )

    def score_from_instructions(
        self,
        instructions: list,
        gadget_type: str = 'Sequential',
        heuristic_score: int = 0,
        address: int = 0,
        gadget_pool=None,
        majority_term_is_ret: int = 1,
        binary_path: str = None,
    ) -> int:
        """
        Score a gadget given its already-collected instruction list.

        Use this when you have the instruction dicts directly (e.g. from the CLI
        iterating over finder.gadgets) rather than a BFS path + graph_manager.

        Parameters
        ----------
        instructions : list of {'mnemonic': ..., 'op_str': ...} dicts
        gadget_type : 'Sequential' or 'Jump-Based'
        heuristic_score : int — existing heuristic score (used as a feature)
        address : int — primary gadget address (for bad-byte features)
        gadget_pool : set of int, optional — all gadget addresses in the binary
        binary_path : str, optional - path to the binary

        Returns
        -------
        int — score in approximate range [0, 400]
        """
        if not instructions:
            return heuristic_score

        pool = gadget_pool if gadget_pool is not None else (
            self._gadget_pool if self._gadget_pool else None
        )

        g_size = sum(i.get("size", 4) for i in instructions) if instructions else 15
        feats = extract_features(
            instructions=instructions,
            arch=self._arch,
            gadget_type=gadget_type,
            heuristic_score=heuristic_score,
            address=address,
            gadget_pool=pool,
            lm=self._lm,
            majority_term_is_ret=majority_term_is_ret,
            binary_path=binary_path,
            gadget_size=g_size,
        )

        # Build feature row in model's expected order
        try:
            import pandas as pd
            X = pd.DataFrame([feats], columns=self._feat_names)
        except ImportError:
            X = [[feats.get(f, 0) for f in self._feat_names]]

        try:
            raw = float(self._model.predict(X)[0])
        except Exception as e:
            print(f"[model_scorer] Inference error: {e}", file=sys.stderr)
            return heuristic_score

        return self._rescale(raw)

    @classmethod
    def _rescale(cls, raw: float) -> int:
        """Map unbounded ranking score to integer [0, 400] via stable sigmoid."""
        import math
        # Clamp to avoid math.exp overflow for extreme values
        clamped = max(-700.0, min(700.0, raw / 3.0))
        sig = 1.0 / (1.0 + math.exp(-clamped))
        return int(sig * cls._OUTPUT_SCALE * 2)

    def score_batch(self, paths: list[tuple], graph_manager) -> list[int]:
        """Score multiple paths in a single model.predict() call (faster for large batches)."""
        rows = []
        heuristics = []
        for path in paths:
            instructions = self._collect_instructions(path, graph_manager)
            heuristics.append(0)
            g_size = sum(i.get("size", 4) for i in instructions) if instructions else 15
            feats = extract_features(
                instructions=instructions,
                arch=self._arch,
                heuristic_score=0,
                address=path[0] if path else 0,
                gadget_pool=self._gadget_pool or None,
                lm=self._lm,
                binary_path=getattr(graph_manager, "binary_path", None),
                gadget_size=g_size,
            )
            rows.append([feats.get(f, 0) for f in self._feat_names])

        try:
            import pandas as pd
            X = pd.DataFrame(rows, columns=self._feat_names)
            raw_scores = self._model.predict(X)
            return [self._rescale(float(r)) for r in raw_scores]
        except Exception as e:
            print(f"[model_scorer] Batch inference error: {e}", file=sys.stderr)
            return [0] * len(paths)

    # ── Internal ──────────────────────────────────────────────────────────────

    @staticmethod
    def _collect_instructions(path: tuple, graph_manager) -> list:
        """Gather instruction dicts from a BFS path via graph_manager.addr_to_node."""
        instructions = []
        for addr in path:
            node = graph_manager.addr_to_node.get(addr)
            if node:
                for insn in node.get('insns', []):
                    instructions.append({
                        'mnemonic': insn.mnemonic if hasattr(insn, 'mnemonic') else insn.get('mnemonic', ''),
                        'op_str':   insn.op_str   if hasattr(insn, 'op_str')   else insn.get('op_str', ''),
                        'size':     insn.size     if hasattr(insn, 'size')     else insn.get('size', 4),
                    })
        return instructions


# ── Batch rescoring helper ─────────────────────────────────────────────────────

def _batch_rescore(finder_instance, scorer, original_score_gadget_func):
    """
    Run batch ML prediction on all gadgets found by BFS and cache normalized scores.

    Strategy: rank-based scoring with heuristic tiebreaking.
    ─────────────────────────────────────────────────────────
    LightGBM LambdaRank raw outputs are typically in ±0.1 and may be identical
    for many gadgets on large binaries (model trained on small CTF queries).
    Instead of using the raw value directly, we:
      1. Sort all gadgets by (raw_score DESC, heuristic DESC).
      2. Assign final scores linearly by rank: rank-0 → 400, rank-(n-1) → 50.
    This guarantees strict ordering and full [50, 400] spread on ANY binary size.
    """
    from lcsajdump.ml.features import extract_features

    sigs = list(finder_instance.grouped_gadgets.keys())
    if not sigs:
        finder_instance._ml_score_cache = {}
        return

    # Populate gadget pool once
    if not scorer._gadget_pool and hasattr(finder_instance, 'gm'):
        scorer.set_gadget_pool(set(finder_instance.gm.addr_to_node.keys()))

    rows = []
    heuristics = []
    for sig in sigs:
        path = finder_instance.grouped_gadgets[sig]["path"]
        insns = scorer._collect_instructions(path, finder_instance.gm)
        heuristic = original_score_gadget_func(finder_instance, path)
        heuristics.append(heuristic)
        g_size = sum(i.get("size", 4) for i in insns) if insns else 15
        feats = extract_features(
            instructions=insns,
            arch=scorer._arch,
            gadget_type='Sequential',   # conservative default; type is 1 of 23 features
            heuristic_score=heuristic,
            address=path[0] if path else 0,
            gadget_pool=scorer._gadget_pool or None,
            lm=scorer._lm,
            binary_path=getattr(finder_instance.gm, "binary_path", None),
            gadget_size=g_size,
        )
        rows.append([feats.get(f, 0) for f in scorer._feat_names])

    try:
        import pandas as pd
        X = pd.DataFrame(rows, columns=scorer._feat_names)
        raw_scores = scorer._model.predict(X)

        n = len(sigs)
        # Sort by (raw_score DESC, heuristic DESC) — heuristic breaks ties
        sorted_indices = sorted(
            range(n),
            key=lambda i: (float(raw_scores[i]), heuristics[i]),
            reverse=True,
        )
        # Assign rank-based scores: best gadget → 400, worst → 50
        score_map = {}
        for rank, idx in enumerate(sorted_indices):
            if n > 1:
                score = int(400 - 350 * rank / (n - 1))
            else:
                score = 225
            score_map[sigs[idx]] = score

        finder_instance._ml_score_cache = score_map
        rmin = float(raw_scores.min())
        rmax = float(raw_scores.max())
        n_unique = len(set(float(r) for r in raw_scores))
        print(f"[model_scorer] Batch rescored {n} gadgets "
              f"(raw range [{rmin:.4f}, {rmax:.4f}], {n_unique} unique → rank-based [50, 400])")
    except Exception as e:
        print(f"[model_scorer] Batch rescoring failed: {e} — using heuristic scores",
              file=sys.stderr)
        finder_instance._ml_score_cache = {}


# ── Monkey-patch helper ────────────────────────────────────────────────────────

def patch_rainbowfinder(finder, model_path: str, arch: str,
                        lm_path: Optional[str] = None):
    """
    Patch a RainbowFinder instance to use the ML scorer.

    Strategy
    --------
    1. search() is wrapped: after BFS completes, batch-predicts all gadgets and
       stores min-max-normalised scores in finder._ml_score_cache.
    2. score_gadget() is wrapped: looks up the cache by gadget signature; falls
       back to per-gadget sigmoid if the cache entry is missing.

    This avoids the score-compression problem of per-gadget sigmoid rescaling
    (LambdaRank raw outputs are typically in ±0.1, making all sigmoid scores ≈200).

    Parameters
    ----------
    finder : RainbowFinder instance (from rainbowBFS.py)
    model_path : str  — path to the pickled model (from trainer.py)
    arch : str        — 'x86_64', 'arm64', or 'riscv64'
    lm_path : str, optional — path to InstructionLM pickle for semantic features
    """
    scorer = MLScorer.load(model_path, arch=arch, lm_path=lm_path)
    if scorer is None:
        return  # No model available — leave finder unchanged

    # Guard against double-patching
    if getattr(finder, '_ml_patched', False):
        print("[model_scorer] RainbowFinder already patched — skipping", file=sys.stderr)
        return

    original_score_gadget = finder.score_gadget.__func__   # unbound heuristic
    original_search       = finder.search.__func__          # unbound BFS

    def ml_search(self_inner):
        result = original_search(self_inner)
        _batch_rescore(self_inner, scorer, original_score_gadget)
        return result

    def ml_score_gadget(self_inner, path):
        heuristic = original_score_gadget(self_inner, path)
        cache = getattr(self_inner, '_ml_score_cache', None)
        if cache:
            # Recompute signature (same formula as search())
            gadget_insns = []
            for addr in path:
                node = self_inner.gm.addr_to_node.get(addr)
                if node:
                    gadget_insns.extend(node.get('insns', []))
            sig = "; ".join(
                f"{i.mnemonic} {i.op_str}"
                if hasattr(i, 'mnemonic') else f"{i.get('mnemonic','')} {i.get('op_str','')}"
                for i in gadget_insns
            )
            if sig in cache:
                return cache[sig]
        # Cache miss: fall back to per-gadget scoring
        return scorer.score(path, self_inner.gm, heuristic_score=heuristic)

    import types
    finder.search       = types.MethodType(ml_search,       finder)
    finder.score_gadget = types.MethodType(ml_score_gadget, finder)
    finder._ml_patched  = True
    print(f"[model_scorer] RainbowFinder patched with ML scorer (arch={arch})")

    # If search() was already called before patching (CLI calls search() first),
    # run batch rescoring immediately so the cache is ready for gadgets_to_json().
    if getattr(finder, 'grouped_gadgets', None):
        _batch_rescore(finder, scorer, original_score_gadget)
