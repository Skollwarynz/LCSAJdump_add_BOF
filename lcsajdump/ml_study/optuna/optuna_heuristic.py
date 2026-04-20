"""
optuna_heuristic.py — Tune config.py scoring_weights using Optuna.

This script optimises the CLASSICAL HEURISTIC formula in RainbowBFS — the one
defined by scoring_weights in ARCH_PROFILES — using Optuna TPE search.

It has NOTHING to do with LightGBM.  The objective is the NDCG@5 of the
heuristic formula itself on the labelled dataset.

Usage
-----
    python -m lcsajdump.ml.optuna_heuristic \\
        --csv /tmp/gadget_dataset_v3.csv \\
        --arch x86_64 \\
        --trials 100 \\
        --out /tmp/heuristic_weights_x86_64.json

    # Or tune all three architectures:
    python -m lcsajdump.ml.optuna_heuristic \\
        --csv /tmp/gadget_dataset_v3.csv \\
        --trials 100
"""
from __future__ import annotations

import argparse
import json
import sys

import numpy as np

try:
    import optuna
    import pandas as pd
    from sklearn.metrics import ndcg_score as _ndcg
except ImportError as e:
    print(f"Missing dependency: {e}\n  pip install optuna pandas scikit-learn", file=sys.stderr)
    sys.exit(1)

optuna.logging.set_verbosity(optuna.logging.WARNING)


# ── Heuristic scoring formula (mirrors rainbowBFS.score_gadget exactly) ───────

def _score_heuristic(row: dict, weights: dict) -> float:
    """
    Reproduce the RainbowBFS scoring formula from a feature-dict row.

    Uses only features that the heuristic formula can compute:
      insn_count, hits_link_reg, hits_arg_reg, hits_frame_reg,
      is_trampoline_term, is_internal_call, is_ret_terminated, has_direct_call,
      is_syscall_term.
    """
    s = weights['base_score']
    s -= row['insn_count']            * weights['insn_penalty']
    if row['hits_link_reg']:          s += weights['bonus_link_reg']
    if row['hits_arg_reg']:           s += weights['bonus_arg_reg']
    if row['hits_frame_reg']:         s += weights['bonus_frame_reg']
    if row['is_trampoline_term']:     s += weights['bonus_trampoline']
    if row['is_internal_call']:       s -= weights['penalty_internal_call']
    # Mirror rainbowBFS exactly: syscall terminators get bonus, not penalty
    if row.get('is_syscall_term', 0):
        s += weights.get('bonus_syscall', 60)
    elif row['is_ret_terminated'] and not row['hits_link_reg']:
        s -= weights['penalty_bad_ret']
    if row['has_direct_call']:        s += weights.get('bonus_direct_call', 0)
    if row.get('is_pivot_gadget', 0):  s += weights.get('bonus_pivot', 0)
    return float(s)


def _eval_weights(df_arch: pd.DataFrame, weights: dict) -> float:
    """Return mean NDCG@5 of the heuristic formula across all binary groups."""
    scores = df_arch.apply(lambda r: _score_heuristic(r.to_dict(), weights), axis=1).values
    labels = df_arch['label'].values
    binary_ids = df_arch['binary_id'].values

    ndcg_vals = []
    for bid in np.unique(binary_ids):
        mask = binary_ids == bid
        tc = labels[mask]
        sc = scores[mask]
        if tc.sum() == 0 or len(tc) < 2:
            continue
        try:
            ndcg_vals.append(_ndcg([tc], [sc], k=5))
        except Exception:
            pass
    return float(np.mean(ndcg_vals)) if ndcg_vals else 0.0


# ── Optuna objective ───────────────────────────────────────────────────────────

def make_objective(df_arch: pd.DataFrame):
    """Return an Optuna objective that tunes the heuristic weights for one arch."""

    def objective(trial: optuna.Trial) -> float:
        weights = {
            'base_score':            100,
            'insn_penalty':          trial.suggest_int('insn_penalty', 1, 60),
            'bonus_link_reg':        trial.suggest_int('bonus_link_reg', 0, 100),
            'bonus_arg_reg':         trial.suggest_int('bonus_arg_reg', 0, 150),
            'bonus_frame_reg':       trial.suggest_int('bonus_frame_reg', 0, 100),
            'penalty_internal_call': trial.suggest_int('penalty_internal_call', 0, 200),
            'bonus_trampoline':      trial.suggest_int('bonus_trampoline', 0, 100),
            'penalty_bad_ret':       trial.suggest_int('penalty_bad_ret', 0, 100),
            'bonus_direct_call':     trial.suggest_int('bonus_direct_call', 0, 80),
            'bonus_pivot':           trial.suggest_int('bonus_pivot', 0, 150),
            'bonus_syscall':         trial.suggest_int('bonus_syscall', 0, 150),
        }
        return _eval_weights(df_arch, weights)

    return objective


# ── Per-arch tuning ────────────────────────────────────────────────────────────

def tune_arch(df: pd.DataFrame, arch: str, n_trials: int = 100) -> dict:
    """Run Optuna on a single architecture. Returns best weights dict."""
    arch_col = f'arch_{arch}'
    if arch_col not in df.columns:
        print(f"[heuristic] Column {arch_col} not found — skipping {arch}", file=sys.stderr)
        return {}

    df_arch = df[df[arch_col] == 1].copy()
    if df_arch.empty:
        print(f"[heuristic] No rows for {arch} — skipping", file=sys.stderr)
        return {}

    n_groups = df_arch['binary_id'].nunique()
    print(f"[heuristic] {arch}: {len(df_arch)} samples, {n_groups} groups, {n_trials} trials")

    # Baseline: current heuristic score (already in the dataset)
    baseline = _eval_weights(df_arch, {
        'base_score': 100, 'insn_penalty': 15, 'bonus_link_reg': 25,
        'bonus_arg_reg': 75, 'bonus_frame_reg': 45, 'penalty_internal_call': 50,
        'bonus_trampoline': 20, 'penalty_bad_ret': 0, 'bonus_direct_call': 15,
        'bonus_pivot': 0, 'bonus_syscall': 60,
    })
    print(f"  Baseline NDCG@5 (current config.py) = {baseline:.4f}")

    study = optuna.create_study(direction='maximize',
                                sampler=optuna.samplers.TPESampler(seed=42))
    study.optimize(make_objective(df_arch), n_trials=n_trials, show_progress_bar=True)

    best = study.best_trial
    best_weights = {'base_score': 100, **best.params}
    best_ndcg = best.value

    print(f"  Best NDCG@5 = {best_ndcg:.4f}  (Δ = {best_ndcg - baseline:+.4f})")
    print(f"  Best weights: {best_weights}")
    return best_weights


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Tune config.py scoring_weights with Optuna (no LightGBM)')
    parser.add_argument('--csv',    required=True, help='Labelled dataset CSV')
    parser.add_argument('--arch',   default=None,
                        choices=['x86_64', 'arm64', 'riscv64'],
                        help='Architecture to tune (default: all three)')
    parser.add_argument('--trials', type=int, default=100, help='Optuna trials per arch')
    parser.add_argument('--out',    default='/tmp/heuristic_weights.json',
                        help='Output JSON with suggested weights')
    args = parser.parse_args()

    df = pd.read_csv(args.csv)
    archs = [args.arch] if args.arch else ['x86_64', 'arm64', 'riscv64']

    results = {}
    for arch in archs:
        print(f"\n{'='*50}")
        print(f" Tuning heuristic for: {arch}")
        print(f"{'='*50}")
        w = tune_arch(df, arch, n_trials=args.trials)
        if w:
            results[arch] = w

    print(f"\n{'='*50}")
    print(" SUGGESTED config.py scoring_weights")
    print(f"{'='*50}")
    print(json.dumps(results, indent=2))

    with open(args.out, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n[heuristic] Saved to {args.out}")
    print("[heuristic] Apply these manually to lcsajdump/core/config.py")
