"""
kfold_cv.py — Group-stratified k-fold cross-validation for the gadget ranker.

Each fold holds out a disjoint set of binary groups (so no binary appears in
both train and val).  Reports NDCG@1/3/5/10 per fold and averaged.

Usage
-----
    python -m lcsajdump_dbg.ml.kfold_cv \\
        --csv /tmp/gadget_dataset_v3.csv \\
        --k 5 \\
        --out /tmp/kfold_results.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict

import numpy as np

try:
    import lightgbm as lgb
    import pandas as pd
    from sklearn.metrics import ndcg_score as _ndcg
except ImportError as e:
    print(f"Missing dependency: {e}", file=sys.stderr)
    sys.exit(1)

from lcsajdump_dbg.ml.features import FEATURE_NAMES
from lcsajdump_dbg.ml.trainer import (
    DEFAULT_PARAMS,
    _fix_degenerate_groups,
    _cap_group_sizes,
)

# ── Core CV logic ─────────────────────────────────────────────────────────────


def run_kfold(df: pd.DataFrame, k: int = 5, params: dict = None) -> dict:
    """
    Group k-fold cross-validation.

    Returns a dict with per-fold and aggregated NDCG scores.
    """
    params = {**DEFAULT_PARAMS, **(params or {})}

    binary_ids = df["binary_id"].unique().tolist()
    n = len(binary_ids)

    if k > n:
        print(f"[kfold] k={k} > n_groups={n}; reducing k to {n}", file=sys.stderr)
        k = n

    # Assign groups to folds round-robin (deterministic)
    rng = np.random.default_rng(42)
    shuffled = rng.permutation(binary_ids).tolist()
    folds = [shuffled[i::k] for i in range(k)]

    fold_results = []
    print(f"[kfold] {k}-fold CV on {n} groups ({len(df)} samples)")
    print(f"[kfold] Fold sizes: {[len(f) for f in folds]}")
    print()

    for fold_idx, val_ids in enumerate(folds):
        train_ids = [bid for bid in binary_ids if bid not in set(val_ids)]

        df_train = df[df["binary_id"].isin(train_ids)].copy()
        df_val = df[df["binary_id"].isin(val_ids)].copy()

        X_train = df_train[FEATURE_NAMES].values
        y_train = df_train["label"].values.astype(np.float32)
        g_train = [
            int(df_train[df_train["binary_id"] == bid].shape[0]) for bid in train_ids
        ]

        X_val = df_val[FEATURE_NAMES].values
        y_val = df_val["label"].values.astype(np.float32)
        g_val = [int(df_val[df_val["binary_id"] == bid].shape[0]) for bid in val_ids]

        # Cap oversized groups then fix degenerate ones
        X_train_df = pd.DataFrame(X_train, columns=FEATURE_NAMES)
        y_train, g_train, X_train_df = _cap_group_sizes(y_train, g_train, X_train_df)
        X_train = X_train_df.values
        y_train_c, g_train_c, _ = _fix_degenerate_groups(y_train, g_train, X_train_df)

        model = lgb.LGBMRanker(**params)
        model.fit(X_train, y_train_c, group=g_train_c)

        # Per-group NDCG for this fold
        # NOTE: use boolean masks instead of offset arithmetic — df_val rows are in
        # CSV order, which may differ from val_ids (shuffled) order.  Offset-based
        # slicing would assign labels/scores to the wrong binary.
        scores = model.predict(X_val)
        ndcg_at = {1: [], 3: [], 5: [], 10: []}
        per_group = {}

        val_bid_col = df_val["binary_id"].values
        for bid in val_ids:
            mask = val_bid_col == bid
            tc = y_val[mask]
            sc = scores[mask]
            if tc.sum() == 0:
                continue
            group_ndcg = {}
            for kk in ndcg_at:
                try:
                    if len(tc) < 2:
                        v = 1.0 if (tc[0] == 1) else 0.0
                    else:
                        v = _ndcg([tc], [sc], k=kk)
                    ndcg_at[kk].append(v)
                    group_ndcg[kk] = round(v, 4)
                except Exception:
                    n_pos = int(tc.sum())
                    if n_pos > 0:
                        top_k_idx = np.argsort(sc)[-kk:][::-1]
                        n_pos_in_top_k = int(tc[top_k_idx].sum())
                        v = n_pos_in_top_k / min(n_pos, kk)
                        ndcg_at[kk].append(v)
                        group_ndcg[kk] = round(v, 4)
            per_group[bid] = group_ndcg

        fold_mean = {
            f"ndcg_{kk}": float(np.mean(v)) if v else 0.0 for kk, v in ndcg_at.items()
        }
        fold_mean["per_group"] = per_group
        fold_mean["val_groups"] = val_ids
        fold_results.append(fold_mean)

        print(f"  Fold {fold_idx + 1}/{k} — val groups: {val_ids}")
        print(
            f"    NDCG@1={fold_mean.get('ndcg_1', 0):.4f}  "
            f"@3={fold_mean.get('ndcg_3', 0):.4f}  "
            f"@5={fold_mean.get('ndcg_5', 0):.4f}  "
            f"@10={fold_mean.get('ndcg_10', 0):.4f}"
        )
        for bid, gn in per_group.items():
            print(
                f"      {bid}: @1={gn.get(1, 0):.3f} @3={gn.get(3, 0):.3f} @5={gn.get(5, 0):.3f}"
            )
        print()

    # Aggregate
    agg = {}
    for metric in ("ndcg_1", "ndcg_3", "ndcg_5", "ndcg_10"):
        vals = [f[metric] for f in fold_results if metric in f]
        if vals:
            agg[metric] = {
                "mean": float(np.mean(vals)),
                "std": float(np.std(vals)),
                "min": float(np.min(vals)),
                "max": float(np.max(vals)),
            }

    print("=== K-FOLD SUMMARY ===")
    for metric, stats in agg.items():
        print(
            f"  {metric}: mean={stats['mean']:.4f} ± {stats['std']:.4f}  "
            f"[{stats['min']:.4f}, {stats['max']:.4f}]"
        )

    return {"k": k, "folds": fold_results, "aggregate": agg}


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="K-fold CV for gadget ranker")
    parser.add_argument("--csv", required=True, help="Dataset CSV path")
    parser.add_argument("--k", type=int, default=5, help="Number of folds")
    parser.add_argument("--out", default="/tmp/kfold_results.json", help="Output JSON")
    args = parser.parse_args()

    df = pd.read_csv(args.csv)
    for col in FEATURE_NAMES:
        if col not in df.columns:
            df[col] = 0
    results = run_kfold(df, k=args.k)

    with open(args.out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[kfold] Results saved to {args.out}")
