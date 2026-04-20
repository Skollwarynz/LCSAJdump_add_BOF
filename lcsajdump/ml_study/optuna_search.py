"""
optuna_search.py — Hyperparameter optimisation for the gadget LambdaRank model.

Uses Optuna TPE sampler to search over LightGBM hyperparameters, optimising
mean NDCG@5 on a group-aware hold-out split.

Usage
-----
    python -m lcsajdump_dbg.ml.optuna_search \\
        --csv /tmp/gadget_dataset_v3.csv \\
        --trials 80 \\
        --out /tmp/optuna_results.json \\
        --model gadget_model_best.pkl
"""
from __future__ import annotations

import argparse
import json
import pickle
import sys

import numpy as np

try:
    import lightgbm as lgb
    import optuna
    import pandas as pd
    from sklearn.model_selection import GroupShuffleSplit
    from sklearn.metrics import ndcg_score as _ndcg
except ImportError as e:
    print(f"Missing dependency: {e}", file=sys.stderr)
    sys.exit(1)

from lcsajdump_dbg.ml.features import FEATURE_NAMES
from lcsajdump_dbg.ml.trainer import _fix_degenerate_groups, _rebuild_groups, DEFAULT_PARAMS

optuna.logging.set_verbosity(optuna.logging.WARNING)


# ── Objective ─────────────────────────────────────────────────────────────────

def make_objective(df: pd.DataFrame, val_fraction: float = 0.2):
    """Return an Optuna objective that evaluates a LightGBM config on a fixed split."""
    X_df = df[FEATURE_NAMES]
    y_arr = df['label'].values.astype(np.float32)

    # Build group index from binary_id (same logic as trainer.py)
    binary_ids = df['binary_id'].unique().tolist()
    bid_to_idx = {bid: i for i, bid in enumerate(binary_ids)}
    group_idx = df['binary_id'].map(bid_to_idx).values
    groups_arr = df.groupby('binary_id', sort=False).size().values

    # Fixed split (same seed as trainer.py for reproducibility)
    gss = GroupShuffleSplit(n_splits=1, test_size=val_fraction, random_state=42)
    train_idx, val_idx = next(gss.split(X_df, y_arr, groups=group_idx))

    X_train = X_df.iloc[train_idx]
    y_train = y_arr[train_idx]
    g_train = _rebuild_groups(group_idx, train_idx)

    X_val = X_df.iloc[val_idx]
    y_val = y_arr[val_idx]
    g_val = _rebuild_groups(group_idx, val_idx)
    g_val_ids = [binary_ids[group_idx[val_idx][0]]]  # not used but for reference

    y_train_c, g_train_c, X_train_c = _fix_degenerate_groups(y_train, g_train, X_train)

    def objective(trial: optuna.Trial) -> float:
        params = {
            'objective':         'lambdarank',
            'metric':            'ndcg',
            'ndcg_eval_at':      [5],
            'label_gain':        [0, 1],
            'verbose':           -1,
            'random_state':      42,

            # Searched hyperparameters
            'num_leaves':        trial.suggest_int('num_leaves', 20, 100),
            'max_depth':         trial.suggest_int('max_depth', 5, 15),
            'min_child_samples': trial.suggest_int('min_child_samples', 20, 200), # min_data_in_leaf
            'learning_rate':     trial.suggest_float('learning_rate', 0.01, 0.1, log=True),
            'n_estimators':      trial.suggest_int('n_estimators', 100, 1000),
            'subsample':         trial.suggest_float('subsample', 0.5, 1.0),
            'colsample_bytree':  trial.suggest_float('colsample_bytree', 0.5, 1.0),
            'reg_alpha':         trial.suggest_float('reg_alpha', 1e-4, 10.0, log=True),
            'reg_lambda':        trial.suggest_float('reg_lambda', 1e-4, 10.0, log=True),
        }

        model = lgb.LGBMRanker(**params)
        model.fit(X_train_c, y_train_c, group=g_train_c)

        scores = model.predict(X_val)
        ndcg_vals = []
        offset = 0
        for size in g_val:
            tc = y_val[offset:offset + size]
            sc = scores[offset:offset + size]
            if tc.sum() > 0:
                try:
                    ndcg_vals.append(_ndcg([tc], [sc], k=5))
                except Exception:
                    pass
            offset += size

        return float(np.mean(ndcg_vals)) if ndcg_vals else 0.0

    return objective, X_train_c, y_train_c, g_train_c, X_val, y_val, g_val


# ── Main ──────────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Optuna hyperparameter search for gadget ranker')
    parser.add_argument('--csv',    required=True, help='Dataset CSV path')
    parser.add_argument('--trials', type=int, default=80, help='Number of Optuna trials')
    parser.add_argument('--out',    default='/tmp/optuna_results.json', help='Output JSON')
    parser.add_argument('--model',  default='/tmp/gadget_model_best.pkl', help='Best model output')
    args = parser.parse_args()

    df = pd.read_csv(args.csv)
    for col in FEATURE_NAMES:
        if col not in df.columns:
            df[col] = 0
    print(f"[optuna] Dataset: {len(df)} samples, {df['binary_id'].nunique()} groups")

    objective, X_tr, y_tr, g_tr, X_val, y_val, g_val = make_objective(df)

    study = optuna.create_study(direction='maximize',
                                sampler=optuna.samplers.TPESampler(seed=42))
    print(f"[optuna] Running {args.trials} trials (optimising NDCG@5)...")
    study.optimize(objective, n_trials=args.trials, show_progress_bar=True)

    best = study.best_trial
    print(f"\n[optuna] Best NDCG@5 = {best.value:.4f}")
    print(f"[optuna] Best params: {best.params}")

    # Retrain best model on full train split
    best_params = {
        'objective':    'lambdarank',
        'metric':       'ndcg',
        'ndcg_eval_at': [1, 3, 5, 10],
        'label_gain':   [0, 1],
        'verbose':      -1,
        'random_state': 42,
        **best.params,
    }
    final_model = lgb.LGBMRanker(**best_params)
    final_model.fit(X_tr, y_tr, group=g_tr)

    # Final evaluation
    scores = final_model.predict(X_val)
    ndcg_at = {}
    for k in (1, 3, 5, 10):
        vals = []
        offset = 0
        for size in g_val:
            tc = y_val[offset:offset + size]
            sc = scores[offset:offset + size]
            if tc.sum() > 0:
                try:
                    vals.append(_ndcg([tc], [sc], k=k))
                except Exception:
                    pass
            offset += size
        ndcg_at[f'ndcg_{k}'] = float(np.mean(vals)) if vals else 0.0

    print("\n=== FINAL EVALUATION (best hyperparams) ===")
    for metric, val in ndcg_at.items():
        print(f"  {metric}: {val:.4f}")

    # Save best model
    model_data = {
        'model':         final_model,
        'feature_names': FEATURE_NAMES,
        'params':        best_params,
        'ndcg':          ndcg_at,
    }
    with open(args.model, 'wb') as f:
        pickle.dump(model_data, f)
    print(f"[optuna] Best model saved to {args.model}")

    # Save study results
    trials_data = [
        {'number': t.number, 'value': t.value, 'params': t.params}
        for t in study.trials
    ]
    results = {
        'best_value': best.value,
        'best_params': best.params,
        'final_ndcg': ndcg_at,
        'trials': trials_data,
    }
    with open(args.out, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"[optuna] Results saved to {args.out}")
