"""
optuna_bfs.py — Ottimizzazione degli iperparametri strutturali del BFS.

Ottimizza i parametri di lcsajdump-dbg (depth, darkness, instructions,
min_score, old) tramite Optuna TPE, massimizzando NDCG@5 sul dataset
di exploit annotati.

Usage
-----
    python -m lcsajdump.ml.optuna_bfs --arch x86_64 --trials 100
    python -m lcsajdump.ml.optuna_bfs --arch arm64 --trials 100 --jobs 4
    python -m lcsajdump.ml.optuna_bfs --arch riscv64 --out /tmp/bfs_riscv64.json
"""
import argparse
import json
import subprocess
import sys
import os
import numpy as np

try:
    import optuna
    from sklearn.metrics import ndcg_score
except ImportError:
    print("Mancano le dipendenze: pip install optuna scikit-learn", file=sys.stderr)
    sys.exit(1)

from lcsajdump.ml.dataset_builder import (
    ALL_SAMPLES,
    extract_gadget_addresses,
    _matches_any_pattern,
    _gadget_text
)

optuna.logging.set_verbosity(optuna.logging.WARNING)

# Default CLI parameters of lcsajdump-dbg (used for baseline)
_DEFAULTS = {
    'depth':        20,
    'darkness':     5,
    'instructions': 15,
    'min_score':    0,
    'old':          False,
}

# NDCG cut-off: consistent with optuna_heuristic.py
NDCG_K = 5


def run_lcsajdump(binary_path, arch, depth, darkness, instructions, min_score, penalty_threshold,
                  all_exec, old=False):
    """Esegue la CLI lcsajdump-dbg e restituisce i risultati JSON."""
    cmd = [
        "lcsajdump-dbg", binary_path,
        "--json", "--limit", "9999",
        "--depth", str(depth),
        "--darkness", str(darkness),
        "--instructions", str(instructions),
        "--min-score", str(min_score),
        "--arch", arch,
    ]
    # Here we would normally pass penalty_threshold to the CLI if it supports it.
    # If the CLI doesn't support it directly yet, you might need to add a CLI flag for it,
    # or export it via env var. Assuming we add an env var or a flag in lcsajdump-dbg later,
    # for now we will just pass it to the function and maybe append to cmd if implemented.
    # We will pass it via an env var hack for now to avoid modifying the CLI arg parser unless requested.
    env = os.environ.copy()
    env["LCSAJ_PENALTY_THRESHOLD"] = str(penalty_threshold)
    
    if all_exec:
        cmd.append("--all-exec")
    if old:
        cmd.append("--old")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=env)
        if result.returncode != 0:
            return None

        start = result.stdout.find('{')
        if start == -1:
            return None

        return json.loads(result.stdout[start:])
    except Exception:
        return None


def _eval_params(test_cases, arch, depth, darkness, instructions, min_score, penalty_threshold, old):
    """Calcola NDCG@K medio per un set di parametri BFS."""
    ndcg_vals = []

    for tc in test_cases:
        data = run_lcsajdump(
            tc['binary'], arch, depth, darkness, instructions, min_score, penalty_threshold,
            tc['all_exec'], old=old,
        )
        if not data:
            continue

        y_true = []
        y_score = []

        all_gadgets = data.get('sequential', []) + data.get('jump_based', [])

        for g in all_gadgets:
            addr = int(g['primary_address'], 16)

            by_addr = (addr in tc['good_addrs'] or any(
                int(dup, 16) in tc['good_addrs']
                for dup in g.get('duplicate_addresses', [])
            ))
            by_pattern = bool(
                tc['patterns'] and _matches_any_pattern(_gadget_text(g), tc['patterns'])
            )

            y_true.append(1 if (by_addr or by_pattern) else 0)
            y_score.append(g.get('score', 0))

        # Skip test cases with no positive gadgets (avoids distorting the mean)
        if sum(y_true) == 0:
            continue

        try:
            ndcg_vals.append(ndcg_score([y_true], [y_score], k=NDCG_K))
        except Exception:
            pass

    return float(np.mean(ndcg_vals)) if ndcg_vals else 0.0


def make_objective(samples, arch):
    test_cases = []
    for s in samples:
        if s.get('arch') != arch or not os.path.exists(s['binary']):
            continue

        good_addrs = set()
        for exp in s.get('exploits', []):
            if os.path.exists(exp):
                good_addrs.update(extract_gadget_addresses(exp, s['binary']))

        patterns = s.get('patterns', [])

        if good_addrs or patterns:
            test_cases.append({
                'binary':    s['binary'],
                'good_addrs': good_addrs,
                'patterns':  patterns,
                'all_exec':  s.get('all_exec', False),
            })

    print(f"[optuna_bfs] Trovati {len(test_cases)} binari di test validi per {arch}")

    # Baseline con parametri default
    baseline = _eval_params(
        test_cases, arch,
        depth=_DEFAULTS['depth'],
        darkness=_DEFAULTS['darkness'],
        instructions=_DEFAULTS['instructions'],
        min_score=_DEFAULTS['min_score'],
        penalty_threshold=50,
        old=_DEFAULTS['old'],
    )
    print(f"[optuna_bfs] Baseline NDCG@{NDCG_K} (default params) = {baseline:.4f}")

    def objective(trial):
        depth        = trial.suggest_int('depth',        3,  50)
        darkness     = trial.suggest_int('darkness',     1,  20)
        instructions = trial.suggest_int('instructions', 3,  30)
        min_score    = trial.suggest_int('min_score',    0, 100)
        penalty_threshold = trial.suggest_int('penalty_threshold', 20, 80)
        old          = trial.suggest_categorical('old', [False, True])

        return _eval_params(
            test_cases, arch, depth, darkness, instructions, min_score, penalty_threshold, old
        )

    return objective, baseline


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Ottimizza i parametri BFS di lcsajdump-dbg con Optuna'
    )
    parser.add_argument('--arch',   required=True, choices=['x86_64', 'arm64', 'riscv64'])
    parser.add_argument('--trials', type=int, default=50,
                        help='Numero di trial Optuna (default: 50)')
    parser.add_argument('--jobs',   type=int, default=1,
                        help='Trials in parallelo (default: 1)')
    parser.add_argument('--out',    default=None,
                        help='Percorso output JSON dei risultati')
    args = parser.parse_args()

    print(f"{'='*50}")
    print(f" Tuning BFS parameters for: {args.arch}")
    print(f" NDCG@{NDCG_K}, {args.trials} trials, {args.jobs} jobs")
    print(f"{'='*50}")

    objective, baseline = make_objective(ALL_SAMPLES, args.arch)

    study = optuna.create_study(
        direction='maximize',
        sampler=optuna.samplers.TPESampler(seed=42),
    )
    study.optimize(
        objective,
        n_trials=args.trials,
        n_jobs=args.jobs,
        show_progress_bar=True,
    )

    best = study.best_trial
    print(f"\n  Baseline NDCG@{NDCG_K}  = {baseline:.4f}")
    print(f"  Miglior NDCG@{NDCG_K}   = {best.value:.4f}  "
          f"(Δ = {best.value - baseline:+.4f})")
    print(f"  Migliori parametri BFS: {best.params}")

    if args.out:
        trials_data = [
            {'number': t.number, 'value': t.value, 'params': t.params}
            for t in study.trials
        ]
        results = {
            'arch':         args.arch,
            'ndcg_k':       NDCG_K,
            'baseline':     baseline,
            'best_value':   best.value,
            'best_params':  best.params,
            'trials':       trials_data,
        }
        with open(args.out, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[optuna_bfs] Risultati salvati in {args.out}")
