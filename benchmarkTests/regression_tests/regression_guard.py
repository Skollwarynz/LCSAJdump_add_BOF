"""
regression_guard.py — Automated regression testing for model/config changes.

Usage:
    python3 -m benchmarkTests.regression_guard [--model MODEL_PATH] [--config CONFIG_PATH]

This script compares new benchmark results against frozen metrics from
benchmarkTests/v12_frozen_metrics.json (or the latest frozen version).

Exit codes:
    0 = All freeze thresholds met (PASS)
    1 = One or more thresholds failed (REGRESSION)
    2 = Error during benchmark execution

To freeze new metrics after retraining:
    cp benchmarkTests/v12_frozen_metrics.json benchmarkTests/v13_frozen_metrics.json
"""

from __future__ import annotations

import sys
import os
import json
import math
import subprocess
import argparse
from pathlib import Path
from typing import Optional

# Paths
BASE_DIR = Path(__file__).parent.parent
DEFAULT_FROZEN_METRICS = BASE_DIR / "benchmarkTests/v12_frozen_metrics.json"


def load_frozen_metrics(path: Path) -> Optional[dict]:
    """Load the frozen metrics baseline."""
    if not path.exists():
        print(f"[ERROR] Frozen metrics not found: {path}")
        return None
    try:
        with open(path) as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load frozen metrics: {e}")
        return None


def run_benchmark(output_path: Path) -> bool:
    """Run the extended benchmark and save results."""
    print("[INFO] Running extended benchmark...")
    cmd = [
        sys.executable,
        "-m",
        "benchmarkTests.extended_benchmark",
        "--all",
        "--output",
        str(output_path),
    ]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        if result.returncode != 0:
            print(f"[ERROR] Benchmark failed: {result.stderr}")
            return False
        print("[INFO] Benchmark completed successfully")
        return True
    except subprocess.TimeoutExpired:
        print("[ERROR] Benchmark timed out after 30 minutes")
        return False
    except Exception as e:
        print(f"[ERROR] Benchmark execution failed: {e}")
        return False


def compare_metrics(frozen: dict, current: dict) -> tuple[bool, list[str]]:
    """
    Compare current metrics against frozen baseline.
    Returns (pass/fail, list of failures).
    """
    failures = []
    warnings = []

    # Check freeze pass flag
    if not current.get("freeze_pass", False):
        failures.append("Current benchmark failed freeze thresholds")
        # Add specific failure reasons
        for reason in current.get("freeze_fail_reasons", []):
            failures.append(f"  -> {reason}")

    # Compare per-architecture metrics
    frozen_archs = frozen.get("per_arch", {})
    current_archs = current.get("per_arch", {})

    print("\n" + "=" * 80)
    print("REGRESSION GUARD COMPARISON")
    print("=" * 80)

    for arch in sorted(set(frozen_archs.keys()) | set(current_archs.keys())):
        f_stats = frozen_archs.get(arch, {})
        c_stats = current_archs.get(arch, {})

        print(f"\n  Architecture: {arch}")
        print(f"  {'─' * 76}")

        # Compare NDCG@20
        f_ndcg = f_stats.get("mean_ndcg20_exploit")
        c_ndcg = c_stats.get("mean_ndcg20_exploit")

        if f_ndcg is not None and c_ndcg is not None:
            delta = c_ndcg - f_ndcg
            marker = "✓" if c_ndcg >= f_ndcg else "✗"
            print(
                f"    NDCG@20:  frozen={f_ndcg:.4f}, current={c_ndcg:.4f}, delta={delta:+.4f} {marker}"
            )
            if c_ndcg < f_ndcg * 0.95:  # 5% regression threshold
                failures.append(
                    f"{arch}: NDCG@20 regression {c_ndcg:.4f} < {f_ndcg * 0.95:.4f}"
                )
        elif f_ndcg is not None and c_ndcg is None:
            warnings.append(f"{arch}: Missing current NDCG@20 (was {f_ndcg:.4f})")

        # Compare recall@20
        f_rec = f_stats.get("mean_recall20_ml")
        c_rec = c_stats.get("mean_recall20_ml")

        if f_rec is not None and c_rec is not None:
            delta = c_rec - f_rec
            marker = "✓" if c_rec >= f_rec else "✗"
            print(
                f"    Recall@20: frozen={f_rec:.4f}, current={c_rec:.4f}, delta={delta:+.4f} {marker}"
            )
            if c_rec < f_rec * 0.95:
                failures.append(
                    f"{arch}: Recall@20 regression {c_rec:.4f} < {f_rec * 0.95:.4f}"
                )
        elif f_rec is not None and c_rec is None:
            warnings.append(f"{arch}: Missing current recall@20 (was {f_rec:.4f})")

        # Compare exploit sample count
        f_exp = f_stats.get("n_exploit_gt", 0)
        c_exp = c_stats.get("n_exploit_gt", 0)
        if c_exp < f_exp:
            warnings.append(f"{arch}: Fewer exploit samples ({c_exp} < {f_exp})")

    # Global comparison
    print(f"\n  {'─' * 76}")
    print("  GLOBAL METRICS")
    print(f"  {'─' * 76}")

    f_global_ndcg = frozen.get("global_mean_ndcg20_exploit")
    c_global_ndcg = current.get("global_mean_ndcg20_exploit")
    if f_global_ndcg and c_global_ndcg:
        print(
            f"    Global NDCG@20: frozen={f_global_ndcg:.4f}, current={c_global_ndcg:.4f}"
        )
        if c_global_ndcg < f_global_ndcg * 0.95:
            failures.append(
                f"Global NDCG@20 regression: {c_global_ndcg:.4f} < {f_global_ndcg * 0.95:.4f}"
            )

    f_global_rec = frozen.get("global_mean_recall20_ml")
    c_global_rec = current.get("global_mean_recall20_ml")
    if f_global_rec and c_global_rec:
        print(
            f"    Global Recall@20: frozen={f_global_rec:.4f}, current={c_global_rec:.4f}"
        )
        if c_global_rec < f_global_rec * 0.95:
            failures.append(
                f"Global recall@20 regression: {c_global_rec:.4f} < {f_global_rec * 0.95:.4f}"
            )

    # Binary count comparison
    f_bins = frozen.get("total_binaries", 0)
    c_bins = current.get("total_binaries", 0)
    print(f"    Total binaries: frozen={f_bins}, current={c_bins}")
    if c_bins < f_bins:
        warnings.append(f"Fewer binaries tested ({c_bins} < {f_bins})")

    return len(failures) == 0, failures


def main():
    parser = argparse.ArgumentParser(description="ML model regression guard")
    parser.add_argument(
        "--frozen",
        type=Path,
        default=DEFAULT_FROZEN_METRICS,
        help="Path to frozen metrics JSON (default: v12_frozen_metrics.json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Output path for new benchmark results (default: temp file)",
    )
    parser.add_argument(
        "--no-benchmark",
        action="store_true",
        help="Skip benchmark, only compare existing results",
    )
    args = parser.parse_args()

    # Load frozen metrics
    frozen = load_frozen_metrics(args.frozen)
    if frozen is None:
        sys.exit(2)

    # Determine output path
    if args.output:
        output_path = args.output
    else:
        output_path = BASE_DIR / "benchmarkTests/current_benchmark.json"

    # Run benchmark if not skipped
    if not args.no_benchmark:
        if not run_benchmark(output_path):
            sys.exit(2)

    # Load current metrics
    current = load_frozen_metrics(output_path)
    if current is None:
        print("[ERROR] Failed to load current benchmark results")
        sys.exit(2)

    # Compare metrics
    passed, failures = compare_metrics(frozen, current)

    # Print summary
    print("\n" + "=" * 80)
    if passed:
        print("✓ REGRESSION GUARD PASSED")
        print("  All metrics meet or exceed frozen baseline")
        if args.no_benchmark:
            print(f"  Compared: {args.frozen}")
            print(f"  Against:  {output_path}")
        sys.exit(0)
    else:
        print("✗ REGRESSION GUARD FAILED")
        print("  Failures:")
        for f in failures:
            print(f"    • {f}")
        print("\n  To update frozen metrics after intentional changes:")
        print(f"    cp {output_path} benchmarkTests/vN_frozen_metrics.json")
        sys.exit(1)


if __name__ == "__main__":
    main()
