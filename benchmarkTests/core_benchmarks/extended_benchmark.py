"""
extended_benchmark.py — Extended Phase A benchmark for v12 freeze criteria.

Walks all binary directories (rop_emporium_bins, testCTFs, ctf_binaries, tesi)
to find ≥20 targets across x86_64, x86_32, arm64, riscv64.

Usage:
    python3 -m benchmarkTests.extended_benchmark --all [--output v12_frozen_metrics.json]

Freeze thresholds (v12 is "perfect" when):
    - Mean NDCG@20 (exploit GT) ≥ 0.75 across all archs
    - No arch with mean NDCG@20 < 0.60
    - Exploit-gadget recall@20 ≥ 90%
"""

from __future__ import annotations

import sys
import os
import json
import math
import argparse
import traceback
import csv
import re
from pathlib import Path
from collections import defaultdict
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lcsajdump_dbg.core.loader import BinaryLoader
from lcsajdump_dbg.core.graph import LCSAJGraph
from lcsajdump_dbg.core.rainbowBFS import RainbowFinder
from lcsajdump_dbg.ml.model_scorer import MLScorer, _batch_rescore
from lcsajdump_dbg.ml.dataset_builder import extract_gadget_addresses, ALL_SAMPLES


BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE, "lcsajdump_dbg/ml/models/gadget_model_v14.pkl")

# ── Freeze thresholds (Phase A) ───────────────────────────────────────────────
FREEZE_NDCG20_MEAN = 0.75  # mean NDCG@20 (exploit GT) across all archs
FREEZE_NDCG20_MIN = 0.60  # no individual arch below this
FREEZE_RECALL20 = 0.90  # exploit-gadget recall@20 (primary metric)

# ── Binary Discovery Configuration ──────────────────────────────────────────────
BINARY_SEARCH_PATHS = [
    ("rop_emporium_bins", "auto"),  # Will detect x86_64 vs x86_32
    ("testCTFs", "auto"),
    ("ctf_binaries", "auto"),
]

# Architecture detection patterns
ARCH_PATTERNS = {
    "x86_64": [b"\x7fELF\x02\x01\x01", b"x86-64"],
    "x86_32": [b"\x7fELF\x01\x01\x01", b"i386"],
    "arm64": [b"\x7fELF\x02\x01\x01", b"aarch64"],
    "riscv64": [b"\x7fELF\x02\x01\x01", b"RISC-V"],
}


# ── Helper: Architecture Detection ───────────────────────────────────────────
def detect_arch(binary_path: str) -> Optional[str]:
    """Detect architecture of an ELF binary."""
    try:
        with open(binary_path, "rb") as f:
            header = f.read(128)

        if len(header) < 5 or header[:4] != b"\x7fELF":
            return None

        elf_class = header[4]  # 1 = 32-bit, 2 = 64-bit
        machine = header[18:20]

        # Check for specific architectures
        with open(binary_path, "rb") as f:
            content = f.read(4096)

        if b"x86-64" in content:
            return "x86_64"
        elif b"aarch64" in content:
            return "arm64"
        elif b"RISC-V" in content:
            return "riscv64"
        elif b"i386" in content or elf_class == 1:
            return "x86_32"

        # Try using file command
        import subprocess

        result = subprocess.run(["file", binary_path], capture_output=True, text=True)
        output = result.stdout.lower()

        if "x86-64" in output or "x86_64" in output:
            return "x86_64"
        elif "aarch64" in output or "arm64" in output:
            return "arm64"
        elif "riscv" in output:
            return "riscv64"
        elif "intel 80386" in output or "i386" in output:
            return "x86_32"

    except Exception:
        pass

    return None


# ── Helper: Discover Binaries ─────────────────────────────────────────────────
def discover_binaries(base_path: str) -> list[dict]:
    """
    Discover all ELF binaries in search paths and match with exploit scripts.
    Returns list of dicts: {binary, arch, exploits, name, all_exec}
    """
    discovered = []

    for subdir, default_arch in BINARY_SEARCH_PATHS:
        search_path = os.path.join(base_path, subdir)
        if not os.path.exists(search_path):
            continue

        for root, dirs, files in os.walk(search_path):
            for fname in files:
                fpath = os.path.join(root, fname)

                # Skip non-executable files and common non-binary extensions
                if not os.path.isfile(fpath) or not os.access(fpath, os.X_OK):
                    continue
                if fname.endswith(
                    (".py", ".txt", ".md", ".c", ".h", ".o", ".so", ".zip")
                ):
                    continue
                if fname.startswith(".") or fname == "Makefile":
                    continue

                # Detect architecture
                arch = detect_arch(fpath)
                if arch is None:
                    continue

                # Look for exploit script in same directory
                exploits = []
                parent_dir = os.path.dirname(fpath)
                for exp_name in [
                    "exploit.py",
                    "solve.py",
                    "xpl.py",
                    f"{fname}_exploit.py",
                    f"{fname}_solve.py",
                    f"xpl_{fname}.py",
                ]:
                    exp_path = os.path.join(parent_dir, exp_name)
                    if os.path.exists(exp_path):
                        exploits.append(exp_path)
                        break

                # Also check for any .py files in the directory
                if not exploits:
                    for py_file in (
                        os.listdir(parent_dir) if os.path.isdir(parent_dir) else []
                    ):
                        if py_file.endswith(".py"):
                            py_path = os.path.join(parent_dir, py_file)
                            # Check if it contains hex addresses
                            try:
                                with open(py_path, "r") as f:
                                    content = f.read()
                                    if re.search(r"0x[0-9a-fA-F]{4,}", content):
                                        exploits.append(py_path)
                                        break
                            except:
                                pass

                discovered.append(
                    {
                        "binary": fpath,
                        "arch": arch,
                        "exploits": exploits,
                        "name": os.path.relpath(fpath, base_path),
                        "all_exec": False,  # Conservative default
                    }
                )

    return discovered


# ── Helper: Merge with ALL_SAMPLES ───────────────────────────────────────────
def build_target_list() -> list[dict]:
    """
    Build comprehensive target list from ALL_SAMPLES + discovered binaries.
    Ensures we have ≥20 targets across all architectures.
    """
    targets = []
    seen_paths = set()

    # First, use ALL_SAMPLES from dataset_builder (high quality, verified exploits)
    for sample in ALL_SAMPLES:
        binary = sample.get("binary", "")
        if binary and os.path.exists(binary):
            targets.append(
                {
                    "binary": binary,
                    "arch": sample.get("arch", "x86_64"),
                    "exploits": sample.get("exploits", []),
                    "name": Path(binary).name,
                    "all_exec": sample.get("all_exec", False),
                    "patterns": sample.get("patterns"),  # For pattern-based GT
                }
            )
            seen_paths.add(os.path.abspath(binary))

    print(f"[build_target_list] Loaded {len(targets)} samples from ALL_SAMPLES")
    print(f"  With exploit GT: {sum(1 for t in targets if t.get('exploits'))}")

    # Then discover additional binaries
    discovered = discover_binaries(BASE)

    added = 0
    for d in discovered:
        abs_path = os.path.abspath(d["binary"])
        if abs_path not in seen_paths:
            targets.append(d)
            seen_paths.add(abs_path)
            added += 1

    print(f"[build_target_list] Added {added} new binaries from discovery")

    return targets


# ── Metrics Helpers ──────────────────────────────────────────────────────────
def _ndcg_at_k(ranked_sigs: list[str], relevant: set[str], k: int) -> float:
    if not relevant:
        return float("nan")
    dcg = sum(
        1.0 / math.log2(r + 2) for r, s in enumerate(ranked_sigs[:k]) if s in relevant
    )
    idcg = sum(1.0 / math.log2(r + 2) for r in range(min(len(relevant), k)))
    return dcg / idcg if idcg > 0 else 0.0


def _jaccard(a: list[str], b: list[str], k: int) -> float:
    sa, sb = set(a[:k]), set(b[:k])
    return len(sa & sb) / len(sa | sb) if sa | sb else 0.0


def _recall_at_k(ranked_sigs: list[str], relevant: set[str], k: int) -> float:
    if not relevant:
        return float("nan")
    hits = sum(1 for s in ranked_sigs[:k] if s in relevant)
    return hits / len(relevant)


def _rank_percentile(ranked_sigs: list[str], relevant: set[str]) -> float:
    if not relevant:
        return float("nan")
    n = len(ranked_sigs)
    percentiles = [r / n for r, s in enumerate(ranked_sigs) if s in relevant]
    return sum(percentiles) / len(percentiles) if percentiles else 1.0


def _top1pct_k(total_gadgets: int) -> int:
    return max(20, total_gadgets // 100)


# ── Single Binary Benchmark ────────────────────────────────────────────────────
def run_single(
    binary: str,
    arch: str,
    top_n: int,
    depth: int,
    darkness: int,
    exploit_paths: list[str] | None = None,
    patterns: list | None = None,
    all_exec: bool = False,
    quiet: bool = False,
) -> dict:
    """
    Run heuristic + ML ranking on one binary. Returns metrics dict.
    """
    if not quiet:
        print(f"\n{'=' * 60}")
        print(f" Binary : {binary}")
        print(f" Arch : {arch} all_exec={all_exec}")
        print(f" Depth : {depth} Darkness: {darkness} Top-N: {top_n}")
        print(f"{'=' * 60}\n")

    if not os.path.exists(binary):
        return {"error": f"binary not found: {binary}"}

    try:
        loader = BinaryLoader(binary, arch, all_exec=all_exec)
        loader.load()
        instructions = loader.disassemble()
        graph = LCSAJGraph(instructions, arch=arch)
        graph.build()
        finder = RainbowFinder(
            graph, max_depth=depth, max_darkness=darkness, max_insns=15
        )
        finder.search()
    except Exception as e:
        return {"error": f"BFS failed: {e}"}

    total = len(finder.grouped_gadgets)
    if not total:
        return {"error": "no gadgets found"}

    if not quiet:
        print(f"[bench] Total gadgets: {total}")

    # Build address-to-sig mapping for exploit GT extraction
    addr_to_sig = {}
    for sig, data in finder.grouped_gadgets.items():
        path = data["path"]
        if path:
            addr_to_sig[path[0]] = sig

    # Heuristic ranking
    heuristic_ranked = [
        (finder.score_gadget(d["path"]), sig)
        for sig, d in finder.grouped_gadgets.items()
    ]
    heuristic_ranked.sort(key=lambda x: x[0], reverse=True)
    h_sigs = [s for _, s in heuristic_ranked]

    # ML ranking
    scorer = MLScorer.load(MODEL_PATH, arch=arch)
    if scorer is None:
        return {"error": "ML model not loaded"}

    _batch_rescore(finder, scorer, finder.score_gadget.__func__)
    ml_cache = finder._ml_score_cache
    ml_ranked = sorted(
        ((ml_cache.get(sig, 0), sig) for sig in finder.grouped_gadgets), reverse=True
    )
    ml_sigs = [s for _, s in ml_ranked]

    # Extract exploit ground truth
    exploit_relevant: set[str] | None = None
    exploit_addrs: set[int] = set()

    if exploit_paths:
        for ep in exploit_paths:
            if ep and os.path.exists(ep):
                exploit_addrs |= extract_gadget_addresses(ep, binary)

    if exploit_addrs:
        exploit_relevant = {addr_to_sig[a] for a in exploit_addrs if a in addr_to_sig}
        if not quiet:
            print(
                f"[bench] Exploit hex addresses: {len(exploit_addrs)} → "
                f"{len(exploit_relevant)} matched gadgets"
            )

    top_n_eff = min(top_n, total)

    metrics = {
        "binary": binary,
        "name": Path(binary).name,
        "arch": arch,
        "total_gadgets": total,
        "has_exploit_gt": exploit_relevant is not None and len(exploit_relevant) > 0,
        "exploit_gt_size": len(exploit_relevant) if exploit_relevant else 0,
    }

    k_vals = [1, 5, 10, 20]
    k1pct = _top1pct_k(total)

    for k in k_vals:
        metrics[f"jaccard_{k}"] = _jaccard(h_sigs, ml_sigs, k)
        metrics[f"ndcg_heur_gt_{k}"] = _ndcg_at_k(ml_sigs, set(h_sigs[:k]), k)
        if exploit_relevant:
            metrics[f"ndcg_exploit_gt_{k}"] = _ndcg_at_k(ml_sigs, exploit_relevant, k)
            metrics[f"recall_ml_{k}"] = _recall_at_k(ml_sigs, exploit_relevant, k)
            metrics[f"recall_heur_{k}"] = _recall_at_k(h_sigs, exploit_relevant, k)

    if exploit_relevant:
        metrics["k_1pct"] = k1pct
        metrics["recall_ml_1pct"] = _recall_at_k(ml_sigs, exploit_relevant, k1pct)
        metrics["recall_heur_1pct"] = _recall_at_k(h_sigs, exploit_relevant, k1pct)
        metrics["ndcg_exploit_gt_1pct"] = _ndcg_at_k(ml_sigs, exploit_relevant, k1pct)
        metrics["rank_pct_ml"] = _rank_percentile(ml_sigs, exploit_relevant)
        metrics["rank_pct_heur"] = _rank_percentile(h_sigs, exploit_relevant)

        # Exploit-success metric: all exploit gadgets in ML top-20?
        all_in_top20 = exploit_relevant.issubset(set(ml_sigs[:20]))
        metrics["all_exploit_in_top20"] = all_in_top20
        metrics["exploit_hit_rate"] = len(exploit_relevant & set(ml_sigs[:20])) / len(
            exploit_relevant
        )

    # Print comparison table
    if not quiet:
        col_w = 52
        print(f"\n{'─' * 120}")
        print(
            f" {'#':<5} {'H_SCORE':<8} {'HEURISTIC TOP':<{col_w}} │ {'ML_SCORE':<8} ML TOP"
        )
        print(f"{'─' * 120}")
        for i in range(top_n_eff):
            hs, hsig = heuristic_ranked[i]
            ms, msig = ml_ranked[i]
            hd = (hsig[: col_w - 1] + "…") if len(hsig) > col_w else hsig
            md = (msig[: col_w - 1] + "…") if len(msig) > col_w else msig
            marker = "◀" if hsig != msig else " "
            h_hit = "✓" if exploit_relevant and hsig in exploit_relevant else " "
            m_hit = "✓" if exploit_relevant and msig in exploit_relevant else " "
            print(
                f" {i + 1:<5} {hs:<8} {h_hit}{hd:<{col_w}} │ {ms:<8} {m_hit}{md} {marker}"
            )

        print(f"\n{'─' * 70}")
        hdr = f" {'k':<5} {'Jaccard':<10} {'NDCG(heur=GT)':<16}"
        if exploit_relevant:
            hdr += f" {'NDCG(exploit=GT)':<18} {'Recall ML@k':<14} {'Recall H@k'}"
        print(hdr)
        print(f"{'─' * 70}")
        for k in k_vals:
            row = (
                f" {k:<5} {metrics[f'jaccard_{k}']:<10.3f}"
                f" {metrics[f'ndcg_heur_gt_{k}']:<16.4f}"
            )
            if exploit_relevant:
                row += (
                    f" {metrics.get(f'ndcg_exploit_gt_{k}', float('nan')):<18.4f}"
                    f" {metrics.get(f'recall_ml_{k}', float('nan')):<14.3f}"
                    f" {metrics.get(f'recall_heur_{k}', float('nan')):.3f}"
                )
            print(row)
        print(f"{'─' * 70}\n")

    return metrics


# ── Full Validation Run ─────────────────────────────────────────────────────
def run_all(
    output_path: str, per_binary_csv: str | None, depth: int, darkness: int
) -> dict:
    """
    Run benchmark across all discovered binaries and save metrics.
    """
    targets = build_target_list()

    # Group by architecture for reporting
    by_arch = defaultdict(list)
    for t in targets:
        by_arch[t["arch"]].append(t)

    print(f"\n{'=' * 80}")
    print(f"DISCOVERED TARGETS: {len(targets)} binaries")
    for arch, items in sorted(by_arch.items()):
        print(f"  {arch}: {len(items)} binaries")
        for item in items[:5]:  # Show first 5
            has_exp = "✓" if item.get("exploits") else "✗"
            print(f"    - {item['name']} (exploit: {has_exp})")
        if len(items) > 5:
            print(f"    ... and {len(items) - 5} more")
    print(f"{'=' * 80}\n")

    if len(targets) < 20:
        print(f"WARNING: Only {len(targets)} targets found, expected ≥20")

    all_metrics = []
    errors = []

    for idx, target in enumerate(targets):
        binary = target["binary"]
        arch = target["arch"]
        exploits = target.get("exploits", [])
        all_exec = target.get("all_exec", False)
        name = target.get("name", Path(binary).name)

        print(f"\n[{idx + 1}/{len(targets)}] {name} ({arch})", flush=True)

        try:
            m = run_single(
                binary=binary,
                arch=arch,
                top_n=20,
                depth=depth,
                darkness=darkness,
                exploit_paths=exploits,
                all_exec=all_exec,
                quiet=True,
            )
            m["name"] = name

            if "error" in m:
                print(f"  SKIP — {m['error']}")
                errors.append({"name": name, "error": m["error"]})
            else:
                total = m["total_gadgets"]
                exploit_info = (
                    f" exploit_gt={m['exploit_gt_size']}"
                    if m["has_exploit_gt"]
                    else " no_exploit_gt"
                )
                j20 = m.get("jaccard_20", float("nan"))
                ndcg20_expl = m.get("ndcg_exploit_gt_20", float("nan"))
                rec20 = m.get("recall_ml_20", float("nan"))
                hit_rate = m.get("exploit_hit_rate", float("nan"))

                status = ""
                if m.get("has_exploit_gt"):
                    if m.get("all_exploit_in_top20"):
                        status = " [ALL_EXPLOIT_IN_TOP20 ✓]"
                    else:
                        status = f" [HIT_RATE={hit_rate:.2%}]"

                print(
                    f"  gadgets={total}{exploit_info} jaccard@20={j20:.3f} "
                    f"NDCG@20={ndcg20_expl if not math.isnan(ndcg20_expl) else 'N/A'} "
                    f"recall@20={rec20 if not math.isnan(rec20) else 'N/A'}{status}"
                )
                all_metrics.append(m)
        except Exception as e:
            print(f"  ERROR — {e}")
            traceback.print_exc()
            errors.append({"name": name, "error": str(e)})

    # ── Aggregate by arch ─────────────────────────────────────────────────────
    archs = sorted({m["arch"] for m in all_metrics})
    per_arch: dict[str, dict] = {}

    for arch in archs:
        arch_ms = [m for m in all_metrics if m["arch"] == arch]
        exploit_ms = [m for m in arch_ms if m.get("has_exploit_gt")]

        def _safe_mean(vals):
            v = [x for x in vals if not math.isnan(x)]
            return sum(v) / len(v) if v else None

        ndcg20_vals = [m.get("ndcg_exploit_gt_20", float("nan")) for m in exploit_ms]
        recall20_vals = [m.get("recall_ml_20", float("nan")) for m in exploit_ms]
        rec1pct_vals = [m.get("recall_ml_1pct", float("nan")) for m in exploit_ms]
        rankpct_vals = [m.get("rank_pct_ml", float("nan")) for m in exploit_ms]
        jaccard20_vals = [m.get("jaccard_20", float("nan")) for m in arch_ms]

        per_arch[arch] = {
            "n_binaries": len(arch_ms),
            "n_exploit_gt": len(exploit_ms),
            "mean_ndcg20_exploit": _safe_mean(ndcg20_vals),
            "mean_recall20_ml": _safe_mean(recall20_vals),
            "mean_recall1pct_ml": _safe_mean(rec1pct_vals),
            "mean_rank_pct_ml": _safe_mean(rankpct_vals),
            "mean_jaccard20": _safe_mean(jaccard20_vals),
        }

    def _safe_mean_global(key, ms):
        vals = [
            m.get(key, float("nan"))
            for m in ms
            if not math.isnan(m.get(key, float("nan")))
        ]
        return sum(vals) / len(vals) if vals else None

    exploit_all_ms = [m for m in all_metrics if m.get("has_exploit_gt")]
    global_mean_ndcg20 = _safe_mean_global("ndcg_exploit_gt_20", exploit_all_ms)
    global_mean_recall20 = _safe_mean_global("recall_ml_20", exploit_all_ms)
    global_mean_rec1pct = _safe_mean_global("recall_ml_1pct", exploit_all_ms)
    global_mean_rankpct = _safe_mean_global("rank_pct_ml", exploit_all_ms)

    # ── Freeze check ──────────────────────────────────────────────────────────
    freeze_pass = True
    freeze_reasons = []

    if global_mean_rec1pct is not None:
        if global_mean_rec1pct < FREEZE_RECALL20:
            freeze_pass = False
            freeze_reasons.append(
                f"global exploit recall@1% {global_mean_rec1pct:.4f} < {FREEZE_RECALL20}"
            )
    elif global_mean_recall20 is not None:
        if global_mean_recall20 < FREEZE_RECALL20:
            freeze_pass = False
            freeze_reasons.append(
                f"global exploit recall@20 {global_mean_recall20:.4f} < {FREEZE_RECALL20}"
            )
    else:
        freeze_reasons.append(
            "no exploit-GT samples — cannot validate recall threshold"
        )
        freeze_pass = False

    if global_mean_ndcg20 is not None and global_mean_ndcg20 < FREEZE_NDCG20_MEAN:
        freeze_pass = False
        freeze_reasons.append(
            f"global mean NDCG@20 {global_mean_ndcg20:.4f} < {FREEZE_NDCG20_MEAN}"
        )

    for arch, stats in per_arch.items():
        v = stats["mean_ndcg20_exploit"]
        if v is not None and v < FREEZE_NDCG20_MIN:
            freeze_pass = False
            freeze_reasons.append(f"arch {arch} NDCG@20 {v:.4f} < {FREEZE_NDCG20_MIN}")

    # ── Summary printout ─────────────────────────────────────────────────────
    print(f"\n{'=' * 90}")
    print("AGGREGATE RESULTS BY ARCH")
    print(f"{'─' * 90}")
    print(
        f" {'ARCH':<12} {'N_BIN':<7} {'N_EXPL':<8} "
        f"{'NDCG@20':<10} {'REC@20':<9} {'REC@1%':<9} {'RANK_PCT':<10} JACCARD@20"
    )
    print(f"{'─' * 90}")
    for arch, s in per_arch.items():
        nd = (
            f"{s['mean_ndcg20_exploit']:.4f}"
            if s["mean_ndcg20_exploit"] is not None
            else "N/A"
        )
        rc = (
            f"{s['mean_recall20_ml']:.4f}"
            if s["mean_recall20_ml"] is not None
            else "N/A"
        )
        r1p = (
            f"{s['mean_recall1pct_ml']:.4f}"
            if s["mean_recall1pct_ml"] is not None
            else "N/A"
        )
        rp = (
            f"{s['mean_rank_pct_ml']:.4f}"
            if s["mean_rank_pct_ml"] is not None
            else "N/A"
        )
        jc = f"{s['mean_jaccard20']:.4f}" if s["mean_jaccard20"] is not None else "N/A"
        print(
            f" {arch:<12} {s['n_binaries']:<7} {s['n_exploit_gt']:<8} "
            f"{nd:<10} {rc:<9} {r1p:<9} {rp:<10} {jc}"
        )
    print(f"{'─' * 90}")
    gn = f"{global_mean_ndcg20:.4f}" if global_mean_ndcg20 is not None else "N/A"
    gr = f"{global_mean_recall20:.4f}" if global_mean_recall20 is not None else "N/A"
    gr1 = f"{global_mean_rec1pct:.4f}" if global_mean_rec1pct is not None else "N/A"
    grp = f"{global_mean_rankpct:.4f}" if global_mean_rankpct is not None else "N/A"
    print(
        f" {'GLOBAL':<12} {len(all_metrics):<7} {len(exploit_all_ms):<8} "
        f"{gn:<10} {gr:<9} {gr1:<9} {grp}"
    )
    print(f"{'=' * 90}")

    print(f"\n{'FREEZE CHECK':}")
    if freeze_pass:
        print(" ✅ PASS — v12 meets all freeze thresholds")
    else:
        print(" ❌ FAIL — thresholds not met:")
        for r in freeze_reasons:
            print(f" • {r}")

    # ── Save JSON ─────────────────────────────────────────────────────────────
    summary = {
        "model": "gadget_model_v14.pkl",
        "total_binaries": len(all_metrics),
        "total_errors": len(errors),
        "arch_coverage": list(per_arch.keys()),
        "global_mean_ndcg20_exploit": global_mean_ndcg20,
        "global_mean_recall20_ml": global_mean_recall20,
        "global_mean_recall1pct_ml": global_mean_rec1pct,
        "global_mean_rank_pct_ml": global_mean_rankpct,
        "freeze_thresholds": {
            "mean_ndcg20": FREEZE_NDCG20_MEAN,
            "min_arch_ndcg20": FREEZE_NDCG20_MIN,
            "recall_1pct": FREEZE_RECALL20,
        },
        "freeze_pass": freeze_pass,
        "freeze_fail_reasons": freeze_reasons,
        "per_arch": per_arch,
        "per_binary": all_metrics,
        "errors": errors,
    }

    if output_path:
        with open(output_path, "w") as f:
            json.dump(
                summary,
                f,
                indent=2,
                default=lambda x: None if isinstance(x, float) and math.isnan(x) else x,
            )
        print(f"\n[bench] Saved → {output_path}")

    # Also emit per-binary CSV
    csv_path = per_binary_csv or (
        output_path.replace(".json", ".csv") if output_path else None
    )
    if csv_path and all_metrics:
        fieldnames = sorted({k for m in all_metrics for k in m.keys()})
        with open(csv_path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=fieldnames)
            w.writeheader()
            for m in all_metrics:
                row = {
                    k: ("" if (isinstance(v, float) and math.isnan(v)) else v)
                    for k, v in m.items()
                }
                w.writerow(row)
        print(f"[bench] CSV → {csv_path}")

    return summary


# ── Main ─────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Extended ML vs Heuristic benchmark")
    parser.add_argument(
        "binary", nargs="?", default=os.path.join(BASE, "rop_emporium_bins/split/split")
    )
    parser.add_argument("arch", nargs="?", default="x86_64")
    parser.add_argument("top_n", nargs="?", type=int, default=20)
    parser.add_argument("--depth", type=int, default=30)
    parser.add_argument("--darkness", type=int, default=5)
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run full validation across all discovered binaries",
    )
    parser.add_argument(
        "--output",
        default="benchmarkTests/v12_frozen_metrics.json",
        help="Output JSON path for --all run",
    )
    parser.add_argument(
        "--csv",
        default=None,
        help="Output CSV path for per-binary metrics (default: auto from --output)",
    )
    args = parser.parse_args()

    if args.all:
        run_all(
            output_path=args.output,
            per_binary_csv=args.csv,
            depth=args.depth,
            darkness=args.darkness,
        )
    else:
        run_single(
            binary=args.binary,
            arch=args.arch,
            top_n=args.top_n,
            depth=args.depth,
            darkness=args.darkness,
        )


if __name__ == "__main__":
    main()
