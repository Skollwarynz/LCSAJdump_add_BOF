import os
import sys
import pandas as pd
from lcsajdump_dbg.core.loader import BinaryLoader
from lcsajdump_dbg.core.graph import LCSAJGraph
from lcsajdump_dbg.core.rainbowBFS import RainbowFinder
from lcsajdump_dbg.ml.features import extract_features, FEATURE_NAMES
from lcsajdump_dbg.ml.ground_truth_factory import generate_ground_truth

def analyze_binary(binary_path, ground_truth_addrs, max_gadgets=500):
    """Run LCSAJdump on a binary and extract ML features."""
    print(f"[*] Analyzing {binary_path}...")
    try:
        loader = BinaryLoader(binary_path, "x86_64")
        insns = loader.disassemble()
        
        gb = LCSAJGraph(insns, "x86_64")
        gb.build_lazy(max_depth=15)
        
        finder = RainbowFinder(gb, max_depth=15, max_darkness=5, max_insns=15)
        paths = finder.search()
        
        rows = []
        gadgets = []
        gadget_pool = set()
        
        for path in paths:
            if not path:
                continue
                
            start_addr = path[0]
            gadget_pool.add(start_addr)
            
            # Reconstruct instructions
            insn_dicts = []
            size_bytes = 0
            for addr in path:
                node = finder.gm.addr_to_node.get(addr)
                if node:
                    for insn in node.get("insns", []):
                        insn_dicts.append({
                            "mnemonic": insn.mnemonic,
                            "op_str": insn.op_str
                        })
                        size_bytes += insn.size
                        
            heuristic_score = finder.score_gadget(path)
            
            # We don't have _classify_gadget directly exported cleanly without path, but we can assume "Sequential"
            gadgets.append({
                "address": start_addr,
                "instructions": insn_dicts,
                "score": heuristic_score,
                "size_bytes": size_bytes,
                "type": "Sequential"
            })
            
        # Sort by heuristic to get a mix of good and bad
        gadgets.sort(key=lambda x: x["score"], reverse=True)
        
        positive_count = 0
        for g in gadgets[:max_gadgets]:
            addr = g["address"]
            is_positive = int(addr in ground_truth_addrs)
            if is_positive:
                positive_count += 1
                
            feats = extract_features(
                instructions=g["instructions"],
                arch="x86_64",
                gadget_type=g["type"],
                heuristic_score=g["score"],
                address=addr,
                gadget_pool=gadget_pool,
                binary_path=binary_path,
                gadget_size=g["size_bytes"]
            )
            
            row = {
                'binary_id': os.path.basename(binary_path),
                'binary': binary_path,
                'arch': "x86_64",
                'address': addr,
                'label': is_positive
            }
            row.update(feats)
            rows.append(row)
            
        print(f"[+] Found {positive_count} positive gadgets out of {len(rows)} analyzed in {binary_path}")
        return rows
    except Exception as e:
        print(f"[!] Failed to analyze {binary_path}: {e}")
        return []

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--target_dir", default="rop_emporium_bins", help="Directory to analyze")
    parser.add_argument("--out_csv", default="synthetic_dataset.csv", help="Output CSV file")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout per binary for angrop")
    parser.add_argument("--max_gadgets", type=int, default=500, help="Max gadgets to analyze per binary")
    args = parser.parse_args()
    
    target_dir = args.target_dir
    out_csv = args.out_csv
    
    print(f"[*] Generating ground truth using angrop on {target_dir}...")
    truth = generate_ground_truth(target_dir, timeout=args.timeout)
    print(f"[+] Found execve chains or useful gadgets for {len(truth)} binaries.")
    
    # We should save progress iteratively to not lose it if it crashes
    import os
    if os.path.exists(out_csv):
        os.remove(out_csv)
    
    total_saved = 0
    total_pos = 0
    
    first = True
    for binary_path, chain_addrs in truth.items():
        rows = analyze_binary(binary_path, chain_addrs, max_gadgets=args.max_gadgets)
        if rows:
            df = pd.DataFrame(rows)
            df.to_csv(out_csv, mode='a', header=first, index=False)
            first = False
            total_saved += len(df)
            total_pos += df['label'].sum()
            print(f"[+] Appended {len(df)} gadgets to {out_csv}")
            
    if total_saved > 0:
        print(f"[+] Final: Saved {total_saved} gadgets to {out_csv}")
        print(f"[+] Dataset contains {total_pos} positive gadgets ({(total_pos/total_saved)*100:.1f}%)")
    else:
        print("[!] No data collected.")

if __name__ == "__main__":
    main()
