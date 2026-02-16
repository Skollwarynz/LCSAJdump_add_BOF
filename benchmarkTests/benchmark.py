import subprocess
import time
import re
import csv
import sys
import datetime
import os

# ================= CONFIGURATION =================
MIN_K = 0
MAX_K = 20

MIN_D = 1
MAX_D = 50
# =================================================

def load_existing_progress(filename):
    """
    Reads the existing CSV and returns a set of (k, d) tuples already processed.
    """
    processed = set()
    if not os.path.exists(filename):
        return processed

    try:
        with open(filename, mode='r', newline='') as f:
            reader = csv.reader(f)
            header = next(reader, None) # Skip header
            if not header: return processed
            
            for row in reader:
                if len(row) >= 2:
                    try:
                        k = int(row[0])
                        d = int(row[1])
                        processed.add((k, d))
                    except ValueError:
                        continue
    except Exception as e:
        print(f"[!] Error reading previous progress: {e}")
    
    return processed

def run_benchmark(target_binary, output_csv):
    # --- UPDATED REGEX FOR NEW OUTPUT FORMAT ---
    # Matches: "(Found 15061 gadgets)"
    gadget_regex = re.compile(r"\(Found\s+(\d+)\s+gadgets\)")
    
    # Matches: "[*] Pruning: 0 pruned branches."
    pruned_regex = re.compile(r"Pruning:\s+(\d+)\s+pruned")

    # Generate all combinations
    k_range = range(MIN_K, MAX_K + 1)
    d_range = range(MIN_D, MAX_D + 1)
    total_combinations = len(k_range) * len(d_range)

    # Load progress
    done_combinations = load_existing_progress(output_csv)
    already_done_count = len(done_combinations)
    
    # CSV Header
    csv_header = ['k', 'd', 'gadgets_found', 'pruned_branches', 'time_sec']

    print(f"[*] Starting SMART Benchmark on: {target_binary}")
    print(f"[*] Total combinations: {total_combinations}")
    
    if already_done_count > 0:
        print(f"[*] Existing file detected: {already_done_count} tests completed. Resuming...")
    else:
        print(f"[*] No previous progress. Starting from scratch.")
    
    print(f"[*] Output file: {output_csv}")
    print("-" * 70)

    try:
        # Check if we need to write the header
        file_exists = os.path.exists(output_csv) and os.path.getsize(output_csv) > 0
        
        with open(output_csv, mode='a', newline='') as csv_file:
            writer = csv.writer(csv_file, delimiter=',')
            
            if not file_exists:
                writer.writerow(csv_header)

            start_session = time.time()
            session_count = 0 

            # Main Loop
            loop_idx = 0
            for k in k_range:
                for d in d_range:
                    loop_idx += 1
                    
                    # RESUME LOGIC
                    if (k, d) in done_combinations:
                        continue

                    session_count += 1
                    
                    # ETA Calculation
                    elapsed_session = time.time() - start_session
                    avg_time = elapsed_session / session_count if session_count > 0 else 0
                    remaining_ops = total_combinations - already_done_count - session_count
                    
                    eta_seconds = int(avg_time * remaining_ops)
                    eta_str = str(datetime.timedelta(seconds=eta_seconds))

                    print(f"[{loop_idx}/{total_combinations}] k={k:02d}, d={d:02d} [ETA: {eta_str}] ... ", end="", flush=True)

                    # Updated Command Line Arguments
                    cmd = ["lcsajdump", "-k", str(k), "-d", str(d), target_binary]

                    run_start = time.time()
                    try:
                        result = subprocess.run(cmd, capture_output=True, text=True)
                        run_end = time.time()
                        elapsed = run_end - run_start

                        # 1. Parsing Gadgets (Updated)
                        g_match = gadget_regex.search(result.stdout)
                        gadgets = g_match.group(1) if g_match else "0"

                        # 2. Parsing Pruned Branches (Updated)
                        p_match = pruned_regex.search(result.stdout)
                        pruned = p_match.group(1) if p_match else "0"

                        # Visual Feedback
                        if int(gadgets) > 0:
                            status = f"\033[92m{gadgets}\033[0m g" # Green
                        else:
                            status = "0 g"
                        
                        pruned_status = f"(pruned: {pruned})"

                        writer.writerow([k, d, gadgets, pruned, f"{elapsed:.4f}"])
                        csv_file.flush()
                        
                        print(f"-> {status} {pruned_status} in {elapsed:.2f}s")

                    except KeyboardInterrupt:
                        print("\n\n[!] Interrupted by user.")
                        raise KeyboardInterrupt
                    except Exception as e:
                        print(f"Error: {e}")
                        writer.writerow([k, d, "Error", "Error", "0"])

    except KeyboardInterrupt:
        print(f"\n[!] Benchmark paused. Data saved in {output_csv}.")
        print("[!] Rerun the script to resume.")
    
    if (already_done_count + session_count) == total_combinations:
        print(f"\n[+] BENCHMARK COMPLETED! Results in {output_csv}")

if __name__ == "__main__":
    # Check for command line argument
    if len(sys.argv) < 2:
        print("Usage: python3 benchmark.py <path_to_binary>")
        print("Example: python3 benchmark.py /usr/riscv64-linux-gnu/lib/libc.so.6")
        sys.exit(1)

    target_binary = sys.argv[1]
    
    # Generate CSV name from binary name (e.g., benchmark_libc.so.6.csv)
    binary_name = os.path.basename(target_binary)
    output_csv_name = f"benchmark_{binary_name}.csv"

    run_benchmark(target_binary, output_csv_name)
