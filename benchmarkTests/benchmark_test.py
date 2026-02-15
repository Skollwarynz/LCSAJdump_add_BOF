import subprocess
import time
import re
import csv
import sys
import datetime
import os

# ================= CONFIGURAZIONE =================
MIN_K = 1
MAX_K = 20

MIN_D = 1
MAX_D = 50

TARGET_BINARY = "testCTFs/nightmare/vuln"
OUTPUT_CSV = "lcsajdump_rop_vuln_benchmark.csv"
# ==================================================

def load_existing_progress(filename):
    """
    Legge il CSV esistente e restituisce un set di tuple (k, d) già completate.
    """
    processed = set()
    if not os.path.exists(filename):
        return processed

    try:
        with open(filename, mode='r', newline='') as f:
            reader = csv.reader(f)
            header = next(reader, None) # Salta l'header
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
        print(f"[!] Errore lettura progresso precedente: {e}")
    
    return processed

def run_benchmark():
    # Regex per output
    gadget_regex = re.compile(r"\(Trovati (\d+) gadget\)")
    pruned_regex = re.compile(r"Pruning effettuato: (\d+) rami")

    # Genera tutte le combinazioni
    k_range = range(MIN_K, MAX_K + 1)
    d_range = range(MIN_D, MAX_D + 1)
    total_combinations = len(k_range) * len(d_range)

    # Carica progresso
    done_combinations = load_existing_progress(OUTPUT_CSV)
    already_done_count = len(done_combinations)
    
    # Header del CSV (se il file è nuovo)
    csv_header = ['k', 'd', 'gadgets_found', 'pruned_branches', 'time_sec']

    print(f"[*] Avvio SMART Benchmark su: {TARGET_BINARY}")
    print(f"[*] Totale combinazioni: {total_combinations}")
    
    if already_done_count > 0:
        print(f"[*] Rilevato file esistente: {already_done_count} test già completati. Riprendo...")
    else:
        print(f"[*] Nessun progresso precedente. Parto da zero.")
    
    print(f"[*] Output: {OUTPUT_CSV}")
    print("-" * 70)

    # Modalità 'a' (append) per non sovrascrivere
    try:
        # Controllo se scrivere l'header (solo se file vuoto o inesistente)
        file_exists = os.path.exists(OUTPUT_CSV) and os.path.getsize(OUTPUT_CSV) > 0
        
        with open(OUTPUT_CSV, mode='a', newline='') as csv_file:
            writer = csv.writer(csv_file, delimiter=',')
            
            if not file_exists:
                writer.writerow(csv_header)

            start_session = time.time()
            session_count = 0 # Conta solo quelli eseguiti in QUESTA sessione

            # Loop principale
            loop_idx = 0
            for k in k_range:
                for d in d_range:
                    loop_idx += 1
                    
                    # LOGICA RESUME: Se la coppia è già fatta, salta
                    if (k, d) in done_combinations:
                        continue

                    session_count += 1
                    
                    # Calcolo ETA basato solo sulla sessione corrente
                    elapsed_session = time.time() - start_session
                    avg_time = elapsed_session / session_count if session_count > 0 else 0
                    remaining_ops = total_combinations - already_done_count - session_count
                    
                    eta_seconds = int(avg_time * remaining_ops)
                    eta_str = str(datetime.timedelta(seconds=eta_seconds))

                    print(f"[{loop_idx}/{total_combinations}] k={k:02d}, d={d:02d} [ETA: {eta_str}] ... ", end="", flush=True)

                    cmd = ["lcsajdump", "-k", str(k), "-d", str(d), TARGET_BINARY]

                    run_start = time.time()
                    try:
                        result = subprocess.run(cmd, capture_output=True, text=True)
                        run_end = time.time()
                        elapsed = run_end - run_start

                        # 1. Parsing Gadgets
                        g_match = gadget_regex.search(result.stdout)
                        gadgets = g_match.group(1) if g_match else "0"

                        # 2. Parsing Pruned Branches
                        p_match = pruned_regex.search(result.stdout)
                        pruned = p_match.group(1) if p_match else "0"

                        # Feedback visuale
                        if int(gadgets) > 0:
                            status = f"\033[92m{gadgets}\033[0m g" # Verde
                        else:
                            status = "0 g"
                        
                        pruned_status = f"(pruned: {pruned})"

                        writer.writerow([k, d, gadgets, pruned, f"{elapsed:.4f}"])
                        
                        # Flush per salvare subito su disco
                        csv_file.flush()
                        
                        print(f"-> {status} {pruned_status} in {elapsed:.2f}s")

                    except KeyboardInterrupt:
                        print("\n\n[!] Interrotto dall'utente.")
                        raise KeyboardInterrupt
                    except Exception as e:
                        print(f"Error: {e}")
                        writer.writerow([k, d, "Error", "Error", "0"])

    except KeyboardInterrupt:
        print(f"\n[!] Benchmark messo in pausa. I dati sono salvi in {OUTPUT_CSV}.")
        print("[!] Rilancia lo script per riprendere da dove hai lasciato.")
    
    if (already_done_count + session_count) == total_combinations:
        print(f"\n[+] BENCHMARK COMPLETATO! Risultati in {OUTPUT_CSV}")

if __name__ == "__main__":
    run_benchmark()
