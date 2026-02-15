import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import sys
import os

# Nome del file CSV generato dal benchmark
CSV_FILE = "lcsajdump_online_vuln_benchmark.csv"

def analyze_data():
    if not os.path.exists(CSV_FILE):
        print(f"[!] Errore: File {CSV_FILE} non trovato.")
        return

    print(f"[*] Caricamento dati da {CSV_FILE}...")
    df = pd.read_csv(CSV_FILE)

    # Assicuriamoci che i dati siano numerici
    df['gadgets_found'] = pd.to_numeric(df['gadgets_found'], errors='coerce').fillna(0)
    df['pruned_branches'] = pd.to_numeric(df['pruned_branches'], errors='coerce').fillna(0)
    df['time_sec'] = pd.to_numeric(df['time_sec'], errors='coerce').fillna(0)

    # Setup stile grafici
    plt.style.use('ggplot')
    
    # =================================================================
    # GRAFICO A: Curva di Saturazione (Gadgets vs Depth)
    # =================================================================
    print("[*] Generazione Grafico A: Saturazione Gadget...")
    plt.figure(figsize=(10, 6))
    
    # Selezioniamo alcuni K significativi per non affollare il grafico
    # Es: k=1, k=2, k=4, e il massimo k disponibile
    k_values_to_plot = [1, 2, 3, 4, 10, df['k'].max()]
    k_values_to_plot = sorted(list(set([k for k in k_values_to_plot if k in df['k'].unique()])))

    for k in k_values_to_plot:
        subset = df[df['k'] == k].sort_values(by='d')
        plt.plot(subset['d'], subset['gadgets_found'], marker='.', label=f'k={k}')

    plt.title('Grafico A: Saturazione dei Gadget (Gadgets vs Depth)')
    plt.xlabel('Depth (d)')
    plt.ylabel('Gadgets Found')
    plt.legend(title="Darkness (k)")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig('grafico_A_saturazione_libc.png', dpi=300)
    print("    -> Salvato 'grafico_A_saturazione_libc.png'")

    # =================================================================
    # GRAFICO B: Efficacia del Pruning (Pruned vs Darkness)
    # =================================================================
    print("[*] Generazione Grafico B: Efficacia Pruning...")
    plt.figure(figsize=(10, 6))

    # Per ogni k, prendiamo la somma totale dei rami tagliati (o la media)
    pruning_by_k = df.groupby('k')['pruned_branches'].max() # Usiamo il max per vedere il caso peggiore

    plt.plot(pruning_by_k.index, pruning_by_k.values, marker='o', color='red', linestyle='-')
    
    plt.title('Grafico B: Efficacia del Pruning (Pruned Branches vs Darkness)')
    plt.xlabel('Darkness (k)')
    plt.ylabel('Max Pruned Branches')
    plt.yscale('log') # Scala logaritmica come suggerito
    plt.grid(True, which="both", ls="-", alpha=0.5)
    plt.tight_layout()
    plt.savefig('grafico_B_pruning_libc.png', dpi=300)
    print("    -> Salvato 'grafico_B_pruning_libc.png'")

    # =================================================================
    # GRAFICO C: Costo della Ricerca (Time vs Depth)
    # =================================================================
    print("[*] Generazione Grafico C: Costo Temporale...")
    plt.figure(figsize=(10, 6))

    # Calcoliamo il tempo medio per ogni Depth (mediando su tutti i k)
    time_by_d = df.groupby('d')['time_sec'].mean()
    
    plt.plot(time_by_d.index, time_by_d.values, color='green', linewidth=2)
    plt.fill_between(time_by_d.index, time_by_d.values, color='green', alpha=0.1)

    plt.title('Grafico C: Costo Computazionale (Time vs Depth)')
    plt.xlabel('Depth (d)')
    plt.ylabel('Average Time (seconds)')
    plt.grid(True)
    plt.tight_layout()
    plt.savefig('grafico_C_time_libc.png', dpi=300)
    print("    -> Salvato 'grafico_C_time_libc.png'")

    # =================================================================
    # CALCOLO AUTOMATICO DEI DEFAULT ("THE SWEET SPOT")
    # =================================================================
    print("\n" + "="*50)
    print("ANALISI AUTOMATICA DEI DEFAULT")
    print("="*50)

    # 1. Calcolo d_opt (Depth)
    # Troviamo il d dove il numero di gadget raggiunge il 99.9% del massimo
    max_gadgets = df['gadgets_found'].max()
    threshold = max_gadgets * 0.999
    
    # Prendiamo il subset con k massimo per essere sicuri di avere tutti i gadget
    max_k = df['k'].max()
    subset_max_k = df[df['k'] == max_k].sort_values(by='d')
    
    # Troviamo il primo d che supera la soglia
    saturation_row = subset_max_k[subset_max_k['gadgets_found'] >= threshold].head(1)
    
    if not saturation_row.empty:
        d_saturation = int(saturation_row['d'].values[0])
        d_opt = int(d_saturation * 1.2) # +20% buffer
        print(f"[RESULT] Saturazione Gadget ({max_gadgets}) raggiunta a d={d_saturation}")
        print(f"[DECISION] Depth Ideale (d_opt) = {d_saturation} + 20% buffer => {d_opt}")
    else:
        print("[!] Impossibile determinare saturazione (dati insufficienti?)")
        d_opt = 32 # Fallback

    # 2. Calcolo k_opt (Darkness)
    # Troviamo il primo k dove pruned_branches scende a 0 (o molto vicino a 0)
    # Usiamo il max pruning per ogni k
    zero_pruning_k = pruning_by_k[pruning_by_k == 0].head(1)
    
    if not zero_pruning_k.empty:
        k_zero = int(zero_pruning_k.index[0])
        k_opt = k_zero * 5 # Fattore di sicurezza 5x
        print(f"\n[RESULT] Pruning scende a Zero a k={k_zero}")
        print(f"[DECISION] Darkness Ideale (k_opt) = {k_zero} * 5 (safety factor) => {k_opt}")
    else:
        # Se non va mai a zero nei dati raccolti, prendiamo l'ultimo
        print("\n[!] Il pruning non è mai sceso a zero nei dati raccolti.")
        k_opt = 20 # Fallback

    print("-" * 50)
    print(f"VALORI DI DEFAULT SUGGERITI PER LA TESI:")
    print(f"DEPTH    (d) = {d_opt}")
    print(f"DARKNESS (k) = {k_opt}")
    print("="*50)

if __name__ == "__main__":
    try:
        import matplotlib
    except ImportError:
        print("Devi installare le librerie: pip install pandas matplotlib")
        sys.exit(1)
        
    analyze_data()
