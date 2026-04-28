import pandas as pd
import numpy as np
import pickle
from sklearn.metrics import ndcg_score as _ndcg
from lcsajdump.ml.features import FEATURE_NAMES

def safe_ndcg(tc, sc, kk):
    try:
        if len(tc) < 2:
            return 1.0 if (tc[0] == 1) else 0.0
        return _ndcg([tc], [sc], k=kk)
    except Exception:
        n_pos = int(tc.sum())
        if n_pos > 0:
            top_k_idx = np.argsort(sc)[-kk:][::-1]
            n_pos_in_top_k = int(tc[top_k_idx].sum())
            return n_pos_in_top_k / min(n_pos, kk)
        return 0.0

def main():
    df = pd.read_csv("gadget_dataset.csv")
    for col in FEATURE_NAMES:
        if col not in df.columns: df[col] = 0

    with open("chainfinder_v5_hybrid.pkl", "rb") as f:
        data = pickle.load(f)
        model = data['model'] if isinstance(data, dict) and 'model' in data else data

    X = df[FEATURE_NAMES].values
    ml_scores = model.predict(X)
    heur_scores = df["heuristic_score"].values
    labels = df["label"].values

    results_heur = {1: [], 3: [], 5: [], 10: []}
    results_ml = {1: [], 3: [], 5: [], 10: []}

    for bid in df["binary_id"].unique():
        mask = df["binary_id"] == bid
        tc = labels[mask]
        sc_h = heur_scores[mask]
        sc_m = ml_scores[mask]
        
        if tc.sum() == 0: continue
        
        for k in [1, 3, 5, 10]:
            results_heur[k].append(safe_ndcg(tc, sc_h, k))
            results_ml[k].append(safe_ndcg(tc, sc_m, k))

    print(f"===========================================================")
    print(f" CONFRONTO PRESTAZIONI: EURISTICA TRADIZIONALE vs ML IBRIDO")
    print(f"===========================================================")
    print(f"Totale binari valutati (gruppi CTF): {len(results_heur[5])}\n")
    
    print(f"[1] Euristica Tradizionale (Solo regole sintattiche)")
    print(f"    NDCG@1:  {np.mean(results_heur[1]):.4f}")
    print(f"    NDCG@3:  {np.mean(results_heur[3]):.4f}")
    print(f"    NDCG@5:  {np.mean(results_heur[5]):.4f}")
    print(f"    NDCG@10: {np.mean(results_heur[10]):.4f}\n")

    print(f"[2] Modello ML (LightGBM + Angr Semantic Features)")
    print(f"    NDCG@1:  {np.mean(results_ml[1]):.4f}")
    print(f"    NDCG@3:  {np.mean(results_ml[3]):.4f}")
    print(f"    NDCG@5:  {np.mean(results_ml[5]):.4f}")
    print(f"    NDCG@10: {np.mean(results_ml[10]):.4f}")
    print(f"===========================================================")

if __name__ == "__main__":
    main()
