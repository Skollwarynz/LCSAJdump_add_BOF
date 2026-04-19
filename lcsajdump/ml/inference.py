import os
import sqlite3
import hashlib
import logging
from typing import List, Dict

from lcsajdump_dbg.ml.features import extract_features, FEATURE_NAMES
from lcsajdump_dbg.ml.semantic_features import extract_semantic_features

CACHE_DB_PATH = os.path.expanduser("~/.lcsajdump_cache.db")

class InferenceEngine:
    """
    Two-Stage Ranking Inference Engine for lcsajdump v15.
    
    Implements a fast static filter to select Top-K gadgets, 
    lazy semantic evaluation using angr, and SQLite-based caching.
    """
    def __init__(self, model_v15_path: str, arch: str, top_k: int = 300, cache_path: str = CACHE_DB_PATH):
        self.model_v15_path = model_v15_path
        self.arch = arch
        self.top_k = top_k
        self.cache_path = cache_path
        
        self.model = self._load_model()
        self._init_cache()

    def _load_model(self):
        import pickle
        try:
            with open(self.model_v15_path, 'rb') as f:
                data = pickle.load(f)
                # Handle both raw models and dictionaries
                if isinstance(data, dict) and 'model' in data:
                    return data['model']
                return data
        except Exception as e:
            logging.error(f"[InferenceEngine] Failed to load model {self.model_v15_path}: {e}")
            return None

    def _init_cache(self):
        """Initialize the SQLite cache database in a thread-safe/fault-tolerant way."""
        try:
            with sqlite3.connect(self.cache_path, timeout=10.0) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS semantic_cache (
                        binary_hash TEXT,
                        gadget_offset INTEGER,
                        sm_controls_arg_reg INTEGER,
                        sm_stack_pivot_size INTEGER,
                        sm_writes_memory INTEGER,
                        PRIMARY KEY (binary_hash, gadget_offset)
                    )
                ''')
                conn.commit()
        except Exception as e:
            logging.error(f"[InferenceEngine] Failed to initialize cache DB: {e}")

    def _get_binary_hash(self, binary_path: str) -> str:
        """Compute MD5 hash of the binary for cache keying."""
        hasher = hashlib.md5()
        try:
            with open(binary_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logging.error(f"[InferenceEngine] Failed to hash binary {binary_path}: {e}")
            return "unknown_hash"

    def _get_cached_semantics(self, binary_hash: str, offsets: List[int]) -> Dict[int, dict]:
        """Fetch cached semantic features for multiple offsets."""
        results = {}
        if not offsets:
            return results
            
        try:
            with sqlite3.connect(self.cache_path, timeout=10.0) as conn:
                cursor = conn.cursor()
                # SQLite limits variables in IN clause (usually 999), chunking if necessary
                chunk_size = 900
                for i in range(0, len(offsets), chunk_size):
                    chunk = offsets[i:i + chunk_size]
                    placeholders = ','.join('?' * len(chunk))
                    query = f'''
                        SELECT gadget_offset, sm_controls_arg_reg, sm_stack_pivot_size, sm_writes_memory
                        FROM semantic_cache
                        WHERE binary_hash = ? AND gadget_offset IN ({placeholders})
                    '''
                    cursor.execute(query, [binary_hash] + chunk)
                    for row in cursor.fetchall():
                        offset, controls, pivot, writes = row
                        results[offset] = {
                            'sm_controls_arg_reg': controls,
                            'sm_stack_pivot_size': pivot,
                            'sm_writes_memory': writes
                        }
        except Exception as e:
            logging.error(f"[InferenceEngine] Cache read error: {e}")
            
        return results

    def _save_cached_semantics(self, binary_hash: str, semantics: Dict[int, dict]):
        """Save computed semantic features to cache robustly."""
        if not semantics:
            return
            
        try:
            with sqlite3.connect(self.cache_path, timeout=10.0) as conn:
                cursor = conn.cursor()
                records = [
                    (
                        binary_hash, 
                        offset, 
                        feat.get('sm_controls_arg_reg', 0),
                        feat.get('sm_stack_pivot_size', 0),
                        feat.get('sm_writes_memory', 0)
                    )
                    for offset, feat in semantics.items()
                ]
                cursor.executemany('''
                    INSERT OR REPLACE INTO semantic_cache 
                    (binary_hash, gadget_offset, sm_controls_arg_reg, sm_stack_pivot_size, sm_writes_memory)
                    VALUES (?, ?, ?, ?, ?)
                ''', records)
                conn.commit()
        except Exception as e:
            logging.error(f"[InferenceEngine] Cache write error: {e}")

    def run_inference(self, binary_path: str, gadgets: List[dict], gadget_pool: set, majority_term_is_ret: int = 1) -> List[dict]:
        """
        Orchestrates the Two-Stage Ranking pipeline.
        
        gadgets: list of dicts, each containing:
            - 'address': int
            - 'instructions': list of dicts {'mnemonic': ..., 'op_str': ...}
            - 'score': int (the static heuristic score)
            - 'size_bytes': int
            - 'type': str ('Sequential', 'Jump-Based')
        """
        if not self.model:
            logging.warning("[InferenceEngine] No ML model loaded. Returning heuristic ranking.")
            return sorted(gadgets, key=lambda x: x.get('score', 0), reverse=True)

        # ---------------------------------------------------------
        # FASE 1: Fast Static Filter (Scrematura)
        # ---------------------------------------------------------
        sorted_gadgets = sorted(gadgets, key=lambda x: x.get('score', 0), reverse=True)
        top_candidates = sorted_gadgets[:self.top_k]
        
        logging.info(f"[InferenceEngine] Stage 1: Filtered {len(gadgets)} down to Top-{len(top_candidates)} using static heuristic.")

        # ---------------------------------------------------------
        # FASE 2 & 3: Lazy Semantic Evaluation & Local Caching
        # ---------------------------------------------------------
        binary_hash = self._get_binary_hash(binary_path)
        candidate_offsets = [g['address'] for g in top_candidates]
        
        cached_semantics = self._get_cached_semantics(binary_hash, candidate_offsets)
        
        semantics_to_compute = []
        for g in top_candidates:
            if g['address'] not in cached_semantics:
                semantics_to_compute.append(g)
                
        logging.info(f"[InferenceEngine] Stage 2 & 3: Cache hits: {len(cached_semantics)}. Computing semantics for {len(semantics_to_compute)} gadgets via angr...")
        
        new_semantics = {}
        for g in semantics_to_compute:
            try:
                sm_feats = extract_semantic_features(
                    binary_path=binary_path,
                    gadget_addr=g['address'],
                    gadget_size=g.get('size_bytes', 0),
                    arch=self.arch
                )
                new_semantics[g['address']] = sm_feats
                cached_semantics[g['address']] = sm_feats
            except Exception as e:
                logging.warning(f"[InferenceEngine] Semantic extraction failed for {hex(g['address'])}: {e}")
                zero_feats = {
                    'sm_controls_arg_reg': 0,
                    'sm_stack_pivot_size': 0,
                    'sm_writes_memory': 0
                }
                new_semantics[g['address']] = zero_feats
                cached_semantics[g['address']] = zero_feats
                
        if new_semantics:
            self._save_cached_semantics(binary_hash, new_semantics)
            logging.info(f"[InferenceEngine] Saved {len(new_semantics)} semantic evaluations to cache.")

        # ---------------------------------------------------------
        # FASE 4: Final Rank (v15)
        # ---------------------------------------------------------
        logging.info(f"[InferenceEngine] Stage 4: Extracting full 29-dim feature vectors and running ML prediction...")
        
        import pandas as pd
        
        X_rows = []
        for g in top_candidates:
            addr = g['address']
            sm_feats = cached_semantics.get(addr, {})
            
            # Extract 26 static features (binary_path=None skips internal semantic extraction)
            feats = extract_features(
                instructions=g.get('instructions', []),
                arch=self.arch,
                gadget_type=g.get('type', 'Sequential'),
                heuristic_score=g.get('score', 0),
                address=addr,
                gadget_pool=gadget_pool,
                majority_term_is_ret=majority_term_is_ret,
                binary_path=None, 
                gadget_size=0
            )
            
            # Inject the 3 lazy-evaluated semantic features
            feats['sm_controls_arg_reg'] = sm_feats.get('sm_controls_arg_reg', 0)
            feats['sm_stack_pivot_size'] = sm_feats.get('sm_stack_pivot_size', 0)
            feats['sm_writes_memory'] = sm_feats.get('sm_writes_memory', 0)
            
            row = [feats.get(f, 0) for f in FEATURE_NAMES]
            X_rows.append(row)
            
        if X_rows:
            X_df = pd.DataFrame(X_rows, columns=FEATURE_NAMES)
            
            # The currently loaded model (gadget_model_last-model.pkl) was trained on 26 features. 
            # We should pass only the features the model expects. We can inspect self.model.feature_name_
            if hasattr(self.model, 'feature_name_'):
                expected_features = self.model.feature_name_
                # Align dataframe to expected features, filling missing ones with 0 just in case
                for f in expected_features:
                    if f not in X_df.columns:
                        X_df[f] = 0
                X_df = X_df[expected_features]
            
            predictions = self.model.predict(X_df)
            
            # Map predictions to [50, 400] scale to match heuristic range
            import math
            for i, g in enumerate(top_candidates):
                raw = float(predictions[i])
                clamped = max(-700.0, min(700.0, raw / 3.0))
                sig = 1.0 / (1.0 + math.exp(-clamped))
                g['ml_score'] = int(sig * 200.0 * 2)
                g['ml_raw'] = raw
                
        # Sort Top-K by final ML score
        final_ranking = sorted(top_candidates, key=lambda x: x.get('ml_raw', -9999.0), reverse=True)
        
        # Append the un-evaluated gadgets at the bottom using their static heuristic score
        # but artificially lowered to ensure they stay below the ML-ranked Top-K
        unranked = [g for g in sorted_gadgets if g['address'] not in [t['address'] for t in top_candidates]]
        for g in unranked:
            g['ml_score'] = min(g.get('score', 0), 49) # Keep them below 50
            g['ml_raw'] = -10000.0
            
        return final_ranking + unranked
