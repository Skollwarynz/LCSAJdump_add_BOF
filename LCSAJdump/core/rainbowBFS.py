import collections

class RainbowFinder:
    # Aggiungiamo i parametri al costruttore con dei default
    def __init__(self, graph_manager, max_depth, max_darkness):
        self.gm = graph_manager
        self.gadgets = []
        
        # Ora usiamo i valori passati da fuori
        self.MAX_DEPTH = max_depth
        self.MAX_DARKNESS = max_darkness

    def score_gadget(self, path):
        score = 100
        full_insns = []
        for addr in path: 
            if addr in self.gm.addr_to_node:
                full_insns.extend(self.gm.addr_to_node[addr]['insns'])
        
        score -= (len(path) * 10) + (len(full_insns) * 2)
        
        has_ra = any('ra' in i.op_str and 'ld' in i.mnemonic for i in full_insns)
        has_a0 = any('a0' in i.op_str and 'ld' in i.mnemonic for i in full_insns)
        
        if has_ra: score += 50
        if has_a0: score += 40
        
        # Penalità JOP (Salti a registro non-ra)
        if full_insns:
            last = full_insns[-1]
            if last.mnemonic in ['jr', 'jalr', 'c.jr', 'c.jalr'] and 'ra' not in last.op_str:
                 score -= 20

        return score

    def search(self):
        print(f"[*] Configurazione Rainbow: Depth={self.MAX_DEPTH}, Darkness={self.MAX_DARKNESS}")
        tails = self.gm.get_gadget_tails()
        queue = collections.deque([([t['start']], {t['start']}) for t in tails])
        node_darkness = collections.defaultdict(int)
        pruned = 0

        while queue:
            path, visited = queue.popleft()
            head = path[0]
            if len(path) > 1: self.gadgets.append(path)
            if len(path) >= self.MAX_DEPTH: continue

            for parent in self.gm.reverse_graph.get(head, []):
                if parent in visited: continue
                if node_darkness[parent] >= self.MAX_DARKNESS:
                    pruned += 1
                    continue
                node_darkness[parent] += 1
                queue.append(([parent] + path, visited | {parent}))
        
        print(f"[*] Pruning effettuato: {pruned} rami tagliati 🌈")
        return self.gadgets

    def print_gadgets(self, limit, min_score):
        # Aggiungiamo il filtro min_score qui
        scored = []
        for g in self.gadgets:
            s = self.score_gadget(g)
            if s >= min_score:
                scored.append((s, g))
        
        scored.sort(key=lambda x: x[0], reverse=True)
        
        print(f"\n--- Visualizzazione Top {limit} (Min Score: {min_score}) ---")
        for i, (s, p) in enumerate(scored[:limit]):
            print(f"\nRANK #{i+1} | SCORE: {s}")
            for addr in p:
                node = self.gm.addr_to_node[addr]
                for insn in node['insns']:
                     print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")