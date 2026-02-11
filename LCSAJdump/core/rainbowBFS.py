import collections

class RainbowFinder:
    jump_mnemonics = ['j', 'c.j', 'jal', 'c.jal']

    def __init__(self, graph_manager, max_depth, max_darkness):
        self.gm = graph_manager
        self.gadgets = []
        
        self.MAX_DEPTH = max_depth
        self.MAX_DARKNESS = max_darkness

    def score_gadget(self, path):
        score = 100
        full_insns = []
        for addr in path: 
            if addr in self.gm.addr_to_node:
                full_insns.extend(self.gm.addr_to_node[addr]['insns'])
        
        # v4 fix: togliere anche (len(path) * 10) era troppo penalizzante per gadget LCSAJ
        score -= (len(full_insns) * 2)
        
        has_ra = any('ra' in i.op_str and 'ld' in i.mnemonic for i in full_insns)
        has_a0 = any('a0' in i.op_str and 'ld' in i.mnemonic for i in full_insns)
        # v4 fix: premiare i salti trampolino
        has_J = any(i.mnemonic in self.jump_mnemonics for i in full_insns)

        if has_ra: score += 50
        if has_a0: score += 40
        if has_J: score += 30

        # Penalità JOP (Salti a registro non-ra)
        if full_insns:
            last = full_insns[-1]
            if last.mnemonic in ['jr', 'jalr', 'c.jr', 'c.jalr'] and 'ra' not in last.op_str:
                 score -= 20

        return score

    def search(self):
        print(f"\n[*] Configurazione Rainbow: Depth={self.MAX_DEPTH}, Darkness={self.MAX_DARKNESS}")
        tails = self.gm.get_gadget_tails()
        queue = collections.deque([([t['start']], {t['start']}) for t in tails])
        node_darkness = collections.defaultdict(int)
        pruned = 0

        while queue:
            path, visited = queue.popleft()
            head = path[0]
            # V4 fix: '>' was blocking sequential gadgets
            if len(path) >= 1: self.gadgets.append(path)
            if len(path) >= self.MAX_DEPTH: continue

            for parent in self.gm.reverse_graph.get(head, []):
                if parent in visited: continue
                if node_darkness[parent] >= self.MAX_DARKNESS:
                    pruned += 1
                    continue
                node_darkness[parent] += 1
                queue.append(([parent] + path, visited | {parent}))
        
        print(f"[*] Pruning effettuato: {pruned} rami tagliati.")
        return self.gadgets

    def _classify_gadget(self, path):
        """Ritorna una etichetta e una categoria per il gadget"""
        if len(path) == 1:
            return "LINEAR", "Sequential"
        
        # Analizziamo il tipo di salto
        first_node = self.gm.addr_to_node[path[0]]
        last_insn = first_node['last_insn']
        mnem = last_insn.mnemonic.lower()
        
        if mnem in ['j', 'c.j', 'jal', 'c.jal']:
            return "TRAMPOLINE", "Jump-Based" # Salta sopra ostacoli
        elif mnem.startswith('b') or mnem.startswith('c.b'):
            return "CONDITIONAL", "Jump-Based" # Logica if/else
        else:
            return "FALLTHROUGH", "Jump-Based" # Discontinuità di memoria

    def print_gadgets(self, limit, min_score, verbose=False):
        categories = {'Sequential': [], 'Jump-Based': []}

        for g in self.gadgets:
            s = self.score_gadget(g)
            if s < min_score: continue
            
            tag, cat = self._classify_gadget(g)
            categories[cat].append((s, g, tag)) 

        for cat_name in ['Sequential', 'Jump-Based']:
            gadgets = categories[cat_name]
            gadgets.sort(key=lambda x: x[0], reverse=True)
            
            print(f"\033[33m\n{'='*60}\033[0m")
            print(f"\033[33m--- TOP {limit} {cat_name.upper()} GADGETS ---\033[0m")
            print(f"\033[33m{'='*60}\033[0m")
            
            for i, (s, p, tag) in enumerate(gadgets[:limit]):
                if verbose:
                    print(f"\nRANK #{i+1} | SCORE: {s} | TYPE: {tag}")
                    for addr in p:
                        node = self.gm.addr_to_node[addr]
                        for insn in node['insns']:
                             print(f"  \033[33m{hex(insn.address)}\033[0m: {insn.mnemonic} {insn.op_str}")
                else:
                    full_gadget_str = []
                    for addr in p:
                        node = self.gm.addr_to_node[addr]
                        for insn in node['insns']:
                            full_gadget_str.append(f"{insn.mnemonic} {insn.op_str}")
                    
                    start_addr = hex(p[0])
                    print(f"\033[33m{start_addr}\033[0m: {'; '.join(full_gadget_str)}")