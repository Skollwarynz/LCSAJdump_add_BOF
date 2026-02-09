import collections

class RainbowFinder:
    def __init__(self, graph_manager):
        self.gm = graph_manager
        self.gadgets = []
        self.MAX_DEPTH = 12
        self.MAX_DARKNESS = 30

    def score_gadget(self, path):
        score = 100
        full_insns = []
        for addr in path: full_insns.extend(self.gm.addr_to_node[addr]['insns'])
        
        score -= (len(path) * 10) + (len(full_insns) * 2)
        
        has_ra = any('ra' in i.op_str and 'ld' in i.mnemonic for i in full_insns)
        has_a0 = any('a0' in i.op_str and 'ld' in i.mnemonic for i in full_insns)
        
        if has_ra: score += 50
        if has_a0: score += 40
        return score

    def search(self):
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

    def print_gadgets(self, limit=10):
        scored = sorted([(self.score_gadget(g), g) for g in self.gadgets], key=lambda x: x[0], reverse=True)
        for i, (s, p) in enumerate(scored[:limit]):
            print(f"\nRANK #{i+1} | SCORE: {s}")
            for addr in p:
                for insn in self.gm.addr_to_node[addr]['insns']:
                    print(f"  {hex(insn.address)}: {insn.mnemonic} {insn.op_str}")
