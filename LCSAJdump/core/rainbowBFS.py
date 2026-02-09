import collections

class RainbowFinder:
    def __init__(self, graph_manager):
        self.gm = graph_manager
        self.gadgets = []
        self.MAX_DEPTH = 8
        self.MAX_DARKNESS = 50

    def score_gadget(self, path):
        """
        Assegna un punteggio di qualità al gadget.
        Più alto è il punteggio, più il gadget è utile e pulito.
        """
        score = 100
        full_insns = []
        for addr in path:
            node = self.gm.addr_to_node[addr]
            full_insns.extend(node['insns'])

        # --- 1. PENALITÀ LUNGHEZZA ---
        score -= (len(path) * 10)       # Penalità blocchi
        score -= (len(full_insns) * 2)  # Penalità numero istruzioni

        # --- 2. ANALISI SEMANTICA ---
        has_ra_control = False
        has_arg_control = False
        danger_zone = False

        for insn in full_insns:
            mnem = insn.mnemonic.lower()
            ops = insn.op_str.lower()

            # Bonus: Controllo del Return Address (Chaining)
            if mnem in ['ld', 'c.ldsp'] and 'ra' in ops and 'sp' in ops:
                has_ra_control = True
            
            # Bonus: Controllo argomenti (a0-a3)
            if mnem in ['ld', 'lw', 'c.ldsp', 'c.lwsp'] and any(reg in ops for reg in ['a0', 'a1', 'a2']):
                if 'sp' in ops: has_arg_control = True

            # Malus: Uso di registri pericolosi o instabili
            if any(reg in ops for reg in ['tp', 'gp', 'zero']):
                danger_zone = True

        if has_ra_control: score += 50
        if has_arg_control: score += 40
        if danger_zone: score -= 30

        # Malus: JOP (salto a registro) è meno immediato di ROP (ret)
        last_mnem = full_insns[-1].mnemonic.lower()
        if 'jr' in last_mnem or 'jalr' in last_mnem:
            if 'ra' not in full_insns[-1].op_str:
                score -= 20

        return score

    def is_gadget_useful(self, path):
        # Usiamo lo score come filtro: un gadget con score basso è "rumore"
        return self.score_gadget(path) > 40

    def search(self):
        print(f"[*] Avvio Rainbow BFS dai {len(self.gm.get_gadget_tails())} sink...")
        tails = self.gm.get_gadget_tails()
        queue = collections.deque()
        for t in tails:
            queue.append(([t['start']], {t['start']}))

        node_darkness = collections.defaultdict(int)
        processed_paths = 0

        while queue:
            curr_path, curr_visited = queue.popleft()
            processed_paths += 1
            head_addr = curr_path[0]
            
            if len(curr_path) > 1:
                self.gadgets.append(curr_path)

            if len(curr_path) >= self.MAX_DEPTH: continue

            parents = self.gm.reverse_graph.get(head_addr, [])
            for parent_addr in parents:
                if parent_addr in curr_visited: continue
                if node_darkness[parent_addr] >= self.MAX_DARKNESS: continue
                
                node_darkness[parent_addr] += 1
                new_path = [parent_addr] + curr_path
                queue.append((new_path, curr_visited | {parent_addr}))

        print(f"[*] Ricerca completata. Trovati {len(self.gadgets)} gadget.")
        return self.gadgets

    def print_gadgets(self, limit=10):
        print(f"\n[*] Calcolo Ranking e filtraggio...")
        
        # Creiamo una lista di tuple (score, gadget)
        scored_list = []
        for g in self.gadgets:
            s = self.score_gadget(g)
            if s > 50: # Mostriamo solo la "Serie A"
                scored_list.append((s, g))
        
        # Ordiniamo per score decrescente
        scored_list.sort(key=lambda x: x[0], reverse=True)
        
        print(f"--- Top {limit} Gadgets by Quality Score ---")
        
        for i, (score, path) in enumerate(scored_list[:limit]):
            print(f"\nRANK #{i+1} | SCORE: {score} | BLOCKS: {len(path)}")
            print("-" * 40)
            
            for idx, block_addr in enumerate(path):
                node = self.gm.addr_to_node[block_addr]
                for insn in node['insns']:
                    indicator = "    "
                    if 'ra' in insn.op_str and 'ld' in insn.mnemonic: indicator = "  🔗"
                    if 'a0' in insn.op_str: indicator = "  🎯"
                    if insn.mnemonic in ['ret', 'c.jr']: indicator = "  🔴"
                    
                    print(f"{indicator} {hex(insn.address)}: {insn.mnemonic:<10} {insn.op_str}")
                
                if idx < len(path) - 1:
                    print("      |")
