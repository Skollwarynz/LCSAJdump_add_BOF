import collections

class RainbowFinder:
    def __init__(self, graph_manager):
        self.gm = graph_manager
        self.gadgets = []
        
        # --- PARAMETRI RAINBOW ---
        self.MAX_DEPTH = 8          # Lunghezza massima del gadget (blocchi)
        self.MAX_DARKNESS = 50      # Saturazione: quante volte posso passare per un nodo?

    def is_gadget_useful(self, path):
        """
        Analisi Semantica Semplificata:
        Il gadget fa qualcosa di utile per un attaccante?
        """
        full_insns = []
        for addr in path:
            if addr in self.gm.addr_to_node:
                node = self.gm.addr_to_node[addr]
                full_insns.extend(node['insns'])

        has_load = False
        has_stack_move = False
        touches_argument_regs = False 
        
        for insn in full_insns:
            mnem = insn.mnemonic.lower()
            ops = insn.op_str.lower()
            
            if mnem in ['ld', 'lw', 'c.ld', 'c.lw', 'c.ldsp'] and 'sp' in ops:
                has_load = True
            
            if 'sp' in ops and ('addi' in mnem or 'c.addi' in mnem):
                has_stack_move = True
                
            if any(reg in ops for reg in ['a0', 'a1', 'a2', 'a3']):
                touches_argument_regs = True

        return (has_load or has_stack_move) and touches_argument_regs

    def search(self):
        print(f"[*] Avvio Rainbow BFS dai {len(self.gm.get_gadget_tails())} sink...")
        tails = self.gm.get_gadget_tails()
        queue = collections.deque()
        
        for t in tails:
            path = [t['start']]
            visited = {t['start']}
            queue.append((path, visited))

        node_darkness = collections.defaultdict(int)
        processed_paths = 0

        while queue:
            curr_path, curr_visited = queue.popleft()
            processed_paths += 1
            head_addr = curr_path[0]
            
            if len(curr_path) > 1:
                self.gadgets.append(curr_path)

            if len(curr_path) >= self.MAX_DEPTH:
                continue

            parents = self.gm.reverse_graph.get(head_addr, [])
            for parent_addr in parents:
                if parent_addr in curr_visited:
                    continue

                if node_darkness[parent_addr] >= self.MAX_DARKNESS:
                    continue
                
                node_darkness[parent_addr] += 1
                new_path = [parent_addr] + curr_path
                new_visited = curr_visited.copy()
                new_visited.add(parent_addr)
                queue.append((new_path, new_visited))

        print(f"[*] Ricerca completata. Processati {processed_paths} percorsi.")
        print(f"[*] Trovati {len(self.gadgets)} gadget candidati.")
        return self.gadgets

    def print_gadgets(self, limit=5):
        print(f"\n[*] Filtraggio completato. Visualizzo i migliori {limit}...")
        
        useful_gadgets = [g for g in self.gadgets if self.is_gadget_useful(g)]
        useful_gadgets.sort(key=len)
        
        if not useful_gadgets:
            print("[!] Nessun gadget utile trovato con i criteri attuali.")
            return

        for i, path in enumerate(useful_gadgets[:limit]):
            print(f"\n{'='*60}")
            print(f"GADGET #{i+1} (Lunghezza: {len(path)} blocchi)")
            print(f"{'='*60}")
            
            for idx, block_addr in enumerate(path):
                node = self.gm.addr_to_node[block_addr]
                print(f"  [BLOCK {idx+1}] @ {hex(block_addr)}")
                
                for insn in node['insns']:
                    prefix = "    "
                    mnem = insn.mnemonic.lower()
                    if mnem in ['ret', 'c.jr', 'jr', 'jalr']:
                        prefix = "  🔴" 
                    elif 'sp' in insn.op_str and ('ld' in mnem or 'lw' in mnem):
                        prefix = "  🟢" 
                    print(f"{prefix} {hex(insn.address)}:  {insn.mnemonic:<10} {insn.op_str}")

                if idx < len(path) - 1:
                    next_addr = path[idx+1]
                    last_insn = node['insns'][-1]
                    expected_next = last_insn.address + last_insn.size
                    if next_addr == expected_next:
                        print("      |\n      | (Fallthrough)\n      v")
                    else:
                        print(f"      |\n      | (SALTO a {hex(next_addr)})\n      v")
                else:
                    print("      |\n      +--> [FINE GADGET / RET]")
