import collections

class RainbowFinder:
    def __init__(self, graph_manager, max_depth, max_darkness):
        self.gm = graph_manager
        self.gadgets = []
        self.MAX_DEPTH = max_depth
        self.MAX_DARKNESS = max_darkness
        self.profile = self.gm.profile 

    def score_gadget(self, path):
        score = 100
        full_insns = []
        for addr in path: 
            if addr in self.gm.addr_to_node:
                full_insns.extend(self.gm.addr_to_node[addr]['insns'])
        
        score -= (len(full_insns) * 2)
        
        l_reg = self.profile.get("link_reg")
        a_reg = self.profile.get("primary_arg_reg")
        t_mnems = self.profile.get("trampoline_mnems", set())
        r_mnems = self.profile.get("ret_mnems", set())

        def reg_in_op(reg_config, op_str):
            if not reg_config:
                return False
            if isinstance(reg_config, str):
                return reg_config in op_str
            return any(r in op_str for r in reg_config)

        has_link_reg = any(reg_in_op(l_reg, i.op_str) for i in full_insns)
        has_arg_reg = any(reg_in_op(a_reg, i.op_str) for i in full_insns)
        has_J = any(i.mnemonic.lower() in t_mnems for i in full_insns)

        if has_link_reg: score += 50
        if has_arg_reg: score += 40
        if has_J: score += 30

        if full_insns:
            last = full_insns[-1]
            if last.mnemonic.lower() in r_mnems and not reg_in_op(l_reg, last.op_str):
                 score -= 20

        return score

    def search(self):
        print(f"\n[*] RainbowBFS config: Depth={self.MAX_DEPTH}, Darkness={self.MAX_DARKNESS}")
        tails = self.gm.get_gadget_tails()
        
        queue = collections.deque([[t['start']] for t in tails])
        node_darkness = collections.defaultdict(int)
        pruned = 0

        while queue:
            path = queue.popleft()
            head = path[0]
            
            if len(path) >= 1: 
                self.gadgets.append(path)
            
            if len(path) >= self.MAX_DEPTH: 
                continue

            for parent in self.gm.reverse_graph.get(head, []):
                if parent in path: 
                    continue
                
                if node_darkness[parent] >= self.MAX_DARKNESS:
                    pruned += 1
                    continue
                
                node_darkness[parent] += 1
                queue.append([parent] + path)
        
        print(f"[*] Pruning: {pruned} pruned branches.")
        return self.gadgets

    def _classify_gadget(self, path):
        if len(path) == 1:
            return "LINEAR", "Sequential"
        
        first_node = self.gm.addr_to_node[path[0]]
        last_insn = first_node['last_insn']
        mnem = last_insn.mnemonic.lower()
        
        # Usa il profilo per decidere il tipo
        if mnem in self.profile["unconditional_jumps"] and mnem not in self.profile["ret_mnems"]:
            return "TRAMPOLINE", "Jump-Based"
        elif mnem.startswith(self.profile["branch_prefixes"]):
            return "CONDITIONAL", "Jump-Based"
        else:
            return "FALLTHROUGH", "Jump-Based"

    def print_gadgets(self, limit, min_score, verbose):
        if verbose:
            print(f"\n[*] Verbose Mode: Showing all {len(self.gadgets)} gadgets individually...")
            categories = {'Sequential': [], 'Jump-Based': []}

            for g in self.gadgets:
                s = self.score_gadget(g)
                if s < min_score: continue
                
                tag, cat = self._classify_gadget(g)
                if cat not in categories: cat = 'Sequential'
                categories[cat].append((s, g, tag)) 

            for cat_name in ['Sequential', 'Jump-Based']:
                gadgets = categories[cat_name]
                gadgets.sort(key=lambda x: x[0], reverse=True)
                
                print(f"\033[33m\n{'='*60}\033[0m")
                print(f"\033[33m--- TOP {limit} {cat_name.upper()} GADGETS (RAW VIEW) ---\033[0m")
                print(f"\033[33m{'='*60}\033[0m")
                
                for i, (s, p, tag) in enumerate(gadgets[:limit]):
                    print(f"\nRANK #{i+1} | SCORE: {s} | TYPE: {tag}")
                    for addr in p:
                        if addr in self.gm.addr_to_node:
                            node = self.gm.addr_to_node[addr]
                            for insn in node['insns']:
                                    print(f"  \033[33m{hex(insn.address)}\033[0m: {insn.mnemonic} {insn.op_str}")

        else:
            unique_gadgets = {'Sequential': {}, 'Jump-Based': {}}
            
            for g in self.gadgets:
                s = self.score_gadget(g)
                if s < min_score: continue
                
                tag, cat = self._classify_gadget(g)
                if cat not in unique_gadgets: cat = 'Sequential'
                
                full_gadget_insns = []
                for addr in g:
                    if addr in self.gm.addr_to_node:
                        node = self.gm.addr_to_node[addr]
                        for insn in node['insns']:
                            full_gadget_insns.append(f"{insn.mnemonic} {insn.op_str}")
                
                signature = "; ".join(full_gadget_insns)
                
                if signature not in unique_gadgets[cat]:
                    unique_gadgets[cat][signature] = {
                        'score': s,
                        'type': tag,
                        'addresses': [] 
                    }
                
                unique_gadgets[cat][signature]['addresses'].append(g[0])

            for cat_name in ['Sequential', 'Jump-Based']:
                sorted_gadgets = sorted(
                    unique_gadgets[cat_name].items(), 
                    key=lambda x: x[1]['score'], 
                    reverse=True
                )
                
                print(f"\033[33m\n{'='*80}\033[0m")
                print(f"\033[33m--- TOP {limit} UNIQUE {cat_name.upper()} GADGETS ---\033[0m")
                print(f"\033[33m{'='*80}\033[0m")
                
                for i, (sig, data) in enumerate(sorted_gadgets[:limit]):
                    addrs = data['addresses']
                    count = len(addrs)
                    
                    primary_addr = hex(addrs[0])
                    
                    print(f"\033[33m{primary_addr}\033[0m: {sig}")
                    
                    if count > 1:
                        others = ", ".join([hex(a) for a in addrs[1:]])
                        print(f"  \033[90mFound {count} times (at {others})\033[0m")