import collections
import sys
import regex as re

def reg_in_op(reg_config, op_str):
    if not reg_config:
        return False
    if isinstance(reg_config, str):
        return reg_config in op_str
    return any(r in op_str for r in reg_config)

class RainbowFinder:
    BASE_SCORE = 100
    INSN_PENALTY_MULTIPLIER = 2
    BONUS_LINK_REG = 50
    BONUS_ARG_REG = 40
    BONUS_TRAMPOLINE = 30
    PENALTY_BAD_RET = 20

    def __init__(self, graph_manager, max_depth, max_darkness):
        self.gm = graph_manager
        self.gadgets = []
        self.MAX_DEPTH = max_depth
        self.MAX_DARKNESS = max_darkness
        self.profile = self.gm.profile 

    def score_gadget(self, path):
        score = self.BASE_SCORE
        full_insns = []
        for addr in path: 
            if addr in self.gm.addr_to_node:
                full_insns.extend(self.gm.addr_to_node[addr]['insns'])
        
        score -= (len(full_insns) * self.INSN_PENALTY_MULTIPLIER)
        
        l_reg = self.profile.get("link_reg")
        a_reg = self.profile.get("primary_arg_reg")
        t_mnems = self.profile.get("trampoline_mnems", set())
        r_mnems = self.profile.get("ret_mnems", set())

        has_link_reg = any(reg_in_op(l_reg, i.op_str) for i in full_insns)
        has_arg_reg = any(reg_in_op(a_reg, i.op_str) for i in full_insns)
        has_J = any(i.mnemonic.lower() in t_mnems for i in full_insns)

        if has_link_reg: score += self.BONUS_LINK_REG
        if has_arg_reg: score += self.BONUS_ARG_REG
        if has_J: score += self.BONUS_TRAMPOLINE

        if full_insns:
            last = full_insns[-1]
            if last.mnemonic.lower() in r_mnems and not reg_in_op(l_reg, last.op_str):
                 score -= self.PENALTY_BAD_RET

        return score

    def search(self):
        print(f"\n[*] RainbowBFS config: Depth={self.MAX_DEPTH}, Darkness={self.MAX_DARKNESS}")
        tails = self.gm.get_gadget_tails()
        
        # Queue format: (current_head, path_tuple, visited_set)
        queue = collections.deque([ (t['start'], (t['start'],), {t['start']}) for t in tails ])
        
        node_darkness = collections.defaultdict(int)
        pruned = 0

        while queue:
            head, path_tuple, visited = queue.popleft()
            
            if len(path_tuple) >= 1: 
                # Convert the tuple back to a list to maintain compatibility with the rest of your code
                self.gadgets.append(list(path_tuple))
            
            if len(path_tuple) >= self.MAX_DEPTH: 
                continue

            for parent in self.gm.reverse_graph.get(head, []):
                # O(1) instantaneous lookup using the set
                if parent in visited: 
                    continue
                
                if node_darkness[parent] >= self.MAX_DARKNESS:
                    pruned += 1
                    continue
                
                node_darkness[parent] += 1
                
                # Efficiently create the new path tuple and update the visited set
                new_path = (parent,) + path_tuple
                new_visited = visited.copy()
                new_visited.add(parent)
                
                queue.append((parent, new_path, new_visited))
        
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
            return "FALLTHROUGH", "Sequential"
        
    def _safe_print(self, text, file=sys.stdout):
        if file != sys.stdout:
            ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
            text = ansi_escape.sub('', text)
        print(text, file=file)

    def print_gadgets(self, limit, min_score, verbose, out_file):
        if verbose:
            self._safe_print(f"\n[*] Verbose Mode: Showing all {len(self.gadgets)} gadgets individually...", file=out_file)
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
                
                self._safe_print(f"\033[33m\n{'='*60}\033[0m", file=out_file)
                self._safe_print(f"\033[33m--- TOP {limit} {cat_name.upper()} GADGETS (RAW VIEW) ---\033[0m", file=out_file)
                self._safe_print(f"\033[33m{'='*60}\033[0m", file=out_file)
                
                for i, (s, p, tag) in enumerate(gadgets[:limit]):
                    self._safe_print(f"\nRANK #{i+1} | SCORE: {s} | TYPE: {tag}", file=out_file)
                    for addr in p:
                        if addr in self.gm.addr_to_node:
                            node = self.gm.addr_to_node[addr]
                            for insn in node['insns']:
                                    self._safe_print(f"  \033[33m{hex(insn.address)}\033[0m: {insn.mnemonic} {insn.op_str}", file=out_file)

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
                
                self._safe_print(f"\033[33m\n{'='*80}\033[0m", file=out_file)
                self._safe_print(f"\033[33m--- TOP {limit} UNIQUE {cat_name.upper()} GADGETS ---\033[0m", file=out_file)
                self._safe_print(f"\033[33m{'='*80}\033[0m", file=out_file)
                
                for i, (sig, data) in enumerate(sorted_gadgets[:limit]):
                    addrs = data['addresses']
                    count = len(addrs)
                    
                    primary_addr = hex(addrs[0])
                    
                    self._safe_print(f"\033[33m{primary_addr}\033[0m: {sig}", file=out_file)
                    
                    if count > 1:
                        others = ", ".join([hex(a) for a in addrs[1:]])
                        self._safe_print(f"  \033[90mFound {count} times (at {others})\033[0m", file=out_file)