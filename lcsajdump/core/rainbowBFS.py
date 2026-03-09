import collections
import sys
import re

def reg_in_op(reg_config, op_str):
    if not reg_config:
        return False
    if isinstance(reg_config, str):
        return reg_config in op_str
    return any(r in op_str for r in reg_config)

class RainbowFinder:
    MAX_INSNS = 15 
    def __init__(self, graph_manager, max_depth, max_darkness):
        self.gm = graph_manager
        self.gadgets = []
        self.MAX_DEPTH = max_depth
        self.MAX_DARKNESS = max_darkness
        self.profile = self.gm.profile 
        
        self.weights = self.profile.get("scoring_weights", {})
        self.base_score = self.weights.get("base_score", 100)
        self.insn_penalty = self.weights.get("insn_penalty", 2)
        
        self.l_reg = self.profile.get("link_reg")
        self.a_reg = self.profile.get("primary_arg_reg")
        self.t_mnems = self.profile.get("trampoline_mnems", set())
        self.r_mnems = self.profile.get("ret_mnems", set())
        
        self.bonus_link = self.weights.get("bonus_link_reg", 50)
        self.bonus_arg = self.weights.get("bonus_arg_reg", 40)
        self.bonus_tramp = self.weights.get("bonus_trampoline", 30)
        self.penalty_ret = self.weights.get("penalty_bad_ret", 20)

    def score_gadget(self, path):
        score = self.base_score
        full_insns = []
        for addr in path: 
            if addr in self.gm.addr_to_node:
                full_insns.extend(self.gm.addr_to_node[addr]['insns'])
        
        score -= (len(full_insns) * self.insn_penalty)

        has_link_reg = any(reg_in_op(self.l_reg, i.op_str) for i in full_insns)
        has_arg_reg = any(reg_in_op(self.a_reg, i.op_str) for i in full_insns)
        has_J = any(i.mnemonic.lower() in self.t_mnems for i in full_insns)

        if has_link_reg: score += self.bonus_link
        if has_arg_reg: score += self.bonus_arg
        if has_J: score += self.bonus_tramp

        if full_insns:
            last = full_insns[-1]
            if last.mnemonic.lower() in self.r_mnems and not reg_in_op(self.l_reg, last.op_str):
                 score -= self.penalty_ret

        return score

    def search(self):
        print(f"\n[*] RainbowBFS config: Depth={self.MAX_DEPTH}, Darkness={self.MAX_DARKNESS}, Max Insns={self.MAX_INSNS}")
        tails = self.gm.get_gadget_tails()
        
        queue = collections.deque()
        
        self.grouped_gadgets = {}
        
        for t in tails:
            insn_count = len(t['insns'])
            if insn_count <= self.MAX_INSNS:
                queue.append((t['start'], (t['start'],), {t['start']}, insn_count))
        
        node_darkness = collections.defaultdict(int)
        pruned = 0
        duplicate_merges = 0

        while queue:
            head, path_tuple, visited, total_insns = queue.popleft()
            
            if len(path_tuple) >= 1:
                gadget_insns = []
                for addr in path_tuple:
                    gadget_insns.extend(self.gm.addr_to_node[addr]['insns'])
                
                sig = "; ".join([f"{i.mnemonic} {i.op_str}" for i in gadget_insns])
                start_addr = path_tuple[0]
                
                if sig not in self.grouped_gadgets:
                    self.grouped_gadgets[sig] = {
                        'path': list(path_tuple),
                        'addresses': {start_addr} 
                    }
                else:
                    self.grouped_gadgets[sig]['addresses'].add(start_addr)
                    duplicate_merges += 1
            
            if len(path_tuple) >= self.MAX_DEPTH: 
                continue

            for parent in self.gm.reverse_graph.get(head, []):
                if parent in visited: 
                    continue
                
                parent_node = self.gm.addr_to_node[parent]
                new_total_insns = total_insns + len(parent_node['insns'])
                
                if new_total_insns > self.MAX_INSNS:
                    pruned += 1
                    continue
                
                if node_darkness[parent] >= self.MAX_DARKNESS:
                    pruned += 1
                    continue
                
                node_darkness[parent] += 1
                
                new_path = (parent,) + path_tuple
                new_visited = visited.copy()
                new_visited.add(parent)
                
                queue.append((parent, new_path, new_visited, new_total_insns))
        
        print(f"[*] Pruning: {pruned} branches (Limits) | {duplicate_merges} duplicates merged.")
        self.gadgets = [g['path'] for g in self.grouped_gadgets.values()]
        return self.gadgets

    def _classify_gadget(self, path):
        if len(path) == 1:
            return "LINEAR", "Sequential"
        
        first_node = self.gm.addr_to_node[path[0]]
        last_insn = first_node['last_insn']
        mnem = last_insn.mnemonic.lower()
        
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

    def print_gadgets(self, limit, min_score, verbose, out_file=sys.stdout):
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
            categories = {'Sequential': [], 'Jump-Based': []}
            
            for sig, data in self.grouped_gadgets.items():
                path = data['path']
                addrs = sorted(list(data['addresses']))
                
                s = self.score_gadget(path)
                if s < min_score: continue
                
                tag, cat = self._classify_gadget(path)
                if cat not in categories: cat = 'Sequential'
                
                categories[cat].append({
                    'score': s,
                    'signature': sig,
                    'addresses': addrs
                })

            for cat_name in ['Sequential', 'Jump-Based']:
                sorted_gadgets = sorted(categories[cat_name], key=lambda x: x['score'], reverse=True)
                
                self._safe_print(f"\033[33m\n{'='*80}\033[0m", file=out_file)
                self._safe_print(f"\033[33m--- TOP {limit} UNIQUE {cat_name.upper()} GADGETS ---\033[0m", file=out_file)
                self._safe_print(f"\033[33m{'='*80}\033[0m", file=out_file)
                
                for i, item in enumerate(sorted_gadgets[:limit]):
                    addrs = item['addresses']
                    count = len(addrs)
                    sig = item['signature']
                    
                    primary_addr = hex(addrs[0])
                    
                    self._safe_print(f"\033[33m{primary_addr}\033[0m: {sig}", file=out_file)
                    
                    if count > 1:
                        others_to_show = addrs[1:5]
                        others_str = ", ".join([hex(a) for a in others_to_show])
                        more_str = f" ... (+{count - 5} others)" if count > 5 else ""
                        self._safe_print(f"  \033[90mFound {count} times (e.g. at {others_str}{more_str})\033[0m", file=out_file)