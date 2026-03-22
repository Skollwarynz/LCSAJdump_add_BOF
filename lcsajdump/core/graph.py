import networkx as nx
import re
from collections import defaultdict
from .loader import draw_progress 
from .config import ARCH_PROFILES

HEX_PATTERN = re.compile(r'(0x[0-9a-fA-F]+)')

class LCSAJGraph:
    def __init__(self, instructions, arch="riscv64"):
        self.instructions = instructions 
        self.arch = arch
        
        profile_data = ARCH_PROFILES[arch]
        self.profile = profile_data 
        
        self.jump_mnems = set(profile_data["jump_mnems"])
        self.unconditional_jumps = set(profile_data["unconditional_jumps"])
        self.ret_mnems = set(profile_data["ret_mnems"])
        self.branch_prefixes = profile_data["branch_prefixes"] 
        self.trampoline_mnems = profile_data["trampoline_mnems"]
        
        self.nodes = []
        self.addr_to_node = {} 
        self.insn_to_block_start = {} 
        self.reverse_graph = defaultdict(list) 
        self.graph = nx.DiGraph()

    def build(self):
        self._create_nodes()
        self._build_edges()

    def _create_nodes(self):
        if not self.instructions: return
        total_insns = len(self.instructions)
        current_block_insns = []
        block_start = self.instructions[0].address 
        
        jump_mnems = self.jump_mnems
        branch_prefixes = self.branch_prefixes

        print(f"[*] Building LCSAJ Nodes for {self.arch}...")
        for idx, insn in enumerate(self.instructions):
            if idx % 5000 == 0: 
                draw_progress(idx, total_insns, "Building Graph")

            current_block_insns.append(insn)
            mnem = insn.mnemonic.lower()
            
            is_jump = mnem in jump_mnems or mnem.startswith(branch_prefixes)

            if is_jump:
                self._add_node(block_start, current_block_insns)
                current_block_insns = []
                if idx + 1 < total_insns:
                    block_start = self.instructions[idx+1].address 

        if current_block_insns:
            self._add_node(block_start, current_block_insns)
        draw_progress(total_insns, total_insns, "Building Graph")

    def _add_node(self, start, insns):
        node = {'start': start, 'end': insns[-1].address, 'insns': insns, 'last_insn': insns[-1]}
        self.nodes.append(node)
        self.addr_to_node[start] = node
        for i in insns:
            self.insn_to_block_start[i.address] = start

    def _build_edges(self):
        print("[*] Building edges...")
        insn_map = self.insn_to_block_start
        uncond_jumps = self.unconditional_jumps
        jump_mnems = self.jump_mnems
        branch_prefixes = self.branch_prefixes
        rev_graph = self.reverse_graph

        for node in self.nodes:
            last = node['last_insn']
            mnem = last.mnemonic.lower()
            start_addr = node['start']
            
            # (Fallthrough)
            if mnem not in uncond_jumps:
                next_addr = last.address + last.size
                if next_addr in insn_map:
                    target = insn_map[next_addr]
                    rev_graph[target].append(start_addr)

            # (Branch/Jump)
            if mnem in jump_mnems or mnem.startswith(branch_prefixes):
                op_str = last.op_str
                
                match = HEX_PATTERN.search(op_str)
                
                if match:
                    try:
                        addr = int(match.group(1), 16)
                        if addr in insn_map:
                            target = insn_map[addr]
                            rev_graph[target].append(start_addr)
                    except ValueError:
                        pass

    def get_gadget_tails(self):
        ret_mnems = self.ret_mnems
        uncond_jumps = self.unconditional_jumps
        call_mnems = self.profile.get("call_mnems", set())
        insn_map = self.insn_to_block_start
        tails = []

        for n in self.nodes:
            last_insn = n['last_insn']
            mnem = last_insn.mnemonic.lower()
            op_str = last_insn.op_str

            if mnem in ret_mnems:
                tails.append(n)

            elif mnem in uncond_jumps and mnem in self.trampoline_mnems:
                hex_match = HEX_PATTERN.search(op_str)

                if not hex_match:
                    tails.append(n)

                elif mnem in call_mnems:
                    try:
                        target_addr = int(hex_match.group(1), 16)
                        if target_addr in insn_map:
                            n['direct_call_target'] = target_addr
                            tails.append(n)
                    except (ValueError, KeyError):
                        pass

        return tails