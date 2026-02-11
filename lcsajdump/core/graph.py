import networkx as nx
from .loader import draw_progress

class LCSAJGraph:
    def __init__(self, instructions):
        self.instructions = instructions
        self.graph = nx.DiGraph()
        self.addr_to_node = {} # Inizio blocco -> Dati blocco
        self.insn_to_block_start = {} # Indirizzo istruzione -> Inizio blocco di appartenenza
        self.reverse_graph = {} 
        self.nodes = []

    def build(self):
        self._create_nodes()
        self._build_edges()

    def _create_nodes(self):
        if not self.instructions: return

        print("[*] Costruzione Nodi LCSAJ...") 
        
        total_insns = len(self.instructions)
        current_block_insns = []
        block_start = self.instructions[0].address 

        for idx, insn in enumerate(self.instructions):
            
            if idx % 1000 == 0:
                draw_progress(idx, total_insns, "Building Graph")

            current_block_insns.append(insn)
            mnem = insn.mnemonic.lower()
            
            is_jump = mnem in ['ret', 'c.jr', 'c.jalr', 'jr', 'jalr'] or \
                      mnem in ['j', 'jal', 'c.j', 'c.jal'] or \
                      mnem.startswith('b') or mnem.startswith('c.b')

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
        for node in self.nodes:
            last = node['last_insn']
            mnem = last.mnemonic.lower()
            targets = []

            if mnem not in ['j', 'jal', 'c.j', 'c.jal', 'ret', 'jr', 'c.jr']:
                next_addr = last.address + last.size
                if next_addr in self.insn_to_block_start:
                    targets.append(self.insn_to_block_start[next_addr])

            if mnem.startswith('b') or mnem in ['jal', 'j', 'c.j', 'c.jal']:
                try:
                    import re
                    hex_match = re.findall(r'0x[0-9a-fA-F]+', last.op_str)
                    if hex_match:
                        addr = int(hex_match[-1], 16)
                        if addr in self.insn_to_block_start:
                            targets.append(self.insn_to_block_start[addr])
                except: pass

            for t in set(targets):
                if t not in self.reverse_graph: self.reverse_graph[t] = []
                self.reverse_graph[t].append(node['start'])

    def get_gadget_tails(self):
        return [n for n in self.nodes if n['last_insn'].mnemonic.lower() in ['ret', 'c.jr', 'jr', 'jalr']]
