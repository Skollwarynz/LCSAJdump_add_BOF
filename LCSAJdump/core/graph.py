import networkx as nx

class LCSAJGraph:
    def __init__(self, instructions):
        self.instructions = instructions
        self.graph = nx.DiGraph()
        
        # Mappa fondamentale per le performance: Indirizzo -> Nodo
        self.addr_to_node = {} 
        
        # Il tuo Grafo Inverso (Fondamentale per la BFS)
        # Struttura: { Indirizzo_Destinazione : [Indirizzo_Sorgente1, Indirizzo_Sorgente2] }
        self.reverse_graph = {}
        
        self.nodes = []

    def build(self):
        print("[*] Costruzione Nodi LCSAJ...")
        self._create_nodes()
        
        print("[*] Costruzione Archi (Collegamenti)...")
        self._build_edges()
        
        print(f"[*] Grafo Completo. Nodi: {len(self.nodes)}, Archi inversi mappati.")

    def _create_nodes(self):
        """Step 1: Taglia il codice in blocchi"""
        if not self.instructions: return

        current_block_insns = []
        block_start = self.instructions[0].address 

        for insn in self.instructions:
            current_block_insns.append(insn)
            mnem = insn.mnemonic.lower()
            
            # Logica di taglio (Salto o Return)
            is_jump = False
            # Return / Uscite
            if mnem in ['ret', 'c.jr', 'c.jalr', 'mret', 'sret', 'jr', 'jalr']:
                is_jump = True
            # Salti (Diretti e Condizionali)
            elif mnem in ['j', 'jal', 'c.j', 'c.jal'] or mnem.startswith('b') or mnem.startswith('c.b'):
                is_jump = True

            if is_jump:
                self._add_node(block_start, current_block_insns)
                current_block_insns = []
                # Il prossimo blocco inizia dopo questo salto
                block_start = insn.address + insn.size

        if current_block_insns:
            self._add_node(block_start, current_block_insns)

    def _add_node(self, start, insns):
        # Salviamo il nodo
        node = {
            'start': start,
            'end': insns[-1].address,
            'insns': insns,
            'last_insn': insns[-1]
        }
        self.nodes.append(node)
        self.addr_to_node[start] = node # Indicizzazione rapida
        self.graph.add_node(start, **node)

    def _build_edges(self):
        """Step 2: Collega i blocchi (Popola reverse_graph)"""
        
        for node in self.nodes:
            last = node['last_insn']
            mnem = last.mnemonic.lower()
            
            # Destinazioni possibili da questo blocco
            targets = []

            # A. Fallthrough (Il codice continua sotto?)
            # Se NON è un salto incondizionato (J, JAL, RET), il flusso continua.
            if mnem not in ['j', 'jal', 'c.j', 'c.jal', 'ret', 'jr', 'c.jr', 'mret']:
                next_addr = last.address + last.size
                if next_addr in self.addr_to_node:
                    targets.append(next_addr)

            # B. Salti Espliciti (JAL, BEQ...)
            # Capstone ci dà gli operandi. Se è un immediato (indirizzo), è un target.
            # Nota: Per semplicità usiamo op_str se l'operando è un immediato esplicito.
            # RISC-V Capstone spesso risolve già l'indirizzo assoluto.
            if mnem.startswith('b') or mnem in ['jal', 'j', 'c.j', 'c.jal', 'c.beqz', 'c.bnez']:
                try:
                    # Parsing brutale ma efficace per la tesi: cerca operandi che sembrano hex
                    ops = last.op_str.split(',')
                    target_cand = ops[-1].strip() # L'ultimo operando è solitamente il target
                    if target_cand.startswith('0x'):
                        addr = int(target_cand, 16)
                        if addr in self.addr_to_node:
                            targets.append(addr)
                except:
                    pass # Ignora parsing complessi per ora

            # C. Registriamo nel Grafo Inverso
            for t in targets:
                if t not in self.reverse_graph:
                    self.reverse_graph[t] = []
                # t (Figlio) è puntato da node['start'] (Padre)
                self.reverse_graph[t].append(node['start'])

    def get_gadget_tails(self):
        """Ritorna i nodi che finiscono con RET/JR"""
        tails = []
        for node in self.nodes:
            mnem = node['last_insn'].mnemonic.lower()
            # Includiamo 'c.jr' e 'jalr' (se su ra) come potenziali return
            if mnem in ['ret', 'c.jr', 'jr', 'c.jalr', 'jalr']:
                tails.append(node)
        return tails
