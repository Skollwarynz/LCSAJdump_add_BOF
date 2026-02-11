import pytest
import os
from LCSAJdump.core.loader import BinaryLoader
from LCSAJdump.core.graph import LCSAJGraph
from LCSAJdump.core.rainbowBFS import RainbowFinder

# Percorso relativo al file vulnerabile
VULN_PATH = "testCTFs/rop/vuln"

@pytest.mark.skipif(not os.path.exists(VULN_PATH), reason="Binario 'vuln' non trovato")
def test_real_binary_gadget_discovery():
    print(f"\n[*] Testing su binario reale: {VULN_PATH}")
    
    # 1. Caricamento Reale
    loader = BinaryLoader(VULN_PATH)
    loader.load()
    instructions = loader.disassemble()
    
    # 2. Costruzione Grafo
    graph = LCSAJGraph(instructions)
    graph.build()
    
    # 3. Ricerca Gadget
    # Usiamo depth bassa per velocità, il gadget target è corto (4 istruzioni)
    finder = RainbowFinder(graph, max_depth=6, max_darkness=2)
    gadgets = finder.search()
    
    # 4. Cerca il gadget specifico dell'exploit (0x4618c)
    target_addr = 0x4618c
    target_found = False
    
    for path in gadgets:
        # Il path è una lista di indirizzi di inzio blocco.
        # Dobbiamo controllare se il target è l'inizio di un blocco trovato.
        if path[0] == target_addr:
            target_found = True
            
            # Verifica opzionale: il gadget finisce con ret?
            last_node = graph.addr_to_node[path[-1]]
            mnem = last_node['last_insn'].mnemonic
            print(f"    -> Trovato gadget target! Finisce con: {mnem}")
            break
            
    assert target_found, "Il gadget critico 0x4618c non è stato trovato nel binario reale!"
