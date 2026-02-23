import pytest
from unittest.mock import MagicMock, patch
from lcsajdump.core.loader import BinaryLoader
from lcsajdump.core.graph import LCSAJGraph
from lcsajdump.core.rainbowBFS import RainbowFinder
import capstone

# Byte presi dai commenti del tuo exploit.py
# 4618c: 70a2 (ld ra, 40(sp))
# 4618e: 6542 (ld a0, 16(sp))
# 46190: 6145 (addi sp, sp, 48)
# 46192: 8082 (ret)
GADGET_BYTES = b'\xa2\x70\x42\x65\x45\x61\x82\x80' # Little Endian
START_ADDR = 0x4618c

def test_decode_exploit_gadget():
    """Verifica che i byte specifici dell'exploit vengano decodificati correttamente."""
    loader = BinaryLoader("dummy", "riscv64") # <- Aggiunto parametro arch
    loader.code_bytes = GADGET_BYTES
    loader.base_addr = START_ADDR
    
    # Questo usa il vero Capstone (non mock) per verificare la config RISC-V C
    insns = loader.disassemble()
    
    assert len(insns) == 4
    assert insns[0].mnemonic in ['c.ldsp', 'ld'] # Capstone potrebbe normalizzare il nome
    assert insns[-1].mnemonic in ['c.jr', 'ret', 'jr']
    
def test_find_exploit_gadget_logic():
    """Verifica che il RainbowFinder identifichi questa sequenza come gadget valido."""
    # 1. Setup Loader e Disassembly reale
    loader = BinaryLoader("dummy", "riscv64") # <- Aggiunto parametro arch
    loader.code_bytes = GADGET_BYTES
    loader.base_addr = START_ADDR
    instructions = loader.disassemble()
    
    # 2. Build Graph
    graph = LCSAJGraph(instructions)
    graph.build()
    
    # 3. Search
    finder = RainbowFinder(graph, max_depth=5, max_darkness=1)
    gadgets = finder.search()
    
    # 4. Verifica: Dobbiamo trovare un gadget che inizia a 0x4618c
    found = False
    for g in gadgets:
        if g[0] == START_ADDR:
            found = True
            # Verifica punteggio alto (ha 'ld ra' e 'ret')
            score = finder.score_gadget(g)
            assert score > 100 # Dovrebbe avere bonus RA (+50) e base
            break
            
    assert found, f"Il tool non ha trovato il gadget a {hex(START_ADDR)}!"
