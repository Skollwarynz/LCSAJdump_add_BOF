import pytest
from unittest.mock import MagicMock
from lcsajdump.core.rainbowBFS import RainbowFinder
from lcsajdump.core.config import ARCH_PROFILES

def make_insn(mnem):
    i = MagicMock()
    i.mnemonic = mnem
    return i

def test_gadget_classification():
    """Verifica che RainbowFinder classifichi correttamente la tipologia di gadget."""
    mock_gm = MagicMock()
    mock_gm.profile = ARCH_PROFILES["riscv64"]
    finder = RainbowFinder(mock_gm, 5, 5, max_insns=15)
    
    # Simula i nodi nel grafo
    mock_gm.addr_to_node = {
        0x1000: {'last_insn': make_insn("j")},    # Jump incondizionato -> TRAMPOLINE
        0x2000: {'last_insn': make_insn("bne")},  # Branch condizionale -> CONDITIONAL
        0x3000: {'last_insn': make_insn("addi")}  # Fallthrough -> FALLTHROUGH
    }
    
    # 1. Un gadget di 1 sola istruzione deve essere LINEAR
    tag, cat = finder._classify_gadget([0x3000])
    assert tag == "LINEAR"
    
    # 2. Gadget che termina con un salto (j)
    tag, cat = finder._classify_gadget([0x9999, 0x1000])
    assert tag == "JOP"
    assert cat == "Jump-Based"
    
    # 3. Gadget che termina con un branch (bne)
    tag, cat = finder._classify_gadget([0x9999, 0x2000])
    assert tag == "CONDITIONAL"
