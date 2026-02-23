import pytest
from unittest.mock import MagicMock
from lcsajdump.core.loader import BinaryLoader
from lcsajdump.core.graph import LCSAJGraph
from lcsajdump.core.rainbowBFS import RainbowFinder
from lcsajdump.core.config import ARCH_PROFILES

# Byte reali per un classico gadget x86_64: "pop rdi; ret"
# 5f: pop rdi
# c3: ret
X86_BYTES = b'\x5f\xc3'
START_ADDR = 0x400000

def make_insn(addr, mnem, op_str, size=1):
    i = MagicMock()
    i.address = addr
    i.mnemonic = mnem
    i.op_str = op_str
    i.size = size
    return i

def test_x86_decode_bytes():
    """Verifica che il loader configuri Capstone per x86_64 e decodifichi i byte."""
    loader = BinaryLoader("dummy", "x86_64")
    loader.code_bytes = X86_BYTES
    loader.base_addr = START_ADDR
    
    insns = loader.disassemble()
    
    assert len(insns) == 2
    assert insns[0].mnemonic == "pop"
    assert "rdi" in insns[0].op_str
    assert insns[1].mnemonic == "ret"

def test_x86_scoring_priorities():
    """Verifica che i bonus vengano assegnati per rdi (arg) e rsp/rip (link)."""
    mock_gm = MagicMock()
    # Assegniamo il vero profilo x86_64 dal config
    mock_gm.profile = ARCH_PROFILES["x86_64"]
    
    finder = RainbowFinder(mock_gm, 5, 5)
    
    # Gadget 1: pop rdi; ret (Ottimo per ROP, setta il primo argomento)
    g1_insns = [make_insn(0x1000, "pop", "rdi", 1), make_insn(0x1001, "ret", "", 1)]
    
    # Gadget 2: add rax, 1; ret (Pessimo, non fa nulla di utile per rop standard)
    g2_insns = [make_insn(0x2000, "add", "rax, 1", 3), make_insn(0x2003, "ret", "", 1)]
    
    # Gadget 3: mov rsp, rbp; ret (Modifica lo stack pointer = link reg in x86)
    g3_insns = [make_insn(0x3000, "mov", "rsp, rbp", 3), make_insn(0x3003, "ret", "", 1)]
    
    mock_gm.addr_to_node = {
        0x1000: {'insns': g1_insns}, 
        0x2000: {'insns': g2_insns},
        0x3000: {'insns': g3_insns}
    }
    
    score1 = finder.score_gadget([0x1000])  # Ha 'rdi' (+40 punti previsti)
    score2 = finder.score_gadget([0x2000])  # Nessun bonus
    score3 = finder.score_gadget([0x3000])  # Ha 'rsp' (+50 punti previsti)
    
    assert score1 > score2, "Il gadget con 'rdi' dovrebbe avere un punteggio superiore!"
    assert score3 > score2, "Il gadget che tocca 'rsp' dovrebbe avere il bonus link_reg!"

def test_x86_syscall_sink():
    """Verifica che una syscall venga considerata una chiusura valida del gadget."""
    mock_gm = MagicMock()
    mock_gm.profile = ARCH_PROFILES["x86_64"]
    mock_gm.get_gadget_tails.return_value = [{'start': 0x4000, 'last_insn': make_insn(0x4000, "syscall", "", 2)}]
    mock_gm.reverse_graph = {0x4000: [0x3000]}
    
    g_insns = [make_insn(0x3000, "pop", "rax", 1), make_insn(0x4000, "syscall", "", 2)]
    mock_gm.addr_to_node = {
        0x3000: {'insns': [g_insns[0]]},
        0x4000: {'insns': [g_insns[1]]}
    }
    
    finder = RainbowFinder(mock_gm, 5, 5)
    gadgets = finder.search()
    
    assert len(gadgets) == 2 # Trova sia [0x4000] che [0x3000, 0x4000]
    
    # Verifica i punteggi matematicamente corretti del RainbowFinder
    score_1_node = finder.score_gadget([0x4000])
    score_2_nodes = finder.score_gadget([0x3000, 0x4000])
    
    # Base 100 - 2 (len) - 20 (penalità assenza rsp) = 78
    assert score_1_node == 78
    # Base 100 - 4 (len) - 20 (penalità assenza rsp) = 76
    assert score_2_nodes == 76
