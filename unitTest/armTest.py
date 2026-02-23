import pytest
from unittest.mock import MagicMock
from lcsajdump.core.loader import BinaryLoader
from lcsajdump.core.graph import LCSAJGraph
from lcsajdump.core.rainbowBFS import RainbowFinder
from lcsajdump.core.config import ARCH_PROFILES

# Real ARM64 bytes for:
# mov x0, x1  -> e0 03 01 aa
# ret         -> c0 03 5f d6
# Byte ARM64 corretti per Little Endian (mov x0, x1 e ret)
ARM64_BYTES = b'\xe0\x03\x01\xaa\xc0\x03\x5f\xd6'
START_ADDR = 0x400000

def make_insn(addr, mnem, op_str, size=4):
    i = MagicMock()
    i.address = addr
    i.mnemonic = mnem
    i.op_str = op_str
    i.size = size
    return i

def test_arm64_decode_bytes():
    """Verify that the loader configures Capstone for ARM64 and decodes the 4-byte instructions."""
    loader = BinaryLoader("dummy", "arm64")
    loader.code_bytes = ARM64_BYTES
    loader.base_addr = START_ADDR
    
    insns = loader.disassemble()
    
    assert len(insns) == 2
    assert insns[0].mnemonic == "mov"
    assert "x0" in insns[0].op_str
    assert insns[1].mnemonic == "ret"
    assert insns[0].size == 4
    assert insns[1].size == 4

def test_arm64_scoring_priorities():
    """Verify that scoring prioritizes the x0 (argument) and x30/lr (link register)."""
    mock_gm = MagicMock()
    mock_gm.profile = ARCH_PROFILES["arm64"]
    
    finder = RainbowFinder(mock_gm, 5, 5)
    
    # Gadget 1: mov x0, x1; ret (Great ROP gadget, sets argument 0)
    g1_insns = [make_insn(0x1000, "mov", "x0, x1"), make_insn(0x1004, "ret", "")]
    
    # Gadget 2: add x2, x2, 1; ret (Useless standard instruction)
    g2_insns = [make_insn(0x2000, "add", "x2, x2, #1"), make_insn(0x2004, "ret", "")]
    
    # Gadget 3: ldp x29, x30, [sp], #16; ret (Standard ARM64 epilogue, restores Link Register)
    g3_insns = [make_insn(0x3000, "ldp", "x29, x30, [sp], #16"), make_insn(0x3004, "ret", "")]
    
    mock_gm.addr_to_node = {
        0x1000: {'insns': g1_insns}, 
        0x2000: {'insns': g2_insns},
        0x3000: {'insns': g3_insns}
    }
    
    score1 = finder.score_gadget([0x1000])  # Should get +40 for 'x0'
    score2 = finder.score_gadget([0x2000])  # No bonuses
    score3 = finder.score_gadget([0x3000])  # Should get +50 for 'x30'
    
    assert score1 > score2, "Gadget setting 'x0' should score higher than a random one!"
    assert score3 > score2, "Gadget restoring 'x30' should get the link_reg bonus!"

def test_arm64_classification():
    """Verify that ARM64 branch mnemonics are classified correctly."""
    mock_gm = MagicMock()
    mock_gm.profile = ARCH_PROFILES["arm64"]
    finder = RainbowFinder(mock_gm, 5, 5)
    
    mock_gm.addr_to_node = {
        0x1000: {'last_insn': make_insn(0x1000, "cbnz", "x0, 0x1050")},  # Conditional
        0x2000: {'last_insn': make_insn(0x2000, "blr", "x1")}            # Trampoline
    }
    
    tag1, _ = finder._classify_gadget([0x1000, 0x9999])
    tag2, _ = finder._classify_gadget([0x2000, 0x9999])
    
    assert tag1 == "CONDITIONAL"
    assert tag2 == "TRAMPOLINE"
