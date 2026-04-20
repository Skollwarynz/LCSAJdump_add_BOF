import pytest
from unittest.mock import MagicMock
from lcsajdump.core.graph import LCSAJGraph
from lcsajdump.core.rainbowBFS import RainbowFinder
from lcsajdump.core.config import ARCH_PROFILES

def test_arm64_tail_discovery():
    # Simulated ARM64 gadgets: 
    # 1. mov x0, #1; ret
    # 2. add x1, x1, #1; ret
    mock_insns = [
        MagicMock(address=0x400, mnemonic="mov", op_str="x0, #1", size=4),
        MagicMock(address=0x404, mnemonic="ret", op_str="", size=4),
        MagicMock(address=0x408, mnemonic="add", op_str="x1, x1, #1", size=4),
        MagicMock(address=0x40c, mnemonic="ret", op_str="", size=4),
    ]
    
    # Manually build the graph to ensure tails are recognized
    graph = LCSAJGraph(mock_insns)
    graph.profile = ARCH_PROFILES["arm64"]
    graph.build()
    
    # Check if tails (the 'ret' instructions) were found
    tails = graph.get_gadget_tails()
    assert len(tails) == 2
    
    finder = RainbowFinder(graph, max_depth=5, max_darkness=1, max_insns=15)
    gadgets = finder.search()
    assert len(gadgets) > 0
