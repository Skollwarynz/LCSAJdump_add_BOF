import pytest
from unittest.mock import MagicMock
from lcsajdump.core.rainbowBFS import RainbowFinder

def test_strict_darkness_pruning():
    """Verifica che max_darkness fermi effettivamente le ricerche ripetitive."""
    mock_gm = MagicMock()
    mock_gm.profile = {"ret_mnems": set()}
    
    # Creiamo un grafo in cui due "code" (tails) diverse (0x3000 e 0x4000) 
    # cercano entrambe di tornare indietro verso lo STESSO nodo (0x2000).
    # 0x2000 -> 0x3000 (Ret)
    # 0x2000 -> 0x4000 (Ret)
    mock_gm.get_gadget_tails.return_value = [
        {'start': 0x3000, 'last_insn': MagicMock()},
        {'start': 0x4000, 'last_insn': MagicMock()}
    ]
    mock_gm.reverse_graph = {
        0x3000: [0x2000],
        0x4000: [0x2000]
    }
    
    # Con darkness=1, il nodo 0x2000 può essere attraversato SOLO dalla prima "coda" che ci arriva.
    # La seconda verrà bloccata.
    finder_strict = RainbowFinder(mock_gm, max_depth=5, max_darkness=1)
    gadgets_strict = finder_strict.search()
    
    # Con darkness=2, entrambe le code possono attraversare 0x2000.
    finder_loose = RainbowFinder(mock_gm, max_depth=5, max_darkness=2)
    gadgets_loose = finder_loose.search()
    
    assert len(gadgets_strict) < len(gadgets_loose), "Il pruning (max_darkness) non sta tagliando i percorsi come dovrebbe!"
