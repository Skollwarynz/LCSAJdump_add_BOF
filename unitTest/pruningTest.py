import pytest
from unittest.mock import MagicMock
from lcsajdump.core.rainbowBFS import RainbowFinder

def _make_insn(mnemonic, op_str):
    insn = MagicMock()
    insn.mnemonic = mnemonic
    insn.op_str = op_str
    return insn

def test_strict_darkness_pruning():
    """Verifica che max_darkness fermi effettivamente le ricerche ripetitive.

    Grafo:
      0x2000 -> 0x3000 (ret)
      0x2000 -> 0x4000 (ret)

    Con darkness=1, 0x2000 viene attraversato solo dalla prima coda.
    Con darkness=2, entrambe le code possono attraversarlo → più gadget unici.
    """
    # Istruzioni distinte per ogni nodo così le firme non collidono
    insn_3000 = _make_insn("ret", "")
    insn_4000 = _make_insn("jr", "ra")
    insn_2000 = _make_insn("addi", "sp, sp, -16")

    mock_gm = MagicMock()
    mock_gm.profile = {
        "scoring_weights": {},
        "link_reg": "ra",
        "primary_arg_reg": "a0",
        "frame_reg": "s0",
        "trampoline_mnems": set(),
        "ret_mnems": {"ret", "jr"},
        "call_mnems": set(),
        "unconditional_jumps": {"ret", "jr"},
        "branch_prefixes": ("b",),
    }

    mock_gm.get_gadget_tails.return_value = [
        {'start': 0x3000, 'last_insn': insn_3000, 'insns': [insn_3000]},
        {'start': 0x4000, 'last_insn': insn_4000, 'insns': [insn_4000]},
    ]
    mock_gm.reverse_graph = {
        0x3000: [0x2000],
        0x4000: [0x2000],
    }
    mock_gm.addr_to_node = {
        0x2000: {'insns': [insn_2000], 'last_insn': insn_2000},
        0x3000: {'insns': [insn_3000], 'last_insn': insn_3000},
        0x4000: {'insns': [insn_4000], 'last_insn': insn_4000},
    }

    # Con darkness=1, il nodo 0x2000 può essere attraversato SOLO una volta.
    finder_strict = RainbowFinder(mock_gm, max_depth=5, max_darkness=1, max_insns=50)
    gadgets_strict = finder_strict.search()

    # Con darkness=2, entrambe le code possono attraversare 0x2000.
    finder_loose = RainbowFinder(mock_gm, max_depth=5, max_darkness=2, max_insns=50)
    gadgets_loose = finder_loose.search()

    assert len(gadgets_strict) < len(gadgets_loose), \
        "Il pruning (max_darkness) non sta tagliando i percorsi come dovrebbe!"
