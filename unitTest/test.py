import pytest
from unittest.mock import MagicMock, patch
from lcsajdump.core.loader import BinaryLoader
from lcsajdump.core.graph import LCSAJGraph
from lcsajdump.core.rainbowBFS import RainbowFinder

# 1. Test del Loader (Parsing delle istruzioni)
def test_loader_disassemble_mock():
    # Mocking di capstone per testare la logica di disassemblaggio
    with patch('capstone.Cs') as mock_cs:
        # Aggiunto il parametro arch ("riscv64")
        loader = BinaryLoader("fake_path", "riscv64")
        loader.code_bytes = b"\x01\x11\x05\x05" # Byte finti
        loader.base_addr = 0x1000
        
        # Simula un'istruzione restituita da capstone
        mock_insn = MagicMock()
        mock_insn.address = 0x1000
        mock_insn.mnemonic = "addi"
        mock_insn.op_str = "sp, sp, -16"
        mock_insn.size = 4  # <- AGGIUNTO per evitare il crash del ciclo while
        
        mock_cs.return_value.disasm.return_value = [mock_insn]
        
        insns = loader.disassemble()
        assert len(insns) == 1
        assert insns[0].mnemonic == "addi"

# 2. Test del Grafo (Creazione dei nodi e LCSAJ)
def test_graph_node_creation():
    # Creiamo istruzioni fittizie: una addi seguita da un ret (fine blocco)
    insn1 = MagicMock(address=0x1000, size=4, mnemonic="addi", op_str="a0, a0, 1")
    insn2 = MagicMock(address=0x1004, size=2, mnemonic="ret", op_str="")
    
    graph = LCSAJGraph([insn1, insn2])
    graph.build()
    
    # Dovrebbe esserci un solo nodo (LCSAJ) che finisce con 'ret'
    assert len(graph.nodes) == 1
    assert graph.nodes[0]['last_insn'].mnemonic == "ret"
    assert graph.nodes[0]['start'] == 0x1000

# 3. Test delle Connessioni (Edges)
def test_graph_edges_fallthrough():
    # Due blocchi sequenziali senza salti
    insn1 = MagicMock(address=0x1000, size=4, mnemonic="addi", op_str="a0, a0, 1")
    insn2 = MagicMock(address=0x1004, size=4, mnemonic="addi", op_str="a1, a1, 1")
    
    graph = LCSAJGraph([insn1, insn2])
    graph._add_node(0x1000, [insn1])
    graph._add_node(0x1004, [insn2])
    graph._build_edges()
    
    # Il blocco 0x1004 dovrebbe avere come predecessore 0x1000 nel reverse_graph
    assert 0x1000 in graph.reverse_graph[0x1004]

# 4. Test della Ricerca (RainbowFinder)
def test_rainbow_search_depth():
    # Mock di un grafo con una catena di 3 nodi che finisce in ret
    # 0x1000 -> 0x2000 -> 0x3000 (ret)
    mock_gm = MagicMock()
    mock_gm.get_gadget_tails.return_value = [{'start': 0x3000, 'last_insn': MagicMock(mnemonic="ret")}]
    mock_gm.reverse_graph = {0x3000: [0x2000], 0x2000: [0x1000]}
    mock_gm.addr_to_node = {
        0x1000: {'insns': []}, 0x2000: {'insns': []}, 0x3000: {'insns': []}
    }
    
    # Test con profondità massima 2
    finder = RainbowFinder(mock_gm, max_depth=2, max_darkness=1)
    gadgets = finder.search()
    
    # Con depth 2, troverà solo percorsi di lunghezza 2 (es. [0x2000, 0x3000])
    # Non dovrebbe raggiungere 0x1000
    for g in gadgets:
        assert len(g) <= 2
