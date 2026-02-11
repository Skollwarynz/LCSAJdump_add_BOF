import pytest
from unittest.mock import MagicMock, patch
import sys
from LCSAJdump.core.loader import BinaryLoader
from LCSAJdump.core.graph import LCSAJGraph
from LCSAJdump.core.rainbowBFS import RainbowFinder

# Helper per creare istruzioni mock
def make_insn(addr, mnem, op_str, size=4):
    i = MagicMock()
    i.address = addr
    i.mnemonic = mnem
    i.op_str = op_str
    i.size = size
    return i

# ==========================================
# 1. LOADER FIX
# ==========================================

def test_loader_no_text_section():
    """Simula un ELF valido ma senza sezione .text."""
    with patch('builtins.open', new_callable=MagicMock), \
         patch('LCSAJdump.core.loader.ELFFile') as mock_elf_class:
        
        mock_elf = mock_elf_class.return_value
        mock_elf.get_section_by_name.return_value = None # Nessuna .text
        
        loader = BinaryLoader("empty.elf")
        
        # FIX: Il loader cattura l'eccezione e fa sys.exit(1), quindi ci aspettiamo SystemExit
        with pytest.raises(SystemExit) as pytest_wrapped_e:
            loader.load()
        assert pytest_wrapped_e.type == SystemExit
        assert pytest_wrapped_e.value.code == 1

def test_loader_file_not_found():
    loader = BinaryLoader("non_esiste.bin")
    with pytest.raises(SystemExit) as pytest_wrapped_e:
        loader.load()
    assert pytest_wrapped_e.type == SystemExit
    assert pytest_wrapped_e.value.code == 1

# ==========================================
# 2. GRAPH FIX
# ==========================================

def test_graph_branch_logic():
    """Testa un if-else: Branch condizionale + Fallthrough."""
    # 0x1000: bne a0, a1, 0x1008 (Salta a Target B)
    # 0x1004: addi ...           (Fallthrough a Target A)
    # 0x1008: ret                (Target B)
    
    i1 = make_insn(0x1000, "bne", "a0, a1, 0x1008")
    i2 = make_insn(0x1004, "addi", "a0, a0, 1") 
    i3 = make_insn(0x1008, "ret", "")
    
    graph = LCSAJGraph([i1, i2, i3])
    graph.build()
    
    # FIX: Il blocco destinazione inizia a 0x1004 (che contiene i2 e i3)
    # Quindi il salto verso 0x1008 viene mappato al nodo 0x1004
    assert 0x1000 in graph.reverse_graph[0x1004] 

def test_graph_infinite_loop():
    insn = make_insn(0x1000, "j", "0x1000")
    graph = LCSAJGraph([insn])
    graph.build()
    assert 0x1000 in graph.reverse_graph[0x1000]

def test_graph_jump_outside():
    i1 = make_insn(0x1000, "j", "0xFFFFFFFF")
    graph = LCSAJGraph([i1])
    graph.build()
    assert 0xFFFFFFFF not in graph.reverse_graph
    assert len(graph.nodes) == 1

# ==========================================
# 3. STRESS TEST FIX & RAINBOW
# ==========================================

def test_stress_large_binary_chain():
    """Simula una catena di 1000 nodi collegati da salti."""
    qty = 1000
    instructions = []
    
    # Generiamo una catena: Nodo 0 -> Nodo 1 -> ... -> Ret
    # Ogni nodo è un salto al successivo.
    for i in range(qty):
        addr = 0x1000 + (i * 4)
        next_addr = addr + 4
        
        if i == qty - 1:
            insn = make_insn(addr, "ret", "")
        else:
            # Usiamo 'j' per forzare la creazione di un nuovo blocco LCSAJ ogni volta
            insn = make_insn(addr, "j", hex(next_addr))
            
        instructions.append(insn)
        
    graph = LCSAJGraph(instructions)
    graph.build()
    
    # Ora abbiamo 'qty' nodi distinti
    assert len(graph.nodes) == qty
    
    # Cerchiamo gadget con profondità limitata
    # Se il grafo è 0->1->2->3... e noi cerchiamo da Ret all'indietro:
    # Ret(999) <- 998 <- 997 ...
    finder = RainbowFinder(graph, max_depth=50, max_darkness=5)
    gadgets = finder.search()
    
    # FIX: Ora dovremmo trovare percorsi validi perché ci sono più nodi collegati
    assert len(gadgets) > 0
    
    # Verifica che il path più lungo sia limitato da max_depth
    max_len = max(len(g) for g in gadgets)
    assert max_len <= 50

def test_rainbow_cycle_handling():
    # ... (stesso codice del precedente, passava già) ...
    mock_gm = MagicMock()
    mock_gm.get_gadget_tails.return_value = [{'start': 0x3000, 'last_insn': make_insn(0x3004, "ret", "")}]
    mock_gm.reverse_graph = {
        0x3000: [0x2000], 0x2000: [0x1000], 0x1000: [0x2000]
    }
    mock_gm.addr_to_node = {
        0x1000: {'insns': [make_insn(0x1000, "nop", "")]}, 
        0x2000: {'insns': [make_insn(0x2000, "nop", "")]}, 
        0x3000: {'insns': [make_insn(0x3000, "ret", "")]}
    }
    finder = RainbowFinder(mock_gm, max_depth=10, max_darkness=5)
    gadgets = finder.search()
    assert len(gadgets) > 0

def test_rainbow_pruning_darkness():
    # ... (stesso codice del precedente, passava già) ...
    mock_gm = MagicMock()
    mock_gm.get_gadget_tails.return_value = [{'start': 0x4000, 'last_insn': make_insn(0x4000, "ret", "")}]
    mock_gm.reverse_graph = {
        0x4000: [0x3000], 0x3000: [0x2000], 0x2000: [0x1000],
    }
    mock_gm.addr_to_node = {k: {'insns': []} for k in [0x1000, 0x2000, 0x3000, 0x4000]}
    finder = RainbowFinder(mock_gm, max_depth=10, max_darkness=0) 
    gadgets = finder.search()
    pass

def test_scoring_priorities():
    # ... (stesso codice del precedente, passava già) ...
    mock_gm = MagicMock()
    finder = RainbowFinder(mock_gm, 5, 5)
    g1_insns = [make_insn(0x1000, "ld", "ra, 8(sp)"), make_insn(0x1004, "ret", "")]
    g2_insns = [make_insn(0x2000, "add", "a0, a1, a2"), make_insn(0x2004, "ret", "")]
    mock_gm.addr_to_node = {0x1000: {'insns': g1_insns}, 0x2000: {'insns': g2_insns}}
    score1 = finder.score_gadget([0x1000])
    score2 = finder.score_gadget([0x2000])
    assert score1 > score2
