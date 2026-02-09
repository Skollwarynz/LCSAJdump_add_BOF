import capstone
from elftools.elf.elffile import ELFFile
import sys

class BinaryLoader:
    def __init__(self, path):
        self.path = path
        self.code_bytes = None
        self.base_addr = 0
        
        # --- CONFIGURAZIONE CAPSTONE ---
        # CS_ARCH_RISCV: Architettura principale
        # CS_MODE_RISCV64: Modalità a 64-bit
        # CS_MODE_RISCVC: Fondamentale! Abilita le istruzioni "Compressed" (16-bit).
        # Senza questo, perderemmo il 50% dei gadget potenziali.
        self.md = capstone.Cs(capstone.CS_ARCH_RISCV, 
                              capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC)
        
        # Abilitiamo i dettagli per poter analizzare gli operandi (registri, imm) dopo
        self.md.detail = True 

    def load(self):
        """
        Apre il file ELF, cerca la sezione .text (codice eseguibile)
        e la carica in memoria.
        """
        print(f"[*] Caricamento binario: {self.path}")
        try:
            with open(self.path, 'rb') as f:
                elf = ELFFile(f)
                text_section = elf.get_section_by_name('.text')
                
                if not text_section:
                    raise ValueError("Errore: Sezione .text non trovata nel binario!")
                
                self.code_bytes = text_section.data()
                self.base_addr = text_section['sh_addr']
                
                print(f"[*] Sezione .text trovata.")
                print(f"    Dimensione: {len(self.code_bytes)} bytes")
                print(f"    Indirizzo Base: {hex(self.base_addr)}")
                
        except FileNotFoundError:
            print(f"[!] Errore: File {self.path} non trovato.")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Errore nel parsing ELF: {e}")
            sys.exit(1)

    def disassemble(self):
        """
        Usa Capstone per trasformare i bytes grezzi in oggetti istruzione.
        Ritorna una lista di oggetti Capstone (CsInsn).
        """
        if self.code_bytes is None:
            self.load()
            
        print("[*] Avvio disassemblaggio con Capstone...")
        
        # md.disasm è un generatore. Lo convertiamo in lista per poterlo
        # scorrere più volte (necessario per il grafo) e accedere per indice.
        instructions = list(self.md.disasm(self.code_bytes, self.base_addr))
        
        print(f"[*] Disassemblaggio completato. {len(instructions)} istruzioni estratte.")
        return instructions

# --- DEBUGGING RAPIDO ---
if __name__ == "__main__":
    import sys
    
    # 1. Controlliamo se l'utente ha passato un argomento
    if len(sys.argv) > 1:
        TEST_BINARY = sys.argv[1] # Prendi il percorso passato da riga di comando
    else:
        # Fallback se non passi nulla
        TEST_BINARY = "" 
    
    print("--- TEST LOADER ---")
    
    # Istanziamo il loader con il percorso dinamico
    loader = BinaryLoader(TEST_BINARY)
    loader.load()
    insns = loader.disassemble()
    
    print("\n--- ANTEPRIMA (Prime 20 istruzioni) ---")
    for i in insns[:20]:
        # Stampa: Indirizzo | Mnemonic (es. addi) | Operandi (es. sp, sp, -16)
        print(f"{hex(i.address)}:\t{i.mnemonic}\t{i.op_str}")
