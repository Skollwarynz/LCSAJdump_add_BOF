import capstone
from elftools.elf.elffile import ELFFile
import sys

def draw_progress(current, total, label=""):
    percent = float(current) / float(total) * 100
    bar_length = 60
    filled_length = int(bar_length * current // total)
    
    bar = '█' * filled_length + '░' * (bar_length - filled_length)
    
    sys.stdout.write(f"\r{label:15} \033[32m[{bar}]\033[0m {percent:>5.1f}%")
    sys.stdout.flush()
    
    if current == total:
        print()

class BinaryLoader:
    def __init__(self, path):
        self.path = path
        self.code_bytes = None
        self.base_addr = 0
        
        # --- CONFIGURAZIONE CAPSTONE ---
        # CS_ARCH_RISCV: Architettura principale
        # CS_MODE_RISCV64: Modalità a 64-bit
        # CS_MODE_RISCVC: Abilita le istruzioni "Compressed" (16-bit).
        self.md = capstone.Cs(capstone.CS_ARCH_RISCV, 
                              capstone.CS_MODE_RISCV64 | capstone.CS_MODE_RISCVC)
        
        # Abilitiamo i dettagli per poter analizzare gli operandi (registri, imm) dopo
        self.md.detail = True 

    def load(self):
        """
        Apre il file ELF, cerca la sezione .text (codice eseguibile)
        e la carica in memoria.
        """
        print(f"[*] Loadaing binary: {self.path}")
        try:
            with open(self.path, 'rb') as f:
                elf = ELFFile(f)
                text_section = elf.get_section_by_name('.text')
                
                if not text_section:
                    raise ValueError("Error: Section .text not found in binary!")
                
                self.code_bytes = text_section.data()
                self.base_addr = text_section['sh_addr']
                
                print(f"[*] Section .text found.")
                print(f"    Dimension: {len(self.code_bytes)} bytes")
                print(f"    Start Address: {hex(self.base_addr)}\n")
                
        except FileNotFoundError:
            print(f"[!] Errore: File {self.path} non trovato.")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Errore nel parsing ELF: {e}")
            sys.exit(1)

    def disassemble(self):
        if self.code_bytes is None:
            self.load()
            
        print("[*] Capstone is disassembling...")
        
        instructions = []
        total_bytes = len(self.code_bytes)
        ptr = 0
        
        while ptr < total_bytes:
            curr_addr = self.base_addr + ptr
            
            # v6 OTTIMIZZAZIONE: Invece di chiederne 1 alla volta,
            try:
                # Slicing (solo con buco nel codice)
                chunk = self.code_bytes[ptr:]
                disasm_iter = self.md.disasm(chunk, curr_addr)
                
                count = 0
                for insn in disasm_iter:
                    instructions.append(insn)
                    ptr += insn.size
                    count += 1
                    
                    if len(instructions) % 5000 == 0:
                        draw_progress(ptr, total_bytes, "Disassembling")
                
                # Se count == 0, significa che Capstone si è bloccato SUBITO.
                # Quindi il byte a 'ptr' è sporco.
                if count == 0:
                    ptr += 2 
                    
            except Exception:
                ptr += 2

        draw_progress(total_bytes, total_bytes, "Disassembling")
        print(f"[*] Disassembling complete. {len(instructions)} instructions estracted.\n")
        return instructions