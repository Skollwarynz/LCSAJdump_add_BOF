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
                print(f"    Indirizzo Base: {hex(self.base_addr)}\n")
                
        except FileNotFoundError:
            print(f"[!] Errore: File {self.path} non trovato.")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Errore nel parsing ELF: {e}")
            sys.exit(1)

    def disassemble(self):
        if self.code_bytes is None:
            self.load()
            
        print("[*] Avvio disassemblaggio con Capstone (Modalità Resiliente)...")
        
        instructions = []
        total_bytes = len(self.code_bytes)
        ptr = 0
        
        while ptr < total_bytes:
            curr_addr = self.base_addr + ptr
            
            try:
                code_chunk = self.code_bytes[ptr:]
                
                gen = self.md.disasm(code_chunk, curr_addr, count=1)
                insn = next(gen, None)
                
                if insn:
                    instructions.append(insn)
                    ptr += insn.size 
                else:
                    ptr += 2
                    
            except StopIteration:
                ptr += 2
            except Exception:
                ptr += 2

            if len(instructions) % 1000 == 0:
                draw_progress(ptr, total_bytes, "Disassembling")

        draw_progress(total_bytes, total_bytes, "Disassembling")
        
        print(f"[*] Disassemblaggio completato. {len(instructions)} istruzioni estratte.\n")
        return instructions