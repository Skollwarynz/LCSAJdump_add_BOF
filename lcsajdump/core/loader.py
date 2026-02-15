import capstone
from elftools.elf.elffile import ELFFile
import sys
from .config import ARCH_PROFILES

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
    def __init__(self, path, arch):
        self.path = path
        self.arch = arch
        self.profile = ARCH_PROFILES.get(arch)
        
        if not self.profile:
            raise ValueError(f"Architettura {arch} non supportata o non configurata.")
        
        self.md = capstone.Cs(self.profile["cs_arch"], self.profile["cs_mode"])
        self.md.detail = True 
        self.code_bytes = None
        self.base_addr = 0

    def load(self):
        print(f"[*] Loading binary: {self.path}")
        try:
            with open(self.path, 'rb') as f:
                elf = ELFFile(f)
                text_section = elf.get_section_by_name('.text')
                
                if not text_section:
                    raise ValueError("Error: Section .text not found in binary!")
                
                self.code_bytes = text_section.data()
                self.base_addr = text_section['sh_addr']
                
                print(f"[*] Section .text found.")
                print(f"    Size: {len(self.code_bytes)} bytes")
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
        step = self.profile["step"] 
        
        while ptr < total_bytes:
            curr_addr = self.base_addr + ptr
            
            try:
                chunk = self.code_bytes[ptr:]
                disasm_iter = self.md.disasm(chunk, curr_addr)
                
                count = 0
                for insn in disasm_iter:
                    instructions.append(insn)
                    ptr += insn.size
                    count += 1
                    
                    if len(instructions) % 5000 == 0:
                        draw_progress(ptr, total_bytes, "Disassembling")
                
                if count == 0:
                    ptr += step
                    
            except Exception:
                ptr += step

        draw_progress(total_bytes, total_bytes, "Disassembling")
        print(f"[*] Disassembling complete. {len(instructions)} instructions extracted.\n")
        return instructions