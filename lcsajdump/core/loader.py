import capstone
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SH_FLAGS
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
    def __init__(self, path, arch, all_exec=False):
        self.path = path
        self.arch = arch
        self.all_exec = all_exec
        self.profile = ARCH_PROFILES.get(arch)

        if not self.profile:
            raise ValueError(f"Architettura {arch} non supportata o non configurata.")

        self.md = capstone.Cs(self.profile["cs_arch"], self.profile["cs_mode"])
        self.md.detail = True
        self.code_bytes = None
        self.base_addr = 0
        self.sections = []

    def load(self):
        print(f"[*] Loading binary: {self.path}")
        try:
            with open(self.path, 'rb') as f:
                elf = ELFFile(f)

                if self.all_exec:
                    self._load_all_exec(elf)
                else:
                    self._load_text_section(elf)

        except FileNotFoundError:
            print(f"[!] Errore: File {self.path} non trovato.")
            sys.exit(1)
        except Exception as e:
            print(f"[!] Errore nel parsing ELF: {e}")
            sys.exit(1)

    def _load_text_section(self, elf):
        text_section = elf.get_section_by_name('.text')

        if not text_section:
            raise ValueError("Error: Section .text not found in binary!")

        self.code_bytes = text_section.data()
        self.base_addr = text_section['sh_addr']
        self.sections = [(self.base_addr, self.code_bytes)]

        print(f"[*] Section .text found.")
        print(f"    Size: {len(self.code_bytes)} bytes")
        print(f"    Start Address: {hex(self.base_addr)}\n")

    def _load_all_exec(self, elf):
        """Load all sections with SHF_EXECINSTR flag."""
        self.sections = []
        for section in elf.iter_sections():
            if section['sh_flags'] & SH_FLAGS.SHF_EXECINSTR:
                data = section.data()
                addr = section['sh_addr']
                if len(data) > 0:
                    self.sections.append((addr, data))
                    print(f"[*] Executable section '{section.name}' found. Size: {len(data)} bytes, Addr: {hex(addr)}")

        if not self.sections:
            raise ValueError("Error: No executable sections found in binary!")

        self.base_addr = self.sections[0][0]
        self.code_bytes = self.sections[0][1]
        print()

    def _disassemble_section(self, code_bytes, base_addr):
        """Disassemble a single section and return a list of instructions."""
        instructions = []
        total_bytes = len(code_bytes)
        ptr = 0
        step = self.profile["step"]

        while ptr < total_bytes:
            curr_addr = base_addr + ptr

            try:
                chunk = code_bytes[ptr:]
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

        return instructions

    def disassemble(self):
        if self.code_bytes is None:
            self.load()

        print("[*] Capstone is disassembling...")

        instructions = []

        if len(self.sections) > 1:
            for base_addr, code_bytes in self.sections:
                instructions.extend(self._disassemble_section(code_bytes, base_addr))
        else:
            instructions.extend(self._disassemble_section(self.code_bytes, self.base_addr))

        draw_progress(1, 1, "Disassembling")
        print(f"[*] Disassembling complete. {len(instructions)} instructions extracted.\n")
        return instructions
