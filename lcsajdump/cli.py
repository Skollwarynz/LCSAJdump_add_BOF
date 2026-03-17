import click
import sys
from .core.loader import BinaryLoader
from .core.graph import LCSAJGraph
from .core.rainbowBFS import RainbowFinder
from elftools.elf.elffile import ELFFile

def auto_detect_env(binary_path):
    """Legge l'header ELF e deduce l'architettura."""
    try:
        with open(binary_path, 'rb') as f:
            elf = ELFFile(f)
            arch_str = elf.get_machine_arch()
            
            if arch_str in ['x64', 'EM_X86_64']:
                return 'x86_64'
            elif arch_str in ['AArch64', 'EM_AARCH64']:
                return 'arm64'
            elif arch_str in ['RISC-V', 'EM_RISCV']:
                return 'riscv64'
            else:
                return 'riscv64' 
    except Exception:
        return 'riscv64'

@click.command()
@click.argument('binary_path', type=click.Path(exists=True))
@click.option('--depth', '-d', default=20, help='Max search depth (LCSAJ blocks).')
@click.option('--darkness', '-k', default=5, help='Pruning threshold (Max visits per node).')
@click.option('--limit', '-l', default=10, help='Desired number of gadgets to show.')
@click.option('--min-score', '-s', default=0, help='Min score for a gadget to be shown.')
@click.option('--instructions', '-i', default=15, help='Max number of instructions contained in a single node')
@click.option('--arch', '-a', default='auto', help='Architecture of the binary (auto[default], riscv64, x86_64, arm64).')
@click.option('--verbose', '-v', is_flag=True, help='Verbose results for a better detailed result.')
@click.option('--file', '-f', is_flag=True, help='Write found gadgets to a file "found_gadgets.txt".')
@click.version_option(version='1.1.3', prog_name='LCSAJdump')
def main(binary_path, depth, darkness, limit, min_score, instructions, verbose, file, arch):
    """
    LCSAJ ROP Finder.
    Analyze a binary to find ROP gadgets using Rainbow BFS algorithm.
    """
    print('\33[33m'+r"""
        ██╗      ██████╗███████╗ █████╗      ██╗██████╗ ██╗   ██╗███╗   ███╗██████╗               ██╗   ██╗ ██╗    ██╗    ██████╗
        ██║     ██╔════╝██╔════╝██╔══██╗     ██║██╔══██╗██║   ██║████╗ ████║██╔══██╗              ██║   ██║███║   ███║    ╚════██╗
        ██║     ██║     ███████╗███████║     ██║██║  ██║██║   ██║██╔████╔██║██████╔╝    █████╗    ██║   ██║╚██║   ╚██║     █████╔╝
        ██║     ██║     ╚════██║██╔══██║██   ██║██║  ██║██║   ██║██║╚██╔╝██║██╔═══╝     ╚════╝    ╚██╗ ██╔╝ ██║    ██║     ╚═══██╗
        ███████╗╚██████╗███████║██║  ██║╚█████╔╝██████╔╝╚██████╔╝██║ ╚═╝ ██║██║                    ╚████╔╝  ██║██╗ ██║██╗ ██████╔╝
        ╚══════╝ ╚═════╝╚══════╝╚═╝  ╚═╝ ╚════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝                     ╚═══╝   ╚═╝╚═╝ ╚═╝╚═╝ ╚═════╝
        

                               RISC-V                            ARM64                          x86-64 
          
          
        https://ko-fi.com/chris1sflaggin - Support the project!    |    https://chris1sflaggin.it/LCSAJdump/ - Official Website
    """+'\33[0m')

    print(f"[*] Analyzing Target: {binary_path}")

    if arch is None or arch == "auto":
        arch = auto_detect_env(binary_path)
        print(f"[\033[32m+\033[0m] Auto-detected architecture: \033[1m{arch.upper()}\033[0m")

    loader = BinaryLoader(binary_path, arch)
    insns = loader.disassemble()
    
    gb = LCSAJGraph(insns, arch)
    gb.build()
    
    finder = RainbowFinder(gb, max_depth=depth, max_darkness=darkness, max_insns=instructions)
    gadgets = finder.search()
    
    if file:
        output_file = "gadgets_found.txt"
        try:
            with open(output_file, "w") as f:
                finder.print_gadgets(limit=len(gadgets), min_score=min_score, verbose=verbose, out_file=f)
            print(f"\n[+] Report saved in: {output_file}")
        except Exception as e:
            print(f"[!] Error while saving file: {e}")
    else:
        finder.print_gadgets(limit=limit, min_score=min_score, verbose=verbose, out_file=sys.stdout)

    print(f"(Found {len(gadgets)} gadgets)")

if __name__ == '__main__':
    main()
