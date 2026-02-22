import click
import sys
from .core.loader import BinaryLoader
from .core.graph import LCSAJGraph
from .core.rainbowBFS import RainbowFinder

@click.command()
@click.argument('binary_path', type=click.Path(exists=True))
@click.option('--depth', '-d', default=30, help='Max search depth (LCSAJ blocks).')
@click.option('--darkness', '-k', default=5, help='Pruning threshold (Max visits per node).')
@click.option('--limit', '-l', default=10, help='Desired number of gadgets to show.')
@click.option('--min-score', '-s', default=0, help='Min score for a gadget to be shown.')
@click.option('--verbose', '-v', is_flag=True, help='Verbose results for a better detailed result.')
@click.option('--arch', '-a', default='riscv64', help='Architecture of the binary (default: riscv64).')
@click.version_option(version='1.1.1', prog_name='LCSAJdump')
def main(binary_path, depth, darkness, limit, min_score, verbose, arch):
    """
    LCSAJ ROP Finder.
    Analyze a binary to find ROP gadgets using Rainbow BFS algorithm.
    """
    print('\33[33m'+r"""
        ██╗      ██████╗███████╗ █████╗      ██╗██████╗ ██╗   ██╗███╗   ███╗██████╗               ██╗   ██╗ ██╗    ██╗    ██╗
        ██║     ██╔════╝██╔════╝██╔══██╗     ██║██╔══██╗██║   ██║████╗ ████║██╔══██╗              ██║   ██║███║   ███║   ███║
        ██║     ██║     ███████╗███████║     ██║██║  ██║██║   ██║██╔████╔██║██████╔╝    █████╗    ██║   ██║╚██║   ╚██║   ╚██║
        ██║     ██║     ╚════██║██╔══██║██   ██║██║  ██║██║   ██║██║╚██╔╝██║██╔═══╝     ╚════╝    ╚██╗ ██╔╝ ██║    ██║    ██║
        ███████╗╚██████╗███████║██║  ██║╚█████╔╝██████╔╝╚██████╔╝██║ ╚═╝ ██║██║                    ╚████╔╝  ██║██╗ ██║██╗ ██║
        ╚══════╝ ╚═════╝╚══════╝╚═╝  ╚═╝ ╚════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝                     ╚═══╝   ╚═╝╚═╝ ╚═╝╚═╝ ╚═╝


                               RISC-V                       ARM64 (shortly)                        x86-64 
          
          
        https://ko-fi.com/chris1sflaggin - Support the project!    |    https://chris1sflaggin.it/LCSAJdump/ - Official Website
    """+'\33[0m')

    if arch == 'arm64':
        print("\33[31m[!] ARM64 support is coming soon. Stay tuned!\33[0m")
        sys.exit(0)

    if arch in ['riscv64', 'x86_64', 'intel64', 'amd64', 'x86']:
        arch = 'x86_64' 

    print(f"[*] Analizing Target: {binary_path}")
    
    loader = BinaryLoader(binary_path, arch)
    insns = loader.disassemble()
    
    gb = LCSAJGraph(insns, arch)
    gb.build()
    
    finder = RainbowFinder(gb, max_depth=depth, max_darkness=darkness)
    gadgets = finder.search()
    
    # Output a video filtrato
    finder.print_gadgets(limit=limit, min_score=min_score, verbose=verbose)
    
    # Output su file 
    output_file = "gadgets_found.txt"
    try:
        with open(output_file, "w") as f:
            sys.stdout = f
            print(f"REPORT GADGET - Depth:{depth} Darkness:{darkness}\n")
            finder.print_gadgets(limit=len(gadgets), min_score=min_score, verbose=verbose)
            sys.stdout = sys.__stdout__ 
        print(f"\n[+] Report saved in: {output_file} (Found {len(gadgets)} gadgets)")
    except Exception as e:
        sys.stdout = sys.__stdout__
        print(f"[!] Errore while saving file: {e}")

if __name__ == '__main__':
    main()
