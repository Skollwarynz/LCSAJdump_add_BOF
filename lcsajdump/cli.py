import click
import sys
from .core.loader import BinaryLoader
from .core.graph import LCSAJGraph
from .core.rainbowBFS import RainbowFinder

@click.command()
@click.argument('binary_path', type=click.Path(exists=True))
@click.option('--depth', '-d', default=12, help='Profondità massima di ricerca (blocchi LCSAJ).')
@click.option('--darkness', '-k', default=30, help='Soglia di pruning (Max visite per nodo).')
@click.option('--limit', '-l', default=10, help='Numero di gadget da mostrare a video.')
@click.option('--min-score', '-s', default=0, help='Punteggio minimo per mostrare un gadget.')
@click.option('--verbose', '-v', is_flag=True, help='Mostra dettagli extra sui gadget trovati.')
@click.version_option(version='1.0.0', prog_name='LCSAJdump')
def main(binary_path, depth, darkness, limit, min_score, verbose):
    """
    RISC-V LCSAJ ROP Finder.
    Analizza un binario per trovare gadget ROP usando l'algoritmo Rainbow BFS.
    """
    print('\33[33m'+r"""
        ██╗      ██████╗███████╗ █████╗      ██╗██████╗ ██╗   ██╗███╗   ███╗██████╗               ██╗   ██╗ ██╗    ██████╗     ██████╗ 
        ██║     ██╔════╝██╔════╝██╔══██╗     ██║██╔══██╗██║   ██║████╗ ████║██╔══██╗              ██║   ██║███║   ██╔═████╗   ██╔═████╗
        ██║     ██║     ███████╗███████║     ██║██║  ██║██║   ██║██╔████╔██║██████╔╝    █████╗    ██║   ██║╚██║   ██║██╔██║   ██║██╔██║
        ██║     ██║     ╚════██║██╔══██║██   ██║██║  ██║██║   ██║██║╚██╔╝██║██╔═══╝     ╚════╝    ╚██╗ ██╔╝ ██║   ████╔╝██║   ████╔╝██║
        ███████╗╚██████╗███████║██║  ██║╚█████╔╝██████╔╝╚██████╔╝██║ ╚═╝ ██║██║                    ╚████╔╝  ██║██╗╚██████╔╝▄█╗╚██████╔╝
        ╚══════╝ ╚═════╝╚══════╝╚═╝  ╚═╝ ╚════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝                     ╚═══╝   ╚═╝╚═╝ ╚═════╝ ╚═╝ ╚═════╝                                                                                                                                
    """+'\33[0m')

    print(f"[*] Analizing Target: {binary_path}")
    
    loader = BinaryLoader(binary_path)
    insns = loader.disassemble()
    
    gb = LCSAJGraph(insns)
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
            finder.print_gadgets(limit=len(gadgets), min_score=min_score)
            sys.stdout = sys.__stdout__ 
        print(f"\n[+] Report saved in: {output_file} (Found {len(gadgets)} gadgets)")
    except Exception as e:
        sys.stdout = sys.__stdout__
        print(f"[!] Errore while saving file: {e}")

if __name__ == '__main__':
    main()
