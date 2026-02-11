import click
import sys
from core.loader import BinaryLoader
from core.graph import LCSAJGraph
from core.rainbowBFS import RainbowFinder

@click.command()
@click.argument('binary_path', type=click.Path(exists=True))
@click.option('--depth', '-d', default=12, help='Profondità massima di ricerca (blocchi LCSAJ).')
@click.option('--darkness', '-k', default=50, help='Soglia di pruning (Max visite per nodo).')
@click.option('--limit', '-l', default=10, help='Numero di gadget da mostrare a video.')
@click.option('--min-score', '-s', default=0, help='Punteggio minimo per mostrare un gadget.')
@click.option('--verbose', '-v', is_flag=True, help='Mostra dettagli extra sui gadget trovati.')
def main(binary_path, depth, darkness, limit, min_score, verbose):
    """
    RISC-V LCSAJ ROP Finder.
    Analizza un binario per trovare gadget ROP usando l'algoritmo Rainbow BFS.
    """
    print(f"[*] Analisi Target: {binary_path}")
    
    loader = BinaryLoader(binary_path)
    insns = loader.disassemble()
    
    gb = LCSAJGraph(insns)
    gb.build()
    
    finder = RainbowFinder(gb, max_depth=depth, max_darkness=darkness)
    gadgets = finder.search()
    
    # Output a video filtrato
    finder.print_gadgets(limit=limit, min_score=min_score, verbose=verbose)
    
    # Output su file (TUTTO, senza limiti di visualizzazione ma ordinato)
    output_file = "gadgets_found.txt"
    try:
        with open(output_file, "w") as f:
            sys.stdout = f
            print(f"REPORT GADGET - Depth:{depth} Darkness:{darkness}\n")
            finder.print_gadgets(limit=len(gadgets), min_score=min_score)
            sys.stdout = sys.__stdout__ # Ripristina stdout
        print(f"\n[+] Report salvato in: {output_file} (Trovati {len(gadgets)} gadget)")
    except Exception as e:
        sys.stdout = sys.__stdout__
        print(f"[!] Errore salvataggio file: {e}")

if __name__ == '__main__':
    main()