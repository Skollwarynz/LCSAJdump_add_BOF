import click
import sys
from core.loader import BinaryLoader
from core.graph import LCSAJGraph
from core.rainbowBFS import RainbowFinder

@click.command()
@click.argument('binary_path')
def main(binary_path):
    loader = BinaryLoader(binary_path)
    insns = loader.disassemble()
    
    gb = LCSAJGraph(insns)
    gb.build()
    
    finder = RainbowFinder(gb)
    gadgets = finder.search()
    
    finder.print_gadgets(limit=10)
    print(f"\n[+] Trovati {len(gadgets)} gadget. Analisi completata.")

if __name__ == '__main__':
    main()
