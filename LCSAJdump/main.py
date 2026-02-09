import click
import sys
from core.loader import BinaryLoader
from core.graph import LCSAJGraph
from core.rainbowBFS import RainbowFinder

@click.command()
@click.argument('binary_path', type=click.Path(exists=True))
def main(binary_path):
    print(f"[*] Analisi LCSAJ ROP su: {binary_path}")

    # 1. Loader
    loader = BinaryLoader(binary_path)
    loader.load()
    instructions = loader.disassemble()

    # 2. Graph Builder
    gb = LCSAJGraph(instructions)
    gb.build()
    
    # 3. Rainbow BFS (Il tuo algoritmo)
    finder = RainbowFinder(gb)
    gadgets = finder.search()
    
    # 4. Output
    finder.print_gadgets(limit=5)

if __name__ == '__main__':
    main()
