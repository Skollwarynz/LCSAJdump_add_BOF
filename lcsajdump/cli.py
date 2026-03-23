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
@click.option('--output', '-o', default=None, type=click.Path(), help='Write gadgets to the specified file path.')
@click.option('--bad-chars', '-b', default='', help='Hex bytes to filter from gadget addresses (e.g. "000a0d").')
@click.option('--json', 'json_output', is_flag=True, help='Output gadgets as structured JSON.')
@click.option('--all-exec', is_flag=True, help='Analyze all executable sections, not just .text.')
@click.option('--viz', 'viz_output', is_flag=True, help='Export full graph (nodes+edges+gadgets+comparison+animation) as JSON for 3D visualization.')
@click.version_option(version='1.2.1', prog_name='LCSAJdump')
def main(binary_path, depth, darkness, limit, min_score, instructions, verbose, output, arch, bad_chars, json_output, all_exec, viz_output):
    """
    LCSAJ ROP Finder.
    Analyze a binary to find ROP gadgets using Rainbow BFS algorithm.
    """
    print('\33[33m'+r"""
        ██╗      ██████╗███████╗ █████╗      ██╗██████╗ ██╗   ██╗███╗   ███╗██████╗               ██╗   ██╗  ██╗   ██████╗     ██╗
        ██║     ██╔════╝██╔════╝██╔══██╗     ██║██╔══██╗██║   ██║████╗ ████║██╔══██╗              ██║   ██║ ███║   ╚════██╗   ███║
        ██║     ██║     ███████╗███████║     ██║██║  ██║██║   ██║██╔████╔██║██████╔╝    █████╗    ██║   ██║ ╚██║    █████╔╝   ╚██║
        ██║     ██║     ╚════██║██╔══██║██   ██║██║  ██║██║   ██║██║╚██╔╝██║██╔═══╝     ╚════╝    ╚██╗ ██╔╝  ██║   ██╔═══╝     ██║
        ███████╗╚██████╗███████║██║  ██║╚█████╔╝██████╔╝╚██████╔╝██║ ╚═╝ ██║██║                    ╚████╔╝   ██║██╗███████╗██╗ ██║
        ╚══════╝ ╚═════╝╚══════╝╚═╝  ╚═╝ ╚════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝                     ╚═══╝    ╚═╝╚═╝╚══════╝╚═╝ ╚═╝


                               RISC-V                            ARM64                          x86-64


        https://ko-fi.com/chris1sflaggin - Support the project!    |    https://chris1sflaggin.it/LCSAJdump/ - Official Website
    """+'\33[0m')

    print(f"[*] Analyzing Target: {binary_path}")

    if arch is None or arch == "auto":
        arch = auto_detect_env(binary_path)
        print(f"[\033[32m+\033[0m] Auto-detected architecture: \033[1m{arch.upper()}\033[0m")

    # Parse bad characters
    bad_bytes = set(bytes.fromhex(bad_chars)) if bad_chars else None

    # Resolve output destination
    out_path = output if output else None

    loader = BinaryLoader(binary_path, arch, all_exec=all_exec)
    insns = loader.disassemble()

    gb = LCSAJGraph(insns, arch)
    gb.build()

    finder = RainbowFinder(gb, max_depth=depth, max_darkness=darkness, max_insns=instructions)
    gadgets = finder.search()

    if json_output:
        json_str = finder.gadgets_to_json(limit=limit, min_score=min_score, bad_bytes=bad_bytes)
        if out_path:
            try:
                with open(out_path, "w") as fh:
                    fh.write(json_str)
                print(f"\n[\033[32m+\033[0m] JSON report saved in: {out_path}")
            except Exception as e:
                print(f"[!] Error while saving file: {e}")
        else:
            print(json_str)
    elif out_path:
        try:
            with open(out_path, "w") as fh:
                summary = finder.print_gadgets(limit=len(gadgets), min_score=min_score, verbose=verbose, out_file=fh, bad_bytes=bad_bytes)
            print(f"\n[\033[32m+\033[0m] Report saved in: {out_path}")
        except Exception as e:
            print(f"[!] Error while saving file: {e}")
            summary = None
    else:
        summary = finder.print_gadgets(limit=limit, min_score=min_score, verbose=verbose, out_file=sys.stdout, bad_bytes=bad_bytes)

    if viz_output:
        from .core.exporter import export_graph_json
        import os
        viz_path = output if output else (os.path.splitext(os.path.basename(binary_path))[0] + "_lcsaj.json")

        coverage_data = None
        trace_data    = None
        pmap_data     = None

        from .core.tool_runner import compute_tool_coverage
        print(f"\n[*] Computing multi-tool coverage...")
        try:
            coverage_data = compute_tool_coverage(gb, finder, binary_path, arch,
                                                  run_real_tools=True)
            sim = coverage_data.get("simulated", [])
            if sim:
                print(f"[\033[33m!\033[0m] Tools simulated (not installed): {', '.join(sim)}")
            else:
                print(f"[\033[32m+\033[0m] Real tool output used for coverage")
        except Exception as e:
            print(f"[\033[33m!\033[0m] Coverage computation failed: {e} — proceeding without")

        from .core.trace_builder import build_animation_trace
        print(f"[*] Building animation trace...")
        try:
            trace_data, pmap_data = build_animation_trace(gb, finder, coverage_data or {})
            print(f"[\033[32m+\033[0m] Animation trace: {len(trace_data)} events")
        except Exception as e:
            print(f"[\033[33m!\033[0m] Animation trace failed: {e} — proceeding without")

        try:
            export_graph_json(binary_path, arch, loader, gb, finder, viz_path,
                              coverage=coverage_data,
                              trace=trace_data,
                              phase_map=pmap_data)
            print(f"\n[\033[32m+\033[0m] Graph JSON exported to: \033[1m{viz_path}\033[0m")
        except Exception as e:
            print(f"\n[!] Graph JSON export failed: {e}")

    if not json_output and summary:
        print(f"\nFound {summary['total']} gadgets. Showing {summary['shown_seq']} sequential + {summary['shown_jmp']} jump-based (use --limit N to show more).")

if __name__ == '__main__':
    main()
