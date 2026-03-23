"""
tool_runner.py — Run ropper/ROPgadget, parse their output, and compute per-node
tool coverage + tail sets for the multi-tool comparison layer.
"""
import re
import subprocess
from .config import ARCH_PROFILES

# Address patterns in tool output
_ROPPER_LINE_RE    = re.compile(r'^(0x[0-9a-fA-F]+)\s*:', re.MULTILINE)
_ROPGADGET_LINE_RE = re.compile(r'^(0x[0-9a-fA-F]+)\s*:', re.MULTILINE)
_RPPLUS_LINE_RE    = re.compile(r'^(0x[0-9a-fA-F]+)\s*:', re.MULTILINE)
_HEX_RE            = re.compile(r'0x[0-9a-fA-F]+')

# x86-64 "standard" registers accessible without REX.B prefix
_X86_STD_REGS = frozenset({
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp',
    'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp',
})
# Extended registers that require REX.B (r8–r15) — ropper cannot seed from these
_X86_REX_REGS = frozenset(f'r{i}' for i in range(8, 16))


# ──────────────────────────────────────────────────────────────────────────────
# Subprocess helpers
# ──────────────────────────────────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 45) -> str | None:
    """Run a command, return its stdout as a string, or None on failure/crash."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            return None  # tool crashed or errored — caller will fall back to simulation
        return r.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def _tool_version(tool: str) -> str | None:
    """Return the version string of a tool, or None if not installed."""
    out = _run([tool, '--version'])
    if out:
        for line in out.splitlines():
            line = line.strip()
            if line:
                return line[:80]
    return None


def _parse_gadget_start_addrs(output: str | None, pattern: re.Pattern) -> set[int]:
    """Extract hex start addresses from tool output lines."""
    if not output:
        return set()
    return {int(m.group(1), 16) for m in pattern.finditer(output)}


# ──────────────────────────────────────────────────────────────────────────────
# Map tool addresses → LCSAJ node addresses
# ──────────────────────────────────────────────────────────────────────────────

def _addrs_to_nodes(tool_addrs: set[int], addr_to_node: dict) -> set[int]:
    """
    For each address reported by an external tool, find the LCSAJ node whose
    address range [start, end] contains it. Returns the set of node start addrs.

    External tools report the START address of a gadget. That address may fall
    anywhere inside a LCSAJ block (not necessarily at the block boundary).
    """
    sorted_starts = sorted(addr_to_node.keys())
    result: set[int] = set()
    for addr in tool_addrs:
        # Binary search for the largest block start ≤ addr
        lo, hi = 0, len(sorted_starts) - 1
        best = None
        while lo <= hi:
            mid = (lo + hi) // 2
            if sorted_starts[mid] <= addr:
                best = sorted_starts[mid]
                lo = mid + 1
            else:
                hi = mid - 1
        if best is not None:
            node = addr_to_node[best]
            if best <= addr <= node['end']:
                result.add(best)
    return result


# ──────────────────────────────────────────────────────────────────────────────
# Run real tools
# ──────────────────────────────────────────────────────────────────────────────

def _run_ropper(binary_path: str, addr_to_node: dict) -> tuple[set[int], bool]:
    """
    Run ropper --type all and return (node_start_addrs, simulated=False).
    Returns (set(), True) when ropper is not installed.
    """
    out = _run(['ropper', '--file', binary_path, '--type', 'all', '--nocolor'])
    if out is None:
        return set(), True
    addrs = _parse_gadget_start_addrs(out, _ROPPER_LINE_RE)
    return _addrs_to_nodes(addrs, addr_to_node), False


def _run_ropgadget(binary_path: str, addr_to_node: dict) -> tuple[set[int], bool]:
    """
    Run ROPgadget --all (deeper depth to capture more gadgets) and return
    (node_start_addrs, simulated=False). Returns (set(), True) on failure.
    """
    out = _run(['ROPgadget', '--binary', binary_path, '--all', '--depth', '20'])
    if out is None:
        return set(), True
    addrs = _parse_gadget_start_addrs(out, _ROPGADGET_LINE_RE)
    return _addrs_to_nodes(addrs, addr_to_node), False


def _run_rp_plus(binary_path: str, addr_to_node: dict) -> tuple[set[int], bool]:
    """
    Run rp++ and return (node_start_addrs, simulated=False).
    Tries 'rp++' then 'rp-lin64' (common alternative name).
    Returns (set(), True) if neither is installed.
    """
    for cmd in ('rp++', 'rp-lin64'):
        out = _run([cmd, '--file', binary_path, '--rop', '6'])
        if out is not None:
            addrs = _parse_gadget_start_addrs(out, _RPPLUS_LINE_RE)
            return _addrs_to_nodes(addrs, addr_to_node), False
    return set(), True


# ──────────────────────────────────────────────────────────────────────────────
# Simulate tail sets from graph data (fallback when tools not installed)
# ──────────────────────────────────────────────────────────────────────────────

def _infer_ropper_tails(graph_manager, arch: str) -> set[int]:
    """
    Simulate ropper's tail-seeding behaviour from the LCSAJ graph.

    x86_64 seeds: ret/retn/retf + jmp/call *std_reg (rax–rdi), NOT r8–r15, NOT E8.
    arm64  seeds: ret, br xN, blr xN.
    riscv64 seeds: ret, jr ra, jalr ra.
    """
    tails: set[int] = set()
    for node in graph_manager.nodes:
        last = node['last_insn']
        mnem = last.mnemonic.lower()
        op   = last.op_str.lower()

        if arch == 'x86_64':
            if mnem in ('ret', 'retn', 'retf', 'iret'):
                tails.add(node['start'])
                continue
            if mnem in ('jmp', 'call'):
                # Skip direct calls (E8) — those have direct_call_target
                if 'direct_call_target' in node:
                    continue
                # Skip bare hex address operands (direct jmp/call imm)
                if _HEX_RE.search(op):
                    continue
                # Must be indirect via standard register only
                has_std = any(r in op for r in _X86_STD_REGS)
                has_rex = any(r in op for r in _X86_REX_REGS)
                if has_std and not has_rex:
                    tails.add(node['start'])

        elif arch == 'arm64':
            if mnem in ('ret', 'br', 'blr'):
                tails.add(node['start'])

        elif arch == 'riscv64':
            if mnem == 'ret':
                tails.add(node['start'])
            elif mnem in ('jr', 'jalr', 'c.jr', 'c.jalr') and 'ra' in op:
                tails.add(node['start'])

    return tails


def _infer_ropgadget_tails(graph_manager, arch: str) -> set[int]:
    """
    Simulate ROPgadget's tail-seeding behaviour.

    x86_64: same as ropper but INCLUDES r8–r15 (REX.B) — ROPgadget recognises
    `call r12` as a terminator. However, it does NOT recognise E8 (call rel32).
    arm64 / riscv64: same as ropper.
    """
    tails: set[int] = set()
    for node in graph_manager.nodes:
        last = node['last_insn']
        mnem = last.mnemonic.lower()
        op   = last.op_str.lower()

        if arch == 'x86_64':
            if mnem in ('ret', 'retn', 'retf', 'iret', 'syscall'):
                tails.add(node['start'])
                continue
            if mnem in ('jmp', 'call'):
                if 'direct_call_target' in node:
                    continue  # E8 rel32 — not in ROPgadget's seed table
                if _HEX_RE.search(op):
                    continue
                tails.add(node['start'])  # any indirect call/jmp including r8–r15

        elif arch == 'arm64':
            if mnem in ('ret', 'br', 'blr', 'svc'):
                tails.add(node['start'])

        elif arch == 'riscv64':
            if mnem in ('ret', 'jr', 'jalr', 'c.jr', 'c.jalr'):
                tails.add(node['start'])

    return tails


def _infer_rp_plus_tails(graph_manager, arch: str) -> set[int]:
    """
    Simulate rp++ tail-seeding behaviour.

    x86_64: same as ROPgadget but also includes `int 0x80` (legacy 32-bit
    syscall) and `int3`. Does NOT seed from E8 (direct call rel32).
    arm64:   same as ROPgadget (ret, br, blr, svc).
    riscv64: ret + jr/jalr with ANY register (not just ra) — rp++ is more
             permissive than ropper/ROPgadget on RISC-V indirect jumps.
    """
    tails: set[int] = set()
    for node in graph_manager.nodes:
        last = node['last_insn']
        mnem = last.mnemonic.lower()
        op   = last.op_str.lower()

        if arch == 'x86_64':
            if mnem in ('ret', 'retn', 'retf', 'iret', 'syscall', 'int3'):
                tails.add(node['start'])
                continue
            if mnem == 'int' and '0x80' in op:
                tails.add(node['start'])
                continue
            if mnem in ('jmp', 'call'):
                if 'direct_call_target' in node:
                    continue  # E8 rel32 — not in rp++ seed table
                if _HEX_RE.search(op):
                    continue
                tails.add(node['start'])  # indirect jmp/call, all regs

        elif arch == 'arm64':
            if mnem in ('ret', 'br', 'blr', 'svc'):
                tails.add(node['start'])

        elif arch == 'riscv64':
            # rp++ seeds from any indirect jump, not just 'ra'
            if mnem in ('ret', 'jr', 'jalr', 'c.jr', 'c.jalr'):
                tails.add(node['start'])

    return tails


# ──────────────────────────────────────────────────────────────────────────────
# Build gadget-node sets from tool addresses
# ──────────────────────────────────────────────────────────────────────────────

def _gadget_nodes_from_tails(tail_nodes: set[int], graph_manager) -> set[int]:
    """
    Given a set of tail node addresses, return all nodes reachable backward
    via reverse_graph up to MAX_INSNS instructions (simplified BFS).
    This approximates what ropper/ROPgadget would include in their gadget paths.
    Used only when tools are simulated (not actually run).
    """
    MAX_INSNS = 15
    covered: set[int] = set()
    addr_to_node = graph_manager.addr_to_node

    for tail_addr in tail_nodes:
        if tail_addr not in addr_to_node:
            continue
        queue = [(tail_addr, len(addr_to_node[tail_addr]['insns']))]
        visited: set[int] = {tail_addr}
        covered.add(tail_addr)
        while queue:
            curr_addr, insn_count = queue.pop()
            for pred in graph_manager.reverse_graph.get(curr_addr, []):
                if pred in visited:
                    continue
                pred_node = addr_to_node.get(pred)
                if pred_node is None:
                    continue
                new_count = insn_count + len(pred_node['insns'])
                if new_count > MAX_INSNS:
                    continue
                visited.add(pred)
                covered.add(pred)
                queue.append((pred, new_count))
    return covered


# ──────────────────────────────────────────────────────────────────────────────
# Public API
# ──────────────────────────────────────────────────────────────────────────────

def compute_tool_coverage(
    graph_manager,
    finder,
    binary_path: str,
    arch: str,
    run_real_tools: bool = True,
) -> dict:
    """
    Build per-tool tail and gadget-node coverage maps.

    Returns:
    {
      "tail_sets": {
        "lcsaj":     set[int],
        "ropper":    set[int],
        "ropgadget": set[int],
        "rp_plus":   set[int],
      },
      "gadget_node_sets": {
        "lcsaj":     set[int],   # all nodes in any lcsajdump gadget path
        "ropper":    set[int],
        "ropgadget": set[int],
        "rp_plus":   set[int],
      },
      "simulated":     list[str],
      "tool_versions": { "ropper": str|None, "ropgadget": str|None, "rp_plus": str|None }
    }
    """
    addr_to_node = graph_manager.addr_to_node
    simulated: list[str] = []
    versions: dict = {}

    # ── lcsajdump tails (from finder's gadget results) ──────────────────────
    lcsaj_tail_set: set[int] = set()
    lcsaj_gadget_nodes: set[int] = set()
    for _, data in getattr(finder, 'grouped_gadgets', {}).items():
        path = data['path']
        if path:
            lcsaj_tail_set.add(path[-1])   # last block = tail (BFS direction)
        for addr in path:
            lcsaj_gadget_nodes.add(addr)

    # ── ropper ──────────────────────────────────────────────────────────────
    if run_real_tools:
        versions['ropper'] = _tool_version('ropper')
        ropper_nodes, ropper_sim = _run_ropper(binary_path, addr_to_node)
    else:
        versions['ropper'] = None
        ropper_nodes, ropper_sim = set(), True

    if ropper_sim:
        simulated.append('ropper')
        ropper_tail_set = _infer_ropper_tails(graph_manager, arch)
        ropper_nodes    = _gadget_nodes_from_tails(ropper_tail_set, graph_manager)
    else:
        # Derive ropper tail set from which nodes are in ropper gadgets
        # and have the right terminator type
        ropper_tail_set = {a for a in ropper_nodes
                           if addr_to_node.get(a) is not None
                           and _infer_ropper_tails.__doc__  # always true
                           and a in _infer_ropper_tails(graph_manager, arch)}

    # ── ROPgadget ────────────────────────────────────────────────────────────
    if run_real_tools:
        versions['ropgadget'] = _tool_version('ROPgadget')
        ropgadget_nodes, rg_sim = _run_ropgadget(binary_path, addr_to_node)
    else:
        versions['ropgadget'] = None
        ropgadget_nodes, rg_sim = set(), True

    if rg_sim:
        simulated.append('ropgadget')
        ropgadget_tail_set = _infer_ropgadget_tails(graph_manager, arch)
        ropgadget_nodes    = _gadget_nodes_from_tails(ropgadget_tail_set, graph_manager)
    else:
        ropgadget_tail_set = {a for a in ropgadget_nodes
                              if a in _infer_ropgadget_tails(graph_manager, arch)}

    # ── rp++ ─────────────────────────────────────────────────────────────────
    if run_real_tools:
        versions['rp_plus'] = _tool_version('rp++') or _tool_version('rp-lin64')
        rpplus_nodes, rpplus_sim = _run_rp_plus(binary_path, addr_to_node)
    else:
        versions['rp_plus'] = None
        rpplus_nodes, rpplus_sim = set(), True

    if rpplus_sim:
        simulated.append('rp_plus')
        rpplus_tail_set = _infer_rp_plus_tails(graph_manager, arch)
        rpplus_nodes    = _gadget_nodes_from_tails(rpplus_tail_set, graph_manager)
    else:
        rpplus_tail_set = {a for a in rpplus_nodes
                           if a in _infer_rp_plus_tails(graph_manager, arch)}

    return {
        'tail_sets': {
            'lcsaj':     lcsaj_tail_set,
            'ropper':    ropper_tail_set,
            'ropgadget': ropgadget_tail_set,
            'rp_plus':   rpplus_tail_set,
        },
        'gadget_node_sets': {
            'lcsaj':     lcsaj_gadget_nodes,
            'ropper':    ropper_nodes,
            'ropgadget': ropgadget_nodes,
            'rp_plus':   rpplus_nodes,
        },
        'simulated':     simulated,
        'tool_versions': versions,
    }
