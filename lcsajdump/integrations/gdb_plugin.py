"""
lcsajdump GDB plugin — adds the `lcsaj` command to GDB, pwndbg, and GEF.

Load with:
    source /path/to/lcsajdump/integrations/gdb_plugin.py
Or add to ~/.gdbinit:
    python import sys; sys.path.insert(0, '/path/to/LCSAJdump')
    source /path/to/lcsajdump/integrations/gdb_plugin.py
"""

import argparse
import json
import os
import re
import subprocess
import sys

import gdb

# ---------------------------------------------------------------------------
# Ensure lcsajdump is importable by subprocesses.
# GDB may use a different Python than the one that has the package installed.
# We propagate the package root (two levels up from this file) via PYTHONPATH.
# ---------------------------------------------------------------------------
_PLUGIN_DIR   = os.path.dirname(os.path.abspath(__file__))   # integrations/
_PACKAGE_ROOT = os.path.dirname(os.path.dirname(_PLUGIN_DIR))  # LCSAJdump/

def _make_env():
    """Return os.environ with PYTHONPATH prepended to include the package root."""
    env = os.environ.copy()
    existing = env.get('PYTHONPATH', '')
    env['PYTHONPATH'] = (_PACKAGE_ROOT + os.pathsep + existing).rstrip(os.pathsep)
    return env

# Also insert into the current process path so any direct imports work.
if _PACKAGE_ROOT not in sys.path:
    sys.path.insert(0, _PACKAGE_ROOT)

# ---------------------------------------------------------------------------
# ANSI helpers (gdb.write honours ANSI on most terminals)
# ---------------------------------------------------------------------------

_GREEN  = '\033[32m'
_YELLOW = '\033[33m'
_GRAY   = '\033[90m'
_BOLD   = '\033[1m'
_CYAN   = '\033[36m'
_RESET  = '\033[0m'


def _g(text):   return _GREEN  + text + _RESET
def _y(text):   return _YELLOW + text + _RESET
def _gr(text):  return _GRAY   + text + _RESET
def _b(text):   return _BOLD   + text + _RESET
def _c(text):   return _CYAN   + text + _RESET


# ---------------------------------------------------------------------------
# Binary auto-detection
# ---------------------------------------------------------------------------

def _autodetect_binary():
    """Try to find the target binary from the current GDB session."""
    # 1) /proc/<pid>/exe if a process is attached
    try:
        pid = gdb.selected_inferior().pid
        if pid and pid != 0:
            exe = os.readlink(f'/proc/{pid}/exe')
            if exe and os.path.isfile(exe):
                return exe
    except Exception:
        pass

    # 2) Parse 'info files' output
    try:
        info = gdb.execute('info files', to_string=True)
        # Look for lines like:  Local exec file: `...'  or  `...' (exec)
        for pattern in [
            r"Local exec file:\s*[`'\"]?([^`'\"\n]+)[`'\"]?",
            r"[`'\"]([^`'\"]+)[`'\"]\s*,\s*file type",
        ]:
            m = re.search(pattern, info)
            if m:
                path = m.group(1).strip()
                if os.path.isfile(path):
                    return path
    except Exception:
        pass

    return None


# ---------------------------------------------------------------------------
# Argument parser (non-exiting on error — raises instead)
# ---------------------------------------------------------------------------

class _NonExitParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError(f'argument error: {message}')

    def exit(self, status=0, message=None):
        raise ValueError(message or '')


def _make_parser():
    p = _NonExitParser(
        prog='lcsaj',
        description='LCSAJ gadget finder inside GDB',
        add_help=True,
    )
    p.add_argument('binary', nargs='?', default=None,
                   help='Path to binary (auto-detected if omitted)')
    p.add_argument('-l', '--limit',        type=int, default=10,
                   help='Number of gadgets to display (default 10)')
    p.add_argument('-b', '--bad-chars',    type=str, default='',
                   help='Hex bytes to exclude from addresses')
    p.add_argument('-d', '--depth',        type=int, default=20,
                   help='Max search depth (LCSAJ blocks)')
    p.add_argument('-k', '--darkness',     type=int, default=5,
                   help='Pruning threshold')
    p.add_argument('-i', '--instructions', type=int, default=15,
                   help='Max instructions per gadget node')
    p.add_argument('-al', '--algo',          action='store_true',
                         help='Use strictly algorithmic ranking (bypass ML)')
    p.add_argument('--all-exec',           action='store_true',
                   help='Analyse all executable sections')
    p.add_argument('--find',               type=str, default=None,
                   help='Filter gadgets whose instructions contain this pattern')
    p.add_argument('--arch', type=str, default='auto',
                   help='Architecture override (auto, x86_64, arm64, riscv64)')
    p.add_argument('--from-json', type=str, default=None, dest='from_json',
                   help='Load gadgets from pre-generated JSON file (skips analysis)')
    return p


# ---------------------------------------------------------------------------
# CLI invocation + JSON parsing
# ---------------------------------------------------------------------------

def _find_lcsajdump_executable():
    """
    Locate the lcsajdump executable.

    Preference order:
      1. 'lcsajdump' on PATH (covers pyenv shims, pipx installs, venvs)
      2. '<package_root>/lcsajdump/cli.py' invoked via sys.executable
         (development / editable install fallback)
    """
    import shutil
    exe = shutil.which('lcsajdump')
    if exe:
        return [exe]
    # fallback: invoke the module directly with GDB's own Python
    return [sys.executable, '-m', 'lcsajdump.cli']


def _run_lcsajdump(binary, args):
    """Run lcsajdump CLI and return parsed JSON dict."""
    cmd = _find_lcsajdump_executable() + [
        binary,
        '--json',
        '--limit', '999999',
        '--depth', str(args.depth),
        '--darkness', str(args.darkness),
        '--instructions', str(args.instructions),
    ]
    if args.arch and args.arch != 'auto':
        cmd += ['--arch', args.arch]
    if args.bad_chars:
        cmd += ['--bad-chars', args.bad_chars]
    if args.all_exec:
        cmd += ['--all-exec']
    if args.algo:
        cmd += ['--algo']

    result = subprocess.run(cmd, capture_output=True, text=True, env=_make_env())
    if result.returncode != 0:
        raise RuntimeError(
            f'lcsajdump CLI exited {result.returncode}:\n{result.stderr.strip()}'
        )

    stdout = result.stdout
    start = stdout.find('{')
    if start == -1:
        raise RuntimeError(f'No JSON found in lcsajdump output:\n{stdout[:300]}')

    return json.loads(stdout[start:])


# ---------------------------------------------------------------------------
# Gadget text helpers
# ---------------------------------------------------------------------------

def _insn_text(instructions):
    """Return a single-line representation of the instruction list."""
    parts = []
    for i in instructions:
        mnem = i.get('mnemonic', '')
        ops  = i.get('op_str', '')
        parts.append((mnem + ' ' + ops).strip())
    return '; '.join(parts)


def _highlight(text, pattern):
    """Bold-highlight every occurrence of pattern (case-insensitive) in text."""
    if not pattern:
        return text
    return re.sub(
        re.escape(pattern),
        lambda m: _b(m.group(0)),
        text,
        flags=re.IGNORECASE,
    )


def _gadget_matches(gadget, pattern):
    """Return True if the gadget's instruction text contains pattern."""
    if not pattern:
        return True
    text = _insn_text(gadget.get('instructions', []))
    return pattern.lower() in text.lower()


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

def _w(text):
    """Write to GDB output, appending newline."""
    gdb.write(text + '\n')


def _display_gadget(entry, pattern=None, idx=None):
    """Pretty-print a single gadget entry."""
    addr   = entry.get('primary_address', '???')
    tag    = entry.get('tag', '')
    score  = entry.get('score', 0)
    insns  = entry.get('instructions', [])
    dups   = entry.get('duplicate_addresses', [])

    text = _insn_text(insns)
    if pattern:
        text = _highlight(text, pattern)

    prefix = f'  [{idx}] ' if idx is not None else '  '
    addr_str   = _y(f'{addr}')
    tag_str    = _gr(f'[{tag}]')
    score_str  = _gr(f'score={score}')

    _w(f'{prefix}{addr_str}  {text}  {tag_str} {score_str}')

    if dups:
        dup_str = ', '.join(dups)
        _w(_gr(f'       also at: {dup_str}'))


# ---------------------------------------------------------------------------
# Main GDB command
# ---------------------------------------------------------------------------

class LCSAJCommand(gdb.Command):
    """LCSAJ gadget finder — run `lcsaj --help` for usage."""

    def __init__(self):
        super().__init__('lcsaj', gdb.COMMAND_USER)

    def invoke(self, arg_str, from_tty):
        parser = _make_parser()

        # Split the raw arg string the same way a shell would
        try:
            import shlex
            argv = shlex.split(arg_str)
        except ValueError as e:
            gdb.write(f'[lcsaj] Error parsing arguments: {e}\n')
            return

        try:
            args = parser.parse_args(argv)
        except ValueError as e:
            gdb.write(f'[lcsaj] {e}\n')
            return
        except SystemExit:
            # argparse --help triggers SystemExit(0); message already printed
            return

        # --- handle JSON loading ---
        if args.from_json:
            json_path = args.from_json
            if not os.path.isfile(json_path):
                gdb.write(f'[lcsaj] JSON file not found: {json_path}\n')
                return
            gdb.write(_gr(f'[lcsaj] Loading gadgets from {json_path} ...\n'))
            try:
                with open(json_path, 'r') as f:
                    data = json.load(f)
            except Exception as e:
                gdb.write(f'[lcsaj] Error loading JSON: {e}\n')
                return
        else:
            # --- resolve binary ---
            binary = args.binary
            if not binary:
                binary = _autodetect_binary()
            if not binary:
                gdb.write(
                    '[lcsaj] Could not auto-detect binary. '
                    'Provide it explicitly: lcsaj /path/to/binary\n'
                )
                return
            gdb.write(_gr(f'[lcsaj] Auto-detected binary: {binary}\n'))

            if not os.path.isfile(binary):
                gdb.write(f'[lcsaj] Binary not found: {binary}\n')
                return

            # --- run analysis ---
            gdb.write(_gr(f'[lcsaj] Analysing {binary} ...\n'))
            try:
                data = _run_lcsajdump(binary, args)
            except RuntimeError as e:
                gdb.write(f'[lcsaj] Error: {e}\n')
                return

        sequential  = data.get('sequential', [])
        jump_based  = data.get('jump_based', [])
        find_pat    = args.find
        limit       = args.limit

        # --- filter ---
        if find_pat:
            sequential = [g for g in sequential if _gadget_matches(g, find_pat)]
            jump_based = [g for g in jump_based  if _gadget_matches(g, find_pat)]

        # --- header ---
        _w('')
        _w(_g(_b(f'  LCSAJ Gadgets — {os.path.basename(binary)}')))
        if find_pat:
            _w(_gr(f'  Filter: "{find_pat}"'))
        _w('')

        total_shown = 0

        # --- sequential section ---
        seq_display = sequential[:limit]
        _w(_b(f'  Sequential gadgets ({len(sequential)} found, showing {len(seq_display)}):'))
        _w(_gr('  ' + '-' * 60))
        if seq_display:
            for idx, entry in enumerate(seq_display, start=1):
                _display_gadget(entry, pattern=find_pat, idx=idx)
        else:
            _w(_gr('  (none)'))
        total_shown += len(seq_display)
        _w('')

        # --- jump-based section ---
        jmp_display = jump_based[:limit]
        _w(_b(f'  Jump-based gadgets ({len(jump_based)} found, showing {len(jmp_display)}):'))
        _w(_gr('  ' + '-' * 60))
        if jmp_display:
            for idx, entry in enumerate(jmp_display, start=1):
                _display_gadget(entry, pattern=find_pat, idx=idx)
        else:
            _w(_gr('  (none)'))
        total_shown += len(jmp_display)
        _w('')

        # --- footer ---
        total_available = len(sequential) + len(jump_based)
        _w(_gr(f' Showing {total_shown} of {total_available} gadgets.'))
        if args.from_json:
            _w(_gr(f' Source: {args.from_json}'))
            _w(_gr(f' Tip: use -l N to show more, --find PATTERN to filter.'))
        else:
            _w(_gr(f' Tip: use -l N to show more, --find PATTERN to filter.'))
            _w(_gr(f' Save results: lcsajdump {binary} --json --output gadgets.json'))
        _w('')

    def complete(self, text, word):
        return gdb.COMPLETE_FILENAME


# ---------------------------------------------------------------------------
# Register command
# ---------------------------------------------------------------------------

LCSAJCommand()
gdb.write('[lcsaj] Plugin loaded.\n')
