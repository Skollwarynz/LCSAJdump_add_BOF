# LCSAJdump Integrations

This directory contains integration modules that connect LCSAJdump with popular reverse engineering and exploitation tools.

## Available Integrations

### 1. pwntools Helper (`pwntools_helper.py`)

A Python API that provides semantic gadget discovery for CTF exploit development. Import `LCSAJGadgets` to search, filter, and chain gadgets using high-level methods.

#### Installation

```bash
# Automatic installation (recommended)
./install_integrations.sh --pwntools

# Manual installation
cd /path/to/lcsajdump
pip install -e .
```

#### Usage

```python
from pwn import *
from lcsajdump.integrations.pwntools_helper import LCSAJGadgets

# Analyze a binary (auto-detects architecture)
gadgets = LCSAJGadgets('./challenge')

# Search for specific gadgets
pop_rdi = gadgets.find('pop rdi')[0]
syscall = gadgets.syscall()[0]

# Filter by semantic category
pivots = gadgets.pivot_gadgets()          # Stack pivot gadgets
zero_rax = gadgets.zero_register('rax')   # Zeroing gadgets

# Chain gadgets
chain = gadgets.find_chain(
    start=gadgets.best('pop rdi'),
    end=gadgets.best('syscall'),
    max_depth=5
)

# Load from pre-generated JSON (faster)
gadgets = LCSAJGadgets.from_json('gadgets.json')
```

#### API Overview

**Search Methods:**
- `find(pattern)` — Substring match on instruction text
- `best(pattern)` — Highest-scoring gadget matching pattern
- `address_in_range(low, high)` — Filter by address range

**Semantic Filters:**
- `pop_chain(*regs)` — Pop sequence from stack
- `sets_register(reg)` — Gadgets that write to register
- `loads_from_stack(reg)` — Pop/ldr from stack
- `zero_register(reg)` — Zeroing gadgets (xor, mov #0)
- `reg_move(src, dst)` — Register-to-register copies
- `write_what_where(what, where)` — Memory writes
- `memory_read(src, dest=None)` — Memory reads
- `call_reg(reg=None)` — Indirect calls via register
- `syscall()` — System call gadgets (syscall/svc/ecall)
- `pivot_gadgets()` — Stack pivot gadgets

**Arithmetic & Logic:**
- `add_register(dst, src=None)` — Addition gadgets
- `sub_register(dst, src=None)` — Subtraction gadgets
- `or_register(dst, src=None)` — OR gadgets
- `and_register(dst, src=None)` — AND gadgets
- `xor_register(dst, src=None)` — XOR gadgets
- `shift_register(dst, direction=None, amount=None)` — Shift/rotate
- `set_immediate(dst, value=None)` — Constant loading
- `stack_delta(n)` — Specific stack adjustment

**Chain Planning:**
- `find_chain(start, end, max_depth=5)` — BFS path finding
- `trampolines(mnem=None, pattern=None)` — JOP dispatchers
- `no_clobber(*regs)` — Preserve register state

**Iteration:**
- `all()` — All gadgets
- `sequential()` — ret-terminated gadgets
- `jump_based()` — JOP-style gadgets
- `by_tag(tag)` — Filter by tag

**Gadget Properties:**
- `gadget.address` — Primary address
- `gadget.score` — ML ranking score
- `gadget.instructions` — Instruction list
- `gadget.is_trampoline` — Indirect jump/call tail
- `gadget.trampoline_target` — Dispatch register/address
- `gadget.clobbered_registers()` — Written registers
- `gadget.chains_to(other)` — Chainability check

---

### 2. GDB Plugin (`gdb_plugin.py`)

A GDB command-line interface that brings LCSAJdump analysis directly into your debugger session. Works with GDB, pwndbg, and GEF.

#### Installation

Add to your `~/.gdbinit`:

```gdb
# Method 1: Direct source
source /path/to/lcsajdump/lcsajdump/integrations/gdb_plugin.py

# Method 2: Python path
python import sys; sys.path.insert(0, '/path/to/LCSAJdump')
source /path/to/lcsajdump/lcsajdump/integrations/gdb_plugin.py
```

Or use the install script:
```bash
./install_integrations.sh --gdb
```

#### Usage

```gdb
# Analyze current binary
(gdb) lcsaj

# Find specific gadgets
(gdb) lcsaj --find "pop rdi"
(gdb) lcsaj --find "syscall" --limit 10

# Filter by type
(gdb) lcsaj --type JOP
(gdb) lcsaj --type lcsaj

# Control depth and coverage
(gdb) lcsaj --depth 15 --darkness 3 --all-exec

# Auto-detect binary from inferior
(gdb) lcsaj --limit 20 --all-exec
```

#### Commands

| Command | Description |
|---------|-------------|
| `lcsaj [binary]` | Analyze binary (auto-detects if omitted) |
| `lcsaj --find "pattern"` | Search for gadgets matching pattern |
| `lcsaj --type <tag>` | Filter by tag (JOP, lcsaj, etc.) |
| `lcsaj -l <n>` / `--limit <n>` | Limit results (default: 30) |
| `lcsaj -d <n>` / `--depth <n>` | Max blocks per path (default: 20) |
| `lcsaj --darkness <n>` | Node visit ceiling (default: 5) |
| `lcsaj --all-exec` | Include all executable sections |

---

## Architecture Support

All integrations support:
- **x86-64** — Intel/AMD 64-bit
- **ARM64** — AArch64 (including compact instructions)
- **RISC-V64** — RV64GC

## Full Documentation

- **pwntools Integration**: https://chris1sflaggin.github.io/LCSAJdump/pwntools/
- **GDB Plugin**: https://chris1sflaggin.github.io/LCSAJdump/gdb/
- **Main Project**: https://chris1sflaggin.github.io/LCSAJdump/

## Contributing

To add a new integration:

1. Create a new Python file in this directory
2. Implement the integration following the patterns in existing files
3. Update this README with usage instructions
4. Submit a PR with tests if possible

## License

Same as the main LCSAJdump project (MIT License).
