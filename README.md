<div align="center">

<img src="_images/LOGO.png" width="60%" alt="LCSAJdump Logo"/>

# LCSAJdump

### *Universal Graph-Based Framework for Automated Gadget Discovery*

[![Status](https://img.shields.io/badge/status-Universal_Framework-orange?style=for-the-badge)](https://github.com/Chris1sFlaggin/LCSAJdump)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

---

**LCSAJdump** is a static analysis framework designed to discover Return-Oriented Programming (ROP) and Jump-Oriented Programming (JOP) gadgets. Unlike traditional scanners, LCSAJdump is **architecture-agnostic** and employs a graph-based approach to uncover vulnerabilities invisible to common linear tools.

</div>

---

## Why LCSAJdump?

Common ROP scanners use a linear "sliding-window" approach over the binary's executable bytes. This method systematically fails to identify **Shadow Gadgets**: execution chains that traverse non-contiguous memory blocks connected by unconditional jumps or conditional branches.

LCSAJdump overcomes this limitation by reconstructing the **Control-Flow Graph (CFG)** through **LCSAJ (Linear Code Sequence and Jump)** analysis. By modeling the binary as a directed graph of basic blocks, the tool identifies:

1.  **Contiguous Gadgets:** Standard linear sequences terminating in a control-flow transfer.
2.  **Shadow Gadgets (Non-Contiguous):** Complex chains that bypass "bad bytes" (e.g., null bytes) by utilizing instructions that would otherwise be unreachable via linear scanning.

---

## Key Features

* **Multi-Architecture Support:** Native support for RISC-V (64GC) and easily extensible to x86, ARM, and MIPS via modular profiles.
* **Graph-Based Analysis:** Segments the `.text` section into LCSAJ basic blocks and reconstructs flow relationships using `NetworkX`.
* **Rainbow BFS Algorithm:** proprietary backward Breadth-First Search starting from control-flow sinks (`ret`, `jr`, `jalr`) to reconstruct valid execution paths.
* **Heuristic Scoring:** Ranking system that prioritizes gadgets manipulating critical registers (e.g., `ra`, `a0`, `sp`).
* **Pruning Parameters:** Configurable "Darkness" factor to balance analysis depth and performance, preventing infinite loops in cyclic graphs.

---

## Supported Architectures

LCSAJdump is designed to be universal. Currently supported:

* **RISC-V 64-bit (RV64GC):** Full support for compressed 16-bit instructions.
* **Other Architectures:** Can be implemented by defining new profiles in `config.py`.

---

## Installation

### Via Pip (Recommended)

```bash
pip install lcsajdump

```

### From Source (Development)

```bash
git clone [https://github.com/Chris1sFlaggin/LCSAJdump.git](https://github.com/Chris1sFlaggin/LCSAJdump.git)
cd LCSAJdump
pip install -r requirements.txt

```

---

## Usage

LCSAJdump offers a powerful CLI for precise binary analysis:

**Standard Analysis (Default RISC-V):**

```bash
python LCSAJdump.py <path_to_binary>

```

**Advanced Analysis (Specifying Architecture):**

```bash
python LCSAJdump.py -a riscv64 -d 15 -k 100 -l 20 --verbose <path_to_binary>

```

### CLI Options:

* `-a, --arch`: Specify the target architecture (e.g., `riscv64`).
* `-d, --depth`: Maximum search depth (in LCSAJ blocks).
* `-k, --darkness`: Pruning threshold (maximum visits per node) to handle cyclic graphs.
* `-l, --limit`: Limit of gadgets to display in the final report.
* `-v, --verbose`: Detailed output for instruction debugging.

---

## Output Example

```text
❯ lcsajdump testCTFs/rop2/vuln
[*] Analyzing Target: testCTFs/rop2/vuln
[*] Section .text found (Size: 258706 bytes)
[*] Capstone is disassembling...
Disassembling   [████████████████████████] 100.0%
[*] Building LCSAJ Nodes for riscv64...
Building Graph  [████████████████████████] 100.0%
[*] Pruning complete: 0 branches cut.

--- TOP 10 SEQUENTIAL GADGETS ---
0x3049c: c.ldsp ra, 0x98(sp); c.addi16sp sp, 0xa0; c.jr ra
0x109fc: c.ldsp ra, 0x18(sp); c.li a0, 0; c.jr ra

--- TOP 10 JUMP-BASED GADGETS ---
0x2d494: c.mv a0, s6; jal -0x14e74; c.ldsp ra, 0x18(sp); c.jr ra
0x1f6ae: c.mv a1, sp; jal 0x17b24; c.ldsp ra, 0x88(sp); c.jr ra

```

---

## Contributing (Open for Forks!)

The framework is open to new implementations. To add a new architecture:

1. **Fork** the repository.
2. Open `lcsajdump/core/config.py`.
3. Add a new profile to the `ARCH_PROFILES` dictionary, defining jump mnemonics, return mnemonics, and registers for the desired architecture (e.g., x86_64).
4. Submit a **Pull Request**.

---

## License

This project is released under the **MIT** license. See the [LICENSE](https://www.google.com/search?q=LICENSE) file for details.

---

## Project Link
Visit the project web page: [LCSAJdump web page](https://chris1sflaggin.it/LCSAJdump)

---

<div align="center">
Made by <b>Chris1sflaggin</b> as a research project for Automated Gadget Discovery.
</div>
