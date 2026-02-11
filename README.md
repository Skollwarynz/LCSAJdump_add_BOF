<div id="top">

<div align="center">

<img src="_images/LOGO.svg" width="60%" style="position: relative; top: 0; right: 0;" alt="Project Logo"/>

# LCSAJdump

<em>LCSAJDump: A Graph-Based Framework for Automated Gadget Discovery in RISC-V Environments.</em>

<img src="https://img.shields.io/badge/status-Thesis_Prototype-orange?style=for-the-badge" alt="Status">
<img src="https://img.shields.io/github/license/chris1sflaggin/wwyl?style=flat-square&logo=opensourceinitiative&logoColor=white&color=FF4B4B" alt="license">

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
    - [Project Index](#project-index)
- [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
    - [Usage](#usage)
    - [Testing](#testing)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

LCSAJdump is a static analysis framework designed to discover Return-Oriented Programming (ROP) and Jump-Oriented Programming (JOP) gadgets within RISC-V binaries.

Traditional ROP scanners typically employ a linear, sliding-window approach over raw executable bytes. While effective for standard instruction sequences, this method fails to identify **Shadow Gadgets**—executable chains that span non-contiguous memory blocks connected by unconditional jumps or conditional branches.

LCSAJdump overcomes this limitation by reconstructing the Control-Flow Graph (CFG) through **Linear Code Sequence and Jump (LCSAJ)** analysis. By modeling the binary as a directed graph of basic blocks, the tool identifies:
1.  **Contiguous Gadgets:** Standard linear sequences terminating in a control-flow transfer.
2.  **Non-Contiguous (Shadow) Gadgets:** Complex chains traversing multiple basic blocks, effectively bypassing "bad bytes" (e.g., null bytes) and utilizing instructions that would otherwise be unreachable by linear scanning.

## Features

* **Comprehensive Architecture Support:** Full support for RISC-V 64-bit (RV64) and Compressed (C) extensions. Handling 16-bit compressed instructions is critical for maximizing gadget coverage in modern RISC-V binaries.
* **Graph-Based Reconstruction:** The engine segments the `.text` section into basic blocks based on control-flow transfers (jumps, branches, returns) and reconstructs edges for both fallthrough and direct targets using NetworkX.
* **Heuristic Backward Search:** Implements a specialized backward Breadth-First Search (BFS) algorithm starting from control-flow sinks (`ret`, `jr`, `jalr`) to reconstruct valid execution paths in reverse.
* **Hybrid Discovery:** Capable of identifying both standard linear gadgets and complex, multi-block trampoline gadgets in a single pass.
* **Scoring and Classification:** Includes a heuristic scoring system that prioritizes gadgets involving critical registers (`ra`, `a0`, `sp`) and classifies results into functional categories (Linear, Trampoline, Conditional, Fallthrough).
* **Optimized Performance:** Features configurable pruning parameters ("Darkness" factor) to limit the search depth and node visitation, balancing analysis speed with coverage depth.

## Project Structure

The repository is organized into modular components responsible for binary loading, graph generation, and algorithmic search.

```text
LCSAJdump/
├── loader.py       # ELF parsing and Capstone disassembly wrapper
├── graph.py        # LCSAJ basic block decomposition and DiGraph construction
├── rainbowBFS.py   # Backward search algorithm, scoring, and classification logic
├── LCSAJdump.py    # Main entry point and CLI argument parsing
└── utils.py        # Helper functions for formatting and logging

```

### Project Index

* **`loader.py`**: Utilizes `pyelftools` to extract executable sections and `Capstone` to disassemble RV64GC instructions into a linear stream.
* **`graph.py`**: Converts the linear instruction stream into a directed graph. Nodes represent basic blocks (LCSAJs), and edges represent control flow (jumps, branches, and fallthroughs).
* **`rainbowBFS.py`**: The core analysis engine. It traverses the reverse graph from leaf nodes (returns) to find executable paths, applying heuristic scoring to filter non-viable chains.
* **`LCSAJdump.py`**: Orchestrates the analysis pipeline, handling user input, parameter tuning, and output generation.

## Getting Started

### Prerequisites

All of them listed in `requirements.txt`:
* Python 3.8 or higher
* `capstone` (Disassembly engine)
* `networkx` (Graph algorithms)
* `pyelftools` (ELF file parsing)

### Installation

Clone the repository and install the required dependencies:

```bash
git clone [https://github.com/Chris1sFlaggin/LCSAJdump.git](https://github.com/Chris1sFlaggin/LCSAJdump.git)
cd LCSAJdump
pip install -r requirements.txt

```

### Usage

**Basic Scan**
Run the tool on a target binary using default parameters:

```bash
python LCSAJdump.py <path_to_binary>

```

**Advanced Configuration**
Users can tune the search depth and pruning thresholds to handle larger binaries or deeper gadget chains:

```bash
python LCSAJdump.py -d 15 -k 100 -l 20 --verbose <path_to_binary>

```

**CLI Options:**

* `-d, --depth`: Maximum search depth (in blocks) for the BFS algorithm.
* `-k, --darkness`: Pruning threshold (maximum visits per node) to prevent infinite loops in cyclic graphs.
* `-l, --limit`: Maximum number of top-ranked gadgets to display.
* `-s, --min-score`: Minimum heuristic score threshold for reporting.
* `-v, --verbose`: Enable detailed output of instruction decoding.

### Testing

To verify the integrity of the graph reconstruction and gadget finding logic, run the unit tests provided in the `tests/` directory:

```bash
python -m pytest unitTest/*
```

---

## Output Example

```text
❯ time python LCSAJdump/LCSAJdump.py testCTFs/rop/vuln 
[*] Analisi Target: testCTFs/rop/vuln
[*] Caricamento binario: testCTFs/rop/vuln
[*] Sezione .text trovata.
    Dimensione: 258236 bytes
    Indirizzo Base: 0x10250

[*] Avvio disassemblaggio con Capstone...
Disassembling   [████████████████████████████████████████████████████████████] 100.0%
[*] Disassemblaggio completato. 89354 istruzioni estratte.

[*] Costruzione Nodi LCSAJ...
Building Graph  [████████████████████████████████████████████████████████████] 100.0%

[*] Configurazione Rainbow: Depth=12, Darkness=30
[*] Pruning effettuato: 0 rami tagliati.

============================================================
--- TOP 10 SEQUENTIAL GADGETS ---
============================================================
0x39ffe: c.ldsp ra, 0x48(sp); c.ldsp a0, 0x38(sp); c.addi16sp sp, 0x50; c.jr ra
0x4078c: c.ldsp a0, 0x20(sp); c.ldsp ra, 0x58(sp); c.addi16sp sp, 0x60; c.jr ra
0x45d2e: c.ld a0, 0x10(a5); c.ldsp ra, 0x38(sp); c.addi16sp sp, 0x40; c.jr ra
0x460b8: c.ldsp ra, 0x38(sp); c.ldsp a0, 0x20(sp); c.addi16sp sp, 0x40; c.jr ra
0x460e6: c.ldsp ra, 0x38(sp); c.ldsp a0, 0x20(sp); c.addi16sp sp, 0x40; c.jr ra
0x4618c: c.ldsp ra, 0x28(sp); c.ldsp a0, 0x10(sp); c.addi16sp sp, 0x30; c.jr ra
0x461b6: c.ldsp ra, 0x28(sp); c.ldsp a0, 0x10(sp); c.addi16sp sp, 0x30; c.jr ra
0x46386: c.ldsp a0, 0(sp); c.ldsp ra, 0x18(sp); c.addi16sp sp, 0x20; c.jr ra
0x4aa1a: c.ldsp a0, 0x18(sp); c.ldsp ra, 0x28(sp); c.addi16sp sp, 0x30; c.jr ra
0x113be: c.ldsp a0, 8(sp); c.ldsp ra, 0x18(sp); c.sw s0, 0x70(a0); c.ldsp s0, 0x10(sp); c.addi16sp sp, 0x20; c.jr ra

============================================================
--- TOP 10 JUMP-BASED GADGETS ---
============================================================
0x4060a: c.ld a0, 0x18(s0); jal -0x27b12; c.ldsp a1, 8(sp); addi a7, zero, 0x87; c.li a0, 2; c.li a2, 0; c.li a3, 8; ecall ; c.ldsp ra, 0x18(sp); c.addi16sp sp, 0x20; c.jr ra
0x46fc0: ld s8, -0x500(s0); ld a0, -0x480(s0); ld a6, -0x4f8(s0); beq a0, s8, 0x10; sd a6, -0x4c8(s0); jal -0x2e4da; c.sd a4, 0x28(a5); c.ldsp ra, 0x78(sp); c.ldsp s8, 0x30(sp); c.addi16sp sp, 0x80; c.jr ra
0x2b9f4: auipc a3, 0x4e; ld a3, 0x504(a3); addi a2, sp, 0x4e0; c.mv a1, a2; c.add a3, tp; c.ld a0, 0(a3); jal 0x13ace; c.lw a4, 0(a5); c.andi a4, -0x11; c.sw a4, 0(a5); c.ldsp ra, 0x18(sp); c.addi16sp sp, 0x20; c.jr ra
0x4146a: ld a0, 8(s10); jal -0x28974; c.mv a0, t3; bltz t3, 0x22e; c.ldsp s0, 0x50(sp); c.ldsp s1, 0x48(sp); c.ldsp s3, 0x38(sp); c.ldsp ra, 0x58(sp); c.ldsp s2, 0x40(sp); c.ldsp s4, 0x30(sp); c.ldsp s5, 0x28(sp); c.addi16sp sp, 0x60; c.jr ra
0x46224: c.addi16sp sp, -0x30; c.sdsp a0, 0(sp); auipc a0, 0x34; ld a0, -0x328(a0); c.sdsp ra, 0x28(sp); c.sdsp s0, 0x20(sp); c.sdsp a1, 8(sp); c.sdsp ra, 0x10(sp); jal -0x16152; c.ldsp ra, 0x18(sp); c.ldsp s0, 0x10(sp); c.li a0, -1; c.addi16sp sp, 0x20; c.jr ra
0x35a06: ld a0, 0x360(s1); c.li a5, -1; beq a0, a5, 8; jal -0x1cf16; c.ld a2, 0x58(s0); c.lw a1, 0x60(s0); auipc a0, 0x34; addi a0, a0, -0x1a; addi s0, s0, 0x80; jal 0x1b864; c.ldsp ra, 0x88(sp); c.ldsp s0, 0x80(sp); c.ldsp s1, 0x78(sp); c.addi16sp sp, 0x90; c.jr ra
0x46366: c.ld a0, 0x10(a0); c.sdsp a5, 8(sp); c.sdsp a4, 0(sp); jal -0x1245a; add a4, a2, a1; c.lw a3, 0(a5); c.sd a2, 0x18(a5); c.sd a4, 8(a5); c.andi a3, -0x11; c.sd a4, 0x10(a5); c.sd a0, 0x90(a5); c.sw a3, 0(a5); c.ldsp ra, 0x28(sp); c.mv a0, a1; c.addi16sp sp, 0x30; c.jr ra
0x1db48: c.ld a0, 8(s0); c.ldsp s0, 0x10(sp); c.ld a1, 8(s1); c.ldsp ra, 0x18(sp); c.ldsp s1, 8(sp); c.addi16sp sp, 0x20; j 0x141fe; c.lw a4, 0(a5); c.ld a3, 8(a5); andi a4, a4, 0x100; c.bnez a4, 0xe; c.ld a5, 0x18(a5); c.lw a0, 0x10(a0); sub a5, a3, a5; c.subw a0, a5; c.jr ra
0x4145e: lw a5, 0(s6); andi a5, a5, 0x40; bnez a5, 0x2c0; ld a0, 8(s10); jal -0x28974; c.mv a0, t3; bltz t3, 0x22e; c.ldsp s0, 0x50(sp); c.ldsp s1, 0x48(sp); c.ldsp s3, 0x38(sp); c.ldsp ra, 0x58(sp); c.ldsp s2, 0x40(sp); c.ldsp s4, 0x30(sp); c.ldsp s5, 0x28(sp); c.addi16sp sp, 0x60; c.jr ra
0x2bd72: c.mv a2, s8; addi a1, zero, 0x20; c.mv a0, s0; jal 0x109e8; slli a0, a4, 5; c.addi a0, 0x10; c.addi a4, 1; c.add a0, a2; c.sd a4, 8(a2); ld a5, 0xa0(gp); c.li a4, 1; c.ldsp ra, 0x18(sp); c.sd a4, 0(a0); c.add a5, a4; sd a5, 0xa0(gp); c.addi16sp sp, 0x20; c.jr ra

[+] Report salvato in: gadgets_found.txt (Trovati 4637 gadget)
python LCSAJdump/LCSAJdump.py testCTFs/rop/vuln  1,67s user 0,27s system 99% cpu 1,936 total
```

---

## Contributing

Contributions to improve the search algorithm or extend architecture support are welcome. Please ensure that any pull requests include relevant test cases and adhere to the existing coding standards.

---

## License

This project is licensed under the MIT License. See the [LICENSE](https://www.google.com/search?q=LICENSE) file for details.
