<div align="center">

<a href='https://chris1sflaggin.it/LCSAJdump'><img src="_images/LOGO.png" width="60%" alt="LCSAJdump Logo"/></a>

# [LCSAJdump](https://chris1sflaggin.it/LCSAJdump)

[![PyPI Downloads](https://static.pepy.tech/personalized-badge/lcsajdump?period=total&units=INTERNATIONAL_SYSTEM&left_color=BLACK&right_color=GREEN&left_text=downloads)](https://pepy.tech/projects/lcsajdump)

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

* **Multi-Architecture Support:** Native support for RISC-V (64GC), x86-64, and ARM64, easily extendable to other architectures via modular profiles.
* **Graph-Based Analysis:** Segments the `.text` section into LCSAJ basic blocks and reconstructs flow relationships using `NetworkX`.
* **Rainbow BFS Algorithm:** Proprietary backward Breadth-First Search starting from control-flow sinks. Now features an **O(1) Early-Drop Uniqueness Filter** and **Hard-Cap Instruction Limits** to prevent state explosion and ensure ultra-fast analysis even on dense CISC binaries.
* **Architecture-Specific Heuristic Scoring:** Dynamic ranking system that evaluates gadgets based on architecture-specific traits (e.g., heavy length penalties for x86_64/ARM, dynamic bonuses for critical argument registers like `rdi` or `x0`).
* **Pruning Parameters:** Configurable "Darkness" factor to balance analysis depth and performance, preventing infinite loops in cyclic graphs.

---

## Supported Architectures

> (see [Benchmarks](https://chris1sflaggin.it/LCSAJdump#benchmarks)).

LCSAJdump is designed to be universal. Currently supported:

* **RISC-V 64-bit (RV64GC):** Full support for compressed 16-bit instructions.
* **x86-64:** Handles variable-length overlapping instructions. Safely navigates dense graphs without memory explosion.
* **ARM64:** Handles 32-bit instructions and deeply filters out bloated gadgets via strict heuristic penalties.
* **Other Architectures:** Can be easily implemented by defining new profiles in `config.py`.

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

[![LCSAJdump Demo_Help](https://asciinema.org/a/nn9IimXht3nl3ozj.svg)](https://asciinema.org/a/nn9IimXht3nl3ozj)

---

## Output Example

https://asciinema.org/a/n1UDtLoqeX3paHt7

[![LCSAJdump Demo](https://asciinema.org/a/n1UDtLoqeX3paHt7.svg)](https://asciinema.org/a/n1UDtLoqeX3paHt7)

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
