# Methodological and Implementational Evolution

The development of the **LCSAJdump** framework was driven by a rigorous analysis of the intrinsic limitations of traditional linear scanners when applied to the RISC-V architecture. The transition from a naive sequential approach to a sophisticated **Graph-Based Analysis** was not immediate; rather, it proceeded through four distinct phases of theoretical refinement and engineering optimization. This section chronicles the evolution of the framework, highlighting for each iteration the formal problem encountered and the algorithmic solution adopted.

### 1. Phase I: The Limitations of Linear Scanning ("The Linear Trap")

The initial iteration (v1) attempted to replicate the deterministic approach of standard tools (e.g., *ROPgadget*) by performing a sequential scan of the `.text` segment. However, the RISC-V architecture introduces complexities absent in fixed-length or purely CISC architectures:

1.  **Variable Length Encoding:** The coexistence of 32-bit and 16-bit instructions (Compressed extension, *C*) renders instruction boundaries ambiguous without contextual disassembly.
2.  **Relative Addressing:** The extensive use of Program Counter-relative jumps ($PC \pm offset$) for local control flow.

The linear approach proved ineffective in tracking non-contiguous control flow. Conditional gadgets (based on `beq`, `bne` branches) and *fallthrough* paths were analyzed as disjoint byte sequences, severing the logical relationship between the jump instruction and its destination. This resulted in "algorithmic blindness" toward **Shadow Gadgets**—valid but non-contiguous instruction sequences reachable only through control transfers that linear scanning could not resolve.

### 2. Phase II: LCSAJ Formalization and Topological Disconnection

To overcome the limitations of v1, version v2 introduced the decomposition of code into **LCSAJ** (Linear Code Sequence and Jump). The object code was modeled as a directed graph $G = (V, E)$, where each node $V$ represents a Basic Block (BB) terminating in a jump or return instruction. The algorithm constructed a Reverse Graph ($G_{rev}$) to enable **Backward Traversal** starting from "Sink" nodes (`ret`, `jr`, `jalr`).

**Critical Flaw ("The Disconnected Graph"):**
The initial implementation imposed an overly stringent adjacency constraint. An edge $E_{i,j}$ was created between a source block $B_i$ and a destination block $B_j$ if and only if the jump target address in $B_i$ matched the exact **Leader** (start address) of $B_j$:

$$Target(B_i) \equiv StartAddress(B_j)$$

This condition proved erroneous for the RISC-V ISA, where jumps frequently land within pre-existing blocks (particularly due to compressed instruction alignment). Consequently, the graph remained sparse and fragmented. Analysis of the standard `libc` library revealed a *Pruning* counter of 0, indicating a total absence of complex paths. The system identified only ~1,400 trivial gadgets, failing to reconstruct the true topology of the control flow.

### 3. Phase III: Intra-Block Mapping and Densification ("The Web")

The methodological breakthrough in v3 was the introduction of **Granular Intra-Block Mapping**. The constraint requiring jumps to target only block leaders was removed. A global mapping function $M: \text{Addr} \rightarrow \text{BlockID}$ was defined, such that every individual instruction—not just the leader—was indexed and associated with its containing block.

The adjacency condition was relaxed to allow **Lateral Entry**:

$$\exists B_j : Target(B_i) \in [StartAddress(B_j), EndAddress(B_j)] \implies E_{i,j} \in G$$

This modification allowed the graph to model jumps into the middle of instruction sequences, transforming the topology from a series of disjoint chains into a densely connected structure ("The Web").

**Result:** Applying this model to `libc` increased the identified gadgets from ~1,400 to over **8,800**. Complex gadgets, consisting of conditional jumps followed by return instructions located in physically distant blocks, emerged, validating the hypothesis that a significant portion of the attack surface had been invisible to v2.

### 4. Phase IV: Heuristic Search and Semantic Ranking (Current State)

With the exponential increase in graph complexity, the problem of **State Space Explosion** arose. The graph traversal generated a combinatorial number of potential paths, making the analysis of large binaries computationally intractable. Version v4 introduced mechanisms to balance exhaustiveness with performance.

**Rainbow BFS Algorithm:**
A modified *Breadth-First Search* ("Rainbow BFS") was implemented to manage path state. To mitigate combinatorial explosion, a **Frequency-Based Pruning** factor ($K_{dark}$, or "Darkness") was introduced. Given a node $v$, if the visitation count $N(v)$ during the current exploration exceeds the threshold $K_{dark}$, the branch is pruned:

$$N(v) > K_{dark} \implies \text{Prune}(Path)$$

This mechanism preserves CPU/RAM resources by preventing infinite loops or redundant traversals of high-connectivity "hub" nodes, without sacrificing the discovery of significant gadgets.

**Semantic Scoring:**
To qualify the results, a heuristic ranking system was developed based on exploit utility. Each gadget is assigned a score $S$, calculated as a weighted sum of its properties:

$$S_{gadget} = \sum (w_{reg} \cdot \mathbb{I}_{reg} + w_{len} \cdot L^{-1} + w_{type})$$

Control of the Program Counter ($RA$) and the first function argument ($A0$) are assigned maximum weights (+50, +40), while chain length ($L$) introduces a penalty.

**Final Outcome:**
The current v4 implementation is capable of analyzing the entire `libc` (~300,000 instructions) in approximately **5.3 seconds**, identifying critical gadgets such as indirect *Stack Pivots*. The architecture also supports asynchronous monitoring of I/O-bound (loading) and CPU-bound (graph construction) phases, ensuring optimal responsiveness.
