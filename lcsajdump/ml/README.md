---
language:
- en
- it
license: mit
tags:
- pwn
- ctf
- rop
- reverse-engineering
- symbolic-execution
- cybersecurity
- angr
- lightgbm
- ranking
datasets:
- custom
metrics:
- ndcg
---

# LCSAJdump Hybrid ML Gadget Ranker

## Model Overview
This repository contains the pre-trained Machine Learning model used by the **[LCSAJdump](https://github.com/chris1sflaggin/LCSAJdump)** ROP/JOP/COP gadget finder. 

The model is a **LightGBM LambdaRank** engine designed to score and sort Return-Oriented Programming (ROP) gadgets extracted from binary executables. It was trained to differentiate between useless instruction sequences and highly valuable, exploit-ready gadgets by combining structural static analysis with **Deep Semantic Features** (extracted via `angr` symbolic execution).

## How it works
Traditional gadget finders (like `ROPgadget` or `ropper`) rely on syntactic heuristics (e.g., "does it end with `ret`?" or "does it pop `rdi`?"). This approach often yields hundreds of false positives, especially in obfuscated binaries or complex architectures like ARM64 and RISC-V.

This LambdaRank model receives a set of 29 features for each gadget, including:
1. **Structural Features:** Extracted by LCSAJdump's RainbowBFS algorithm (e.g., instruction count, presence of internal calls, clobbered registers).
2. **Semantic Features:** Extracted by running the gadget through the `angr` symbolic execution engine. The model mathematically knows if a gadget *actually* performs a stack pivot (`sm_stack_pivot_size`), controls argument registers (`sm_controls_arg_reg`), or performs memory writes (`sm_writes_memory`).

By learning from a ground truth of **real-world CTF exploit scripts**, the model learns to prioritize gadgets that are genuinely useful for building exploit chains, achieving an **NDCG@5 of 0.97+**.

## Architectures Supported
The model is fully architecture-aware and currently supports:
- **x86_64**
- **x86_32**
- **ARM64 (AArch64)**
- **RISC-V (64-bit)**

## Usage in LCSAJdump
This model is deeply integrated into the `LCSAJdump` CLI tool. 
You do not need to download or run this model manually. When you install `LCSAJdump`, the `.pkl` file is bundled in the `lcsajdump/ml/models/` directory.

Simply run the tool against a binary:
```bash
python3 -m lcsajdump.cli /path/to/binary
```
If the model is present, LCSAJdump will automatically activate the **ML re-ranking** engine and output:
`[+] ML re-ranking active (gadget_model.pkl)`

*(To disable the ML engine and fall back to pure static heuristics, use the `--algo` flag).*

## Training Data & Performance
The model was trained on a custom dataset (`gadget_dataset.csv`, ~1700 samples) built by automatically extracting and labeling gadgets used in **published exploit scripts** from major CTF competitions (e.g., DEF CON, LACTF, DiceCTF, ROP Emporium).

**Performance (K-Fold Cross Validation):**
- **NDCG@1:** 0.9833 (The #1 suggested gadget is the absolute best choice in 98% of cases)
- **NDCG@3:** 0.9833
- **NDCG@5:** 0.9749
- **NDCG@10:** 0.9656

*(Compared to pure static heuristics which score ~0.81 on NDCG@10).*

## Feature Importances (SHAP)
The most impactful features learned by the model are:
1. `is_ret_terminated` (Clean execution flow is paramount)
2. `heuristic_score` (Base syntactic score)
3. `frame_size_bytes` (Stack damage minimization)
4. `sm_stack_pivot_size` (Semantic stack control via `angr`)
5. `stack_slots`

## Author
Created by [Chris1sFlaggin](https://chris1sflaggin.it/LCSAJdump/) for the LCSAJdump project.
