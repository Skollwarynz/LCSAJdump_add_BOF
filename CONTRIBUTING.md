# Contributing to LCSAJdump

Thank you for your interest in contributing to **LCSAJdump**! This guide will help you understand how to extend support to new architectures and how to improve the Machine Learning ranking engine.

---

## Developer Setup

To get started, clone the repository and install the development dependencies (including the ML training tools):

```bash
git clone https://github.com/Chris1sFlaggin/LCSAJdump.git
cd LCSAJdump
pip install -r requirements.txt
pip install -e .
```

---

## 🏗 1. Adding New Architectures (Config)

LCSAJdump is built to be *architecture-agnostic*. All support for new Instruction Set Architectures (ISAs) is handled in `lcsajdump/core/config.py`.

### How to add a profile:
If you want to add support for a new architecture (e.g., MIPS, PowerPC), you need to define a new `ArchProfile` inside the `Config` class.

1. **Define key instructions:** You need to identify which Capstone instructions represent the control-flow "sinks":
   - `jump_ins`: Unconditional jumps (e.g., `jmp`, `b`, `jr`).
   - `ret_ins`: Return instructions (e.g., `ret`, `bx lr`).
   - `call_ins`: Function calls (e.g., `call`, `bl`).

2. **Create the profile in `config.py`:**
```python
"mips": ArchProfile(
    name="mips",
    jump_ins={"j", "jr", "jalr"},
    ret_ins={"jr $ra"},
    call_ins={"jal", "bal"},
    alignment=4,
)
```

> Take a look at others definition to get a better idea

3. **Register the architecture:** Ensure that the loader recognizes the architecture name returned by Capstone/angr.

---

## 🧠 2. Machine Learning Pipeline (ML Training)

The scoring engine relies on a **LightGBM** model. The entire training pipeline is located in the `lcsajdump/ml_study/` directory.

### Step 1: Dataset Generation
To train the model, you need data extracted via symbolic execution.
- Use `build_dataset.py` to analyze a collection of binaries (e.g., CTF binaries or system libraries).
- This script extracts semantic features (stack pivots, register controls) using **angr** and saves them to a `.csv` file.

```bash
python lcsajdump/ml_study/build_dataset.py --binaries ./my_binaries_folder --output dataset.csv
```

### Step 2: Optuna Optimization
Before the final training, we use **Optuna** to find the best hyperparameters (learning rate, tree depth, etc.).
- The optimization scripts are in `lcsajdump/ml_study/optuna/`.
- Run `optuna_unified.py` to start a tuning session:

```bash
python lcsajdump/ml_study/optuna/optuna_unified.py --dataset dataset.csv
```
Once finished, you will get the optimal parameters that minimize the ranking error (NDCG).

### Step 3: Training and Export
Once you have the parameters, use `train_model.py` to generate the final model file.
- The model will be saved as `chainfinder_v4_hybrid.pkl` (or similar).
- **Important:** To make the model usable by the CLI, copy it to the `lcsajdump/ml/models/` directory.

```bash
python lcsajdump/ml_study/train_model.py --dataset dataset.csv --output chainfinder_v4_hybrid.pkl
```

---

## 3. Testing and Validation

Every change to the core engine or the ML model must pass the unit tests to prevent regressions, especially regarding graph calculations and ranking accuracy.

Run the full test suite:
```bash
python unitTest/test.py
```

For architecture-specific tests:
- `python unitTest/x86test.py`
- `python unitTest/armIntegrationTest.py`

---

## Pull Request Guidelines

1. **Documentation:** If you add a new ML feature, update the `README.md` inside the `ml/` folder explaining the newly extracted semantic features.
2. **Code Quality:** Follow the PEP8 standard.
3. **Commits:** Use clear and descriptive commit messages (e.g., `feat(config): add support for MIPS architecture`).

---

Have technical questions about a specific feature of the **Rainbow BFS** algorithm? Feel free to open an Issue or start a discussion thread! 
