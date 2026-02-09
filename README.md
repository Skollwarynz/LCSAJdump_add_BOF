# LCSAJdump for RISC-V architecture

## 1. Compile

### 1.1 Download repo

```zsh
❯ git clone https://github.com/chris1sflaggin/LCSAJdump.git
```

### 1.2 Create and activate venv (optional)

```zsh
❯ python -m venv venv
```

```zsh
❯ source venv/bin/activate
```

### 1.3 Download python dependencies

```zsh
❯ pip install -r requirements.txt
```

## 2. Usage

```zsh
❯ python LCSAJdump.py --help 
Usage: LCSAJdump.py [OPTIONS] BINARY_PATH

  RISC-V LCSAJ ROP Finder. Analizza un binario per trovare gadget ROP usando
  l'algoritmo Rainbow BFS.

Options:
  -d, --depth INTEGER      Profondità massima di ricerca (blocchi LCSAJ).
  -k, --darkness INTEGER   Soglia di pruning (Max visite per nodo).
  -l, --limit INTEGER      Numero di gadget da mostrare a video.
  -s, --min-score INTEGER  Punteggio minimo per mostrare un gadget.
  --help                   Show this message and exit.
```

## About

[BEST THEORETICALLY EXPLAINED PAPER](https://github.com/chris1sflaggin/LCSAJdump/PAPER.md)
