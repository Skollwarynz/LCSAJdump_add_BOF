# 🌈 RISC-V LCSAJ ROP Finder (Rainbow Search)

Questo tool è un estrattore avanzato di gadget **ROP (Return Oriented Programming)** progettato specificamente per l'architettura **RISC-V**. A differenza dei tool standard che utilizzano scansioni lineari, questo software modella il binario come un grafo di sequenze **LCSAJ (Linear Code Sequence and Jump)** per identificare catene di esecuzione complesse e non contigue.

---

### 🏛️ Architettura e Logica Core

Il tool trasforma un binario ELF in una lista di "armi" (gadget) classificate per utilità semantica attraverso quattro fasi:

1. **Loader (Capstone + Pyelftools):** Estrae la sezione `.text` e disassembla le istruzioni. Supporta nativamente l'estensione **Compressed (C)** di RISC-V, raddoppiando la densità dei gadget permettendo l'allineamento a 2-byte.
2. **LCSAJ Decomposer:** Invece di singole istruzioni, il tool lavora su blocchi logici che terminano con un'istruzione di salto o ritorno.
3. **Graph Builder (Reverse CFG):** Costruisce una mappa inversa delle connessioni tra i blocchi, risolvendo i salti diretti e i fallthrough.
4. **Rainbow BFS Finder:** Un algoritmo di ricerca a ritroso che esplora i percorsi dai "sink" (le istruzioni `RET`) verso l'alto.

---

### 🧠 Problemi Riscontrati e Soluzioni (Timeline)

Durante lo sviluppo abbiamo affrontato e risolto sfide critiche che rendono questo tool superiore a una semplice implementazione BFS:

#### 1. Il Problema del "Vibecoding" (Cecità Logica)

* **Problema:** Gli scanner lineari ignorano i salti condizionali. Se un gadget utile è preceduto da un `BEQ` che non viene preso, lo scanner lineare lo perde.
* **Soluzione:** Utilizzo dei blocchi **LCSAJ**. Il tool vede le "strade" possibili nel grafo, catturando sequenze che attraversano i confini dei blocchi base.

#### 2. L'Esplosione Combinatoria (Nodi Hub)

* **Problema:** In binari grandi come la `libc`, alcune funzioni comuni vengono chiamate da migliaia di punti, mandando la memoria in crash (state space explosion).
* **Soluzione:** **Frequency-Based Pruning (Rainbow Pruning)**. Ogni nodo ha un contatore di "oscurità". Se un blocco viene attraversato troppe volte, l'algoritmo lo "scurisce" e taglia il ramo, preservando la RAM e la velocità.

#### 3. Il "Diamond Problem" (Perdita di Percorsi)

* **Problema:** Una BFS classica con colori globali scarta i nodi già visitati, perdendo gadget validi che condividono un blocco comune.
* **Soluzione:** **Stateful Path Exploration**. Ogni "raggio di luce" (percorso) porta con sé la propria storia locale, permettendo al tool di trovare più "sfumature" (percorsi diversi) che passano per lo stesso nodo.

#### 4. La Severità del Grafo (Archi Mancanti)

* **Problema:** Inizialmente il grafo collegava solo i salti che puntavano all'inizio di un blocco. Molti salti però finiscono "nel mezzo" di un blocco LCSAJ.
* **Soluzione:** **Intra-Block Mapping**. Abbiamo implementato una mappa `instruction-to-block` che permette di collegare un salto a qualunque punto del blocco di appartenenza, aumentando drasticamente il numero di archi mappati (da ~1.400 a ~8.800+ gadget trovati).

---

### 📊 Performance e Risultati (Real-World Test)

L'ultima analisi eseguita sulla **`libc.so.6` (RISC-V 64-bit)** dimostra l'efficienza del sistema:

| Metrica | Risultato |
| --- | --- |
| **Istruzioni analizzate** | ~291.793 |
| **Nodi LCSAJ generati** | 66.492 |
| **Gadget identificati** | **8.867** |
| **Tempo di esecuzione** | **~5.3 secondi** |
| **Efficacia CPU** | 99% |

---

### 🏆 Sistema di Scoring Semantico

Per gestire migliaia di risultati, il tool utilizza una formula di ranking per isolare i gadget di "Serie A":

* **Bonus Chaining (+50):** Assegnato se il gadget controlla il registro `ra` (permette di concatenare altri gadget).
* **Bonus Argument (+40):** Assegnato se il gadget carica dati in `a0`, `a1`, etc. (fondamentale per chiamare `system()`).
* **Penalty Noise:** Riduce il punteggio per ogni istruzione extra che "sporca" l'esecuzione.

---

### 🚀 Come Utilizzarlo

1. Assicurati di avere le dipendenze: `pip install capstone pyelftools networkx click`.
2. Lancia l'analisi:
```bash
python main.py /path/to/riscv/binary

```


3. I risultati verranno mostrati a video (Top 10) e salvati integralmente in `gadgets_found.txt`.

---

**Sviluppato per:** Tesi di Laurea - Analisi della Code Reuse Vulnerability su Architetture RISC-V.

