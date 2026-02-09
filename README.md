# Titolo del Progetto: Analisi Automatizzata di Gadget ROP su Architettura RISC-V mediante Decomposizione LCSAJ e Ricerca Euristica (Rainbow BFS)

---

## 1. Introduzione e Definizione del Problema

L'architettura RISC-V sta guadagnando rapidamente popolarità in ambiti che spaziano dall'embedded al server-side. Con la diffusione dell'hardware, aumenta la necessità di analizzare la sicurezza dei binari compilati per questa architettura. Una delle tecniche di sfruttamento più comuni è la *Return Oriented Programming* (ROP), che consente l'esecuzione di codice arbitrario concatenando frammenti di codice esistente (gadget) terminanti con un'istruzione di ritorno.

Gli strumenti di analisi esistenti (e.g., ROPGadget) utilizzano prevalentemente un approccio di scansione lineare (*linear sweeping*). Tale approccio, sebbene veloce, presenta limitazioni significative: non è in grado di modellare correttamente il flusso di controllo in presenza di salti condizionali o di sequenze di codice non contigue.

Il presente lavoro propone un nuovo strumento di analisi statica che supera tali limiti modellando il binario come un grafo di sequenze lineari e salti (LCSAJ), applicando un algoritmo di ricerca *Breadth-First Search* (BFS) modificato con euristiche di potatura (*pruning*) per identificare catene di gadget complesse ed efficaci.

## 2. Metodologia

### 2.1 Decomposizione LCSAJ

Al fine di superare i limiti della scansione lineare, il binario viene decomposto in blocchi **LCSAJ** (*Linear Code Sequence and Jump*). Un blocco LCSAJ è definito come una sequenza di istruzioni consecutive che termina incondizionatamente con un salto o che può essere interrotta da un flusso di controllo divergente.

Formalmente, dato un insieme di istruzioni , un blocco  è una sottosequenza  tale che:

* Per ogni , l'esecuzione prosegue sequenzialmente da  a .
* L'istruzione  è un'istruzione di salto (condizionato o incondizionato), una chiamata a funzione, o un ritorno (`RET`).

Questa decomposizione permette di isolare le "strutture atomiche" del flusso di esecuzione, includendo anche i percorsi di *fallthrough* (mancato salto) spesso ignorati dagli scanner classici.

### 2.2 Costruzione del Grafo e Mappatura Intra-Block

Il programma viene modellato come un grafo diretto , dove  rappresenta l'insieme dei blocchi LCSAJ.
Una criticità riscontrata nell'analisi dei binari RISC-V (specialmente con estensione *Compressed*) è che un salto può avere come destinazione un indirizzo interno a un blocco esistente, non necessariamente il suo inizio.

Per risolvere questo problema, è stata implementata una strategia di **Intra-Block Mapping**. Definiamo una funzione di mappatura  che associa ogni indirizzo di memoria al blocco  che lo contiene.
Un arco diretto  esiste se:

1. L'ultima istruzione di  è un salto verso un indirizzo  e .
2. L'ultima istruzione di  non è un salto incondizionato e l'indirizzo successivo sequenziale appartiene a  (*fallthrough*).

### 2.3 Algoritmo "Rainbow BFS"

La ricerca dei gadget avviene mediante un algoritmo BFS a ritroso (*backward*), partendo dai nodi "sink" (blocchi terminanti con `RET` o `JALR`). L'algoritmo, denominato **Rainbow BFS**, introduce due concetti chiave per gestire l'esplosione combinatoria tipica dei grafi di controllo complessi:

1. **Stateful Path Exploration (Sfumatura):** A differenza di una BFS standard che marca i nodi come "visitati" globalmente, l'algoritmo mantiene lo stato di visita locale per ogni percorso. Ciò permette di scoprire molteplici gadget che condividono nodi intermedi ma divergono nel flusso logico.
2. **Frequency-Based Pruning (Scurimento):** Per evitare loop infiniti o un consumo eccessivo di memoria su nodi ad alta connettività (hub), viene mantenuto un contatore globale di frequenza  per ogni nodo .

La condizione di arresto per un ramo di ricerca è definita come:



Dove  e  sono soglie configurabili.

## 3. Modello Matematico di Scoring

Dato l'elevato numero di gadget identificati, è necessario un sistema di ranking per filtrare i risultati semanticamente rilevanti per un attaccante. Ogni gadget  (inteso come percorso nel grafo) riceve un punteggio  calcolato come segue:

Dove:

* : Punteggio iniziale ideale.
* : Penalità basata sul numero di blocchi LCSAJ attraversati (la complessità riduce l'affidabilità).
* : Penalità per il numero totale di istruzioni (riduzione degli effetti collaterali).
* : Bonus semantico basato sull'analisi dei registri coinvolti.

Il termine  è definito come:
$$ B_{sem}(g) = \begin{cases}
+50 & \text{se } g \text{ controlla } RA \text{ (Return Address)} \
+40 & \text{se } g \text{ controlla } A0 \dots A7 \text{ (Argument Registers)} \
-30 & \text{se } g \text{ modifica } GP \text{ o } TP \text{ (Registri Critici)}
\end{cases} $$

Questo modello privilegia gadget brevi, puliti e funzionali al concatenamento (ROP Chaining) e all'invocazione di funzioni di sistema.

## 4. Implementazione

Il prototipo è stato sviluppato in Python sfruttando le seguenti librerie:

* **Capstone Engine:** Per il disassemblaggio, configurato con `CS_MODE_RISCV64` e `CS_MODE_RISCVC` per il supporto corretto alle istruzioni compresse a 16-bit.
* **NetworkX:** Per la gestione della struttura dati del grafo.
* **PyElftools:** Per il parsing del formato binario ELF.

## 5. Risultati Sperimentali

Il sistema è stato validato analizzando la libreria standard C (`libc.so.6`) per architettura RISC-V 64-bit.

**Metriche di Analisi:**

* **Dimensione Input:** ~291.000 istruzioni disassemblate.
* **Tempo di Esecuzione:** 5.3 secondi (su macchina standard).
* **Copertura:** 66.492 nodi LCSAJ generati.
* **Gadget Identificati:** 8.867 gadget totali.
* **Pruning:** Con profondità 20 e soglia di saturazione 2, sono stati potati 8 rami ridondanti.

**Analisi Qualitativa:**
I gadget con il punteggio più alto () mostrano sequenze ottimali per il caricamento diretto dei registri  e  dallo stack. Inoltre, l'analisi semantica ha permesso di isolare gadget complessi di **Stack Pivoting** (e.g., `add sp, s0, t0`), essenziali per bypassare le protezioni di memoria moderne, che sarebbero sfuggiti a un'analisi tradizionale.

## 6. Conclusioni

Il lavoro dimostra che l'approccio basato su grafi LCSAJ, combinato con una mappatura precisa delle istruzioni intra-blocco e un algoritmo di ricerca euristica, supera significativamente le tecniche di scansione lineare. Lo strumento sviluppato è in grado di identificare un numero maggiore di gadget funzionali in tempi compatibili con l'utilizzo reale, fornendo una base solida per l'automazione della costruzione di exploit su architettura RISC-V.
