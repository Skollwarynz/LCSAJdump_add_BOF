# LCSAJdump for RISC-V architecture

---

## 1. Introduzione

L'architettura RISC-V sta vivendo una rapida diffusione in ambiti critici, spaziando dai sistemi embedded ai server ad alte prestazioni. Parallelamente, la complessità degli exploit moderni richiede strumenti di analisi di sicurezza sempre più sofisticati. La tecnica ROP (*Return Oriented Programming*) rappresenta da sempre una delle minacce più pervasive, permettendo l'esecuzione di codice arbitrario concatenando frammenti di codice esistente ("gadget") che terminano con un'istruzione di ritorno, aggirando così le protezioni di memoria come NX (No-Execute).

Gli attuali strumenti di analisi statica (e.g., [Ropper](https://github.com/sashs/Ropper.git), [ROPGadget](https://github.com/JonathanSalwan/ROPgadget.git)) si basano prevalentemente sulla *scansione lineare* del segmento di codice eseguibile. Questo approccio, sebbene efficiente in termini di tempo computazionale, fallisce nell'identificare gadget complessi che includono salti condizionali o flussi di esecuzione non contigui.

Questo lavoro propone un nuovo approccio basato sulla decomposizione del binario in blocchi **LCSAJ** (*Linear Code Sequence and Jump*). Tale metodo permette di modellare il programma come un grafo diretto e di applicare algoritmi di ricerca avanzati per identificare catene di esecuzione "nascoste", altrimenti invisibili agli scanner tradizionali.

## 2. Metodologia

### 2.1 Decomposizione LCSAJ
Per superare i limiti della scansione lineare, il codice disassemblato viene segmentato in blocchi atomici denominati LCSAJ.
Un blocco LCSAJ è definito come una sequenza di istruzioni che viene eseguita linearmente e termina incondizionatamente (es. salto diretto, ritorno) o potenzialmente (es. salto condizionato, chiamata a funzione).

Questa decomposizione permette di catturare due flussi distinti per ogni blocco:
1.  Il ramo di salto (*taken branch*).
2.  Il ramo di continuazione sequenziale (*fallthrough*).
Ciò crea una mappa completa dei flussi di controllo possibili, inclusi quelli che attraversano "bivi" condizionali.

### 2.2 Costruzione del Grafo e Mappatura Intra-Block
Il binario viene modellato come un grafo diretto $G = (V, E)$, dove:
* $V$ è l'insieme dei nodi, corrispondenti ai blocchi LCSAJ identificati.
* $E$ è l'insieme degli archi, che rappresentano i trasferimenti di controllo tra blocchi.

Una criticità specifica dell'architettura RISC-V (in particolare con l'estensione *Compressed* a 16-bit) è la possibilità che un'istruzione di salto abbia come destinazione un indirizzo intermedio all'interno di un blocco esistente, e non necessariamente il suo inizio (Leader). I metodi tradizionali che mappano solo i Leader perdono queste connessioni.

Per risolvere questo problema, è stata implementata una strategia di **Intra-Block Mapping**: una funzione di mappatura $M(addr) \rightarrow B_k$ associa ogni singolo indirizzo di istruzione al blocco $B_k$ che la contiene. Questo permette la creazione di archi nel grafo anche verso destinazioni non allineate all'inizio del blocco, aumentando drasticamente la densità delle connessioni.

### 2.3 Algoritmo di Ricerca "Rainbow BFS"
L'esplorazione del grafo avviene tramite un algoritmo *Breadth-First Search* (BFS) a ritroso (*backward slicing*), partendo dalle istruzioni di ritorno (Sink).
Per gestire l'esplosione combinatoria dei percorsi in binari complessi (come `libc`), l'algoritmo implementa due euristiche fondamentali:

1.  **Stateful Path Exploration (Sfumatura):** Ogni percorso mantiene una memoria locale dei nodi visitati. Questo permette di evitare cicli banali all'interno dello stesso gadget, ma consente di riattraversare nodi comuni se si proviene da percorsi diversi, garantendo la scoperta di varianti dello stesso gadget.
2.  **Frequency-Based Pruning (Scurimento):** Viene definito un contatore di saturazione globale $\phi(v)$ per ogni nodo $v$. Se un nodo viene visitato troppe volte da percorsi diversi, viene considerato un "hub" saturo e i successivi percorsi che lo attraversano vengono tagliati. È proprio questa progressiva saturazione verso il nero a dare il nome 'rainbow' a questa variante dell'algoritmo.
   
La condizione di arresto (pruning) per un dato percorso $p$ è definita formalmente come:

$$\phi(v) >= \tau_{darkness} $$

Dove:
* $\phi(v)$ è il numero di volte che il nodo $v$ è stato visitato globalmente.
* $\tau_{darkness}$ è una soglia configurabile.

---

## 3. Modello Matematico di Scoring (Ranking dei Gadget)

Dato l'elevato numero di gadget candidati (ordine di $10^3$ - $10^4$), è necessario un sistema di ranking per presentare all'analista i risultati semanticamente più rilevanti.
Ogni gadget $g$ riceve un punteggio di qualità $S(g)$ calcolato secondo la seguente funzione lineare:

$$S(g) = S_{base} - P_{len}(g) - P_{ins}(g) + B_{sem}(g)$$

### Definizione dei termini:

1.  **Base Score ($S_{base}$):**
    $$S_{base} = 100$$
    Rappresenta il punteggio massimo ideale per un gadget privo di difetti.

2.  **Penalità di Lunghezza ($P_{len}$):**
    $$P_{len}(g) = 10 \cdot |B_g|$$
    Dove $|B_g|$ è il numero di blocchi LCSAJ che compongono il gadget. Gadget multi-blocco sono intrinsecamente più instabili e ricevono una penalità maggiore.

3.  **Penalità di Istruzioni ($P_{ins}$):**
    $$P_{ins}(g) = 2 \cdot N_{ins}$$
    Dove $N_{ins}$ è il numero totale di istruzioni nel gadget. Gadget lunghi introducono "rumore" (effetti collaterali sui registri) e vengono penalizzati.

4.  **Bonus Semantico ($B_{sem}$):**
    Analizza le istruzioni per identificare comportamenti utili all'exploit. È definito come la somma di tre componenti:
    $$B_{sem}(g) = \delta_{RA} + \delta_{ARG} - \delta_{CRIT}$$

    * $\delta_{RA} = +50$: Assegnato se il gadget carica il *Return Address* (`ra`) dallo stack (essenziale per il chaining dei gadget).
    * $\delta_{ARG} = +40$: Assegnato se il gadget carica i registri argomento (`a0`-`a7`) dallo stack (essenziale per preparare chiamate a funzione).
    * $\delta_{CRIT} = 30$: Penalità applicata se il gadget modifica registri critici come `gp` (Global Pointer) o `tp` (Thread Pointer), rischiando il crash del processo.

---

## 4. Considerazioni

Il punteggio di 160 rappresenta il massimo locale pratico per architetture reali RISC-V. Esso corrisponde a un gadget di tipo Fallthrough (2 blocchi) altamente efficiente (5 istruzioni) che offre il controllo completo del flusso (`ra` + `a0`). La consistenza di questo valore tra i primi 10 risultati conferma che l'algoritmo di ranking sta correttamente identificando e raggruppando la classe di gadget funzionalmente ottimali disponibili nel binario target.

---

## 5. Analisi dei Risultati Sperimentali

Il sistema è stato validato analizzando la libreria standard C (`libc.so.6`, architettura RISC-V 64-bit), un binario di dimensioni significative e alta complessità.

**Metriche Ottenute:**
* **Spazio di Ricerca:** ~291.000 istruzioni disassemblate.
* **Tempo di Analisi:** 5.3 secondi (su hardware commodity).
* **Copertura:** 66.492 nodi LCSAJ generati.
* **Gadget Identificati:** 8.867 totali (rispetto ai ~1.400 identificabili senza la mappatura Intra-Block).

**Validazione dell'Euristica:**
I gadget classificati nei primi 10 posti (Score $\approx 160$) mostrano invariabilmente la struttura:
`Check Condizionale` $\rightarrow$ `Caricamento A0` $\rightarrow$ `Caricamento RA` $\rightarrow$ `RET`.

Questa struttura conferma la capacità del tool di identificare sequenze ottimali per la costruzione di catene ROP, filtrando efficacemente le migliaia di sequenze irrilevanti.
Inoltre, l'algoritmo ha isolato con successo gadget di **Stack Pivoting** complessi (es. `add sp, s0, t0`), dimostrando una copertura semantica superiore agli scanner tradizionali che faticano a tracciare manipolazioni aritmetiche dello Stack Pointer attraverso blocchi multipli.

---

## 6. Conclusioni

Il lavoro dimostra che l'approccio basato su grafi LCSAJ, potenziato da una mappatura precisa delle istruzioni intra-blocco e da un algoritmo di ricerca euristica (Rainbow BFS), supera significativamente le tecniche di scansione lineare. Lo strumento sviluppato è in grado di identificare un numero maggiore di gadget funzionali e semanticamente ricchi in tempi compatibili con l'utilizzo reale, fornendo una base solida per l'automazione della costruzione di exploit su architettura RISC-V.
