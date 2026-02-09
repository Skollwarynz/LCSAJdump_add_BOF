'''ZSH
~/Desktop/tesi/LCSAJdump LCSAJdump ❯ time python main.py ../test/level2/vuln
[*] Analisi LCSAJ ROP su: ../test/level2/vuln
[*] Caricamento binario: ../test/level2/vuln
[*] Sezione .text trovata.
    Dimensione: 258236 bytes
    Indirizzo Base: 0x10250
[*] Avvio disassemblaggio con Capstone...
[*] Disassemblaggio completato. 89354 istruzioni estratte.
[*] Costruzione Nodi LCSAJ...
[*] Costruzione Archi (Collegamenti)...
[*] Grafo Completo. Nodi: 19568, Archi inversi mappati.
[*] Avvio Rainbow BFS dai 1714 sink...
[*] Ricerca completata. Processati 4579 percorsi.
[*] Trovati 2865 gadget candidati.

[*] Filtraggio completato. Visualizzo i migliori 5...

============================================================
GADGET #1 (Lunghezza: 2 blocchi)
============================================================
  [BLOCK 1] @ 0x10530
     0x10530:  c.bnez     a0, 0x28
      |
      | (Fallthrough)
      v
  [BLOCK 2] @ 0x10532
     0x10532:  ld         a5, -0x640(tp)
     0x10536:  auipc      a2, 0x70
     0x1053a:  ld         a2, 0xe2(a2)
  🟢 0x1053e:  c.ldsp     a1, 0x18(sp)
     0x10540:  c.sdsp     a5, 0x100(sp)
     0x10542:  ld         a5, -0x648(tp)
  🟢 0x10546:  c.ldsp     a0, 0x10(sp)
     0x10548:  c.sdsp     a5, 0x108(sp)
     0x1054a:  c.addi4spn a5, sp, 0x28
     0x1054c:  sd         a5, -0x640(tp)
  🟢 0x10550:  c.ldsp     a5, 8(sp)
     0x10552:  c.jalr     a5
      |
      +--> [FINE GADGET / RET]

============================================================
GADGET #2 (Lunghezza: 2 blocchi)
============================================================
  [BLOCK 1] @ 0x1096e
     0x1096e:  c.bnez     a0, 8
      |
      | (Fallthrough)
      v
  [BLOCK 2] @ 0x10970
  🟢 0x10970:  c.ldsp     ra, 8(sp)
     0x10972:  c.addi     sp, 0x10
  🔴 0x10974:  c.jr       ra
      |
      +--> [FINE GADGET / RET]

============================================================
GADGET #3 (Lunghezza: 2 blocchi)
============================================================
  [BLOCK 1] @ 0x109c2
     0x109c2:  addi       a5, zero, 0x20
     0x109c6:  beq        a4, a5, 0x24
      |
      | (Fallthrough)
      v
  [BLOCK 2] @ 0x109ca
     0x109ca:  slli       a0, a4, 5
     0x109ce:  c.addi     a0, 0x10
     0x109d0:  c.addi     a4, 1
     0x109d2:  c.add      a0, a2
     0x109d4:  c.sd       a4, 8(a2)
     0x109d6:  ld         a5, 0xa0(gp)
     0x109da:  c.li       a4, 1
  🟢 0x109dc:  c.ldsp     ra, 0x18(sp)
     0x109de:  c.sd       a4, 0(a0)
     0x109e0:  c.add      a5, a4
     0x109e2:  sd         a5, 0xa0(gp)
     0x109e6:  c.addi16sp sp, 0x20
  🔴 0x109e8:  c.jr       ra
      |
      +--> [FINE GADGET / RET]

============================================================
GADGET #4 (Lunghezza: 2 blocchi)
============================================================
  [BLOCK 1] @ 0x10a7a
     0x10a7a:  c.li       a5, 4
     0x10a7c:  c.sd       a5, 0(a0)
     0x10a7e:  c.sd       s1, 8(a0)
     0x10a80:  c.sd       a1, 0x10(a0)
     0x10a82:  c.sd       a2, 0x18(a0)
     0x10a84:  c.li       a5, 0
     0x10a86:  addi       a4, s0, 8
     0x10a8a:  amoswap.w.rl a5, a5, (a4)
     0x10a8e:  c.addiw    a5, 0
     0x10a90:  c.li       a4, 1
     0x10a92:  blt        a4, a5, 0x10
      |
      | (Fallthrough)
      v
  [BLOCK 2] @ 0x10a96
     0x10a96:  c.li       a0, 0
  🟢 0x10a98:  c.ldsp     ra, 0x38(sp)
  🟢 0x10a9a:  c.ldsp     s0, 0x30(sp)
  🟢 0x10a9c:  c.ldsp     s1, 0x28(sp)
     0x10a9e:  c.addi16sp sp, 0x40
  🔴 0x10aa0:  c.jr       ra
      |
      +--> [FINE GADGET / RET]

============================================================
GADGET #5 (Lunghezza: 2 blocchi)
============================================================
  [BLOCK 1] @ 0x10db4
     0x10db4:  c.beqz     a2, 0x7a
      |
      | (Fallthrough)
      v
  [BLOCK 2] @ 0x10db6
     0x10db6:  addiw      a5, a2, -1
     0x10dba:  c.sw       a5, 4(a4)
  🟢 0x10dbc:  c.ldsp     ra, 0x38(sp)
     0x10dbe:  c.mv       a0, s0
  🟢 0x10dc0:  c.ldsp     s0, 0x30(sp)
  🟢 0x10dc2:  c.ldsp     s1, 0x28(sp)
  🟢 0x10dc4:  c.ldsp     s2, 0x20(sp)
  🟢 0x10dc6:  c.ldsp     s3, 0x18(sp)
     0x10dc8:  c.addi16sp sp, 0x40
  🔴 0x10dca:  c.jr       ra
      |
      +--> [FINE GADGET / RET]

'''

🏆 Gadget #5: Il "Sacro Graal"

Voto: 10/10 (Elite)

    Perché: È un gadget quasi perfetto. Fa due cose fondamentali:

        c.mv a0, s0: Ti permette di spostare un valore che hai precedentemente caricato in s0 direttamente in a0 (l'argomento della funzione che vuoi chiamare).

        c.ldsp ra, 0x38(sp): Ricarica il Return Address. Questo significa che il gadget è incatenabile (chainable). Puoi decidere dove andare dopo.

        Ripristino massiccio: Carica s0, s1, s2, s3. Ti dà il controllo totale su metà dei registri "saved".

    Utilizzo: Carichi s0 con un altro gadget, poi usi questo per passarlo a win() o system().

🥈 Gadget #2: Il "Linker" Pulito

Voto: 8/10 (Essenziale)

    Perché: È la quintessenza della semplicità. Fa solo due cose: ricarica ra e pulisce lo stack (addi sp, 0x10).

    Utilizzo: Serve come "colla" tra altri gadget. Se hai un gadget che fa qualcosa di utile ma non ricarica bene ra, puoi provare a saltare qui per "aggiustare" il flusso. È corto, non sporca nessun registro (tranne ra) e non rischia di crashare.

🥉 Gadget #4: Il "Restauratore"

Voto: 7/10 (Molto Buono)

    Perché: Ti permette di caricare s0 e s1 dallo stack. Controllare s0 è fondamentale per poi usare il Gadget #5.

    Il difetto: Ha un'istruzione c.li a0, 0. Questo è un'arma a doppio taglio: è utilissimo se vuoi chiamare una funzione che richiede 0 come primo argomento, ma ti impedisce di usare questo gadget se vuoi passare un puntatore (come /bin/sh) in a0.

🔸 Gadget #1: Il "JOP Complesso"

Voto: 5/10 (Situazionale)

    Perché: Carica sia a0 che a1 dallo stack. È potentissimo perché controlla due argomenti in un colpo solo.

    Il problema: È molto "sporco". Accede a tp (Thread Pointer) con ld a5, -0x640(tp). Se il binario usa i thread in modo particolare, questo accesso potrebbe causare un Segmentation Fault immediato prima ancora di arrivare alla fine del gadget. Inoltre, termina con c.jalr a5 (Jump-Oriented Programming), il che richiede che tu abbia pre-caricato l'indirizzo target in a5. Difficile da manovrare.

🔸 Gadget #3: Il "Rumoroso"

Voto: 4/10 (Scarso)

    Perché: Carica ra (buono), ma fa un sacco di operazioni inutili nel mezzo: slli, addi, add, e soprattutto scrive in memoria (c.sd a4, 8(a2)).

    Il rischio: Scrivere in memoria a un indirizzo contenuto in a2 è pericolosissimo. Se in quel momento a2 contiene un indirizzo non valido, il programma crasha. È un gadget "fragile". Lo useresti solo come ultima spiaggia se non ci fosse altro.
