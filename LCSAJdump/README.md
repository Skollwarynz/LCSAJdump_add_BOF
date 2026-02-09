```ZSH
~/Desktop/tesi/LCSAJdump main* LCSAJdump ❯ time python main.py ../test/level2/vuln
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
[*] Ricerca completata. Trovati 2865 gadget.

[*] Calcolo Ranking e filtraggio...
--- Top 5 Gadgets by Quality Score ---

RANK #1 | SCORE: 160 | BLOCKS: 2
----------------------------------------
  🎯 0x4078a: c.beqz     a0, -0x32
      |
  🎯 0x4078c: c.ldsp     a0, 0x20(sp)
  🔗 0x4078e: c.ldsp     ra, 0x58(sp)
     0x40790: c.addi16sp sp, 0x60
  🔴 0x40792: c.jr       ra

RANK #2 | SCORE: 160 | BLOCKS: 2
----------------------------------------
  🎯 0x460b6: c.bnez     a0, 0xa
      |
  🔗 0x460b8: c.ldsp     ra, 0x38(sp)
  🎯 0x460ba: c.ldsp     a0, 0x20(sp)
     0x460bc: c.addi16sp sp, 0x40
  🔴 0x460be: c.jr       ra

RANK #3 | SCORE: 160 | BLOCKS: 2
----------------------------------------
  🎯 0x460e4: c.bnez     a0, 0xa
      |
  🔗 0x460e6: c.ldsp     ra, 0x38(sp)
  🎯 0x460e8: c.ldsp     a0, 0x20(sp)
     0x460ea: c.addi16sp sp, 0x40
  🔴 0x460ec: c.jr       ra

RANK #4 | SCORE: 160 | BLOCKS: 2
----------------------------------------
  🎯 0x4618a: c.bnez     a0, 0xa
      |
  🔗 0x4618c: c.ldsp     ra, 0x28(sp)
  🎯 0x4618e: c.ldsp     a0, 0x10(sp)
     0x46190: c.addi16sp sp, 0x30
  🔴 0x46192: c.jr       ra

RANK #5 | SCORE: 160 | BLOCKS: 2
----------------------------------------
  🎯 0x461b4: c.bnez     a0, 0xa
      |
  🔗 0x461b6: c.ldsp     ra, 0x28(sp)
  🎯 0x461b8: c.ldsp     a0, 0x10(sp)
     0x461ba: c.addi16sp sp, 0x30
  🔴 0x461bc: c.jr       ra
python main.py ../test/level2/vuln  1,50s user 0,33s system 99% cpu 1,823 total

```

Score=100−(Lblocks​×10)−(Linsns​×2)+Bonus−Malus


