#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

// Variabili globali per evitare ottimizzazioni
volatile int g_state = 0;

void gadget_farm() {
    // Un po' di assembly inline per creare gadget "succosi" in mezzo al caos
    __asm__("c.nop");
    __asm__("c.nop");
    __asm__("ret");
}

void chaotic_function(int seed) {
    int local_state = seed;
    char buffer[64]; // Vulnerabile a overflow se non stiamo attenti

    // BLOCCO A: Loop complessi con condizioni volatili
    // Questo costringe il BFS a esplorare più profondità (Depth)
    for (int i = 0; i < 10; i++) {
        if (local_state % 2 == 0) {
            local_state = (local_state >> 1) ^ 0xDEADBEEF;
        } else {
            local_state = (local_state << 1) ^ 0xCAFEBABE;
        }
        g_state += i;
    }

    // BLOCCO B: Spaghetti Code (GOTO)
    // Questo crea cicli nel grafo (Darkness)
    // Simula tecniche di offuscamento "Control Flow Flattening"
    
    start_maze:
    if (local_state > 1000) {
        local_state -= 100;
        goto mid_maze;
    }
    
    // Gadget nascosto nel flusso
    __asm__("c.ldsp ra, 0(sp)");
    __asm__("c.jr ra");

    if (local_state < 0) {
        goto end_maze;
    }

    mid_maze:
    local_state += g_state;
    if (local_state % 3 == 0) {
        goto start_maze; // SALTO ALL'INDIETRO! (Richiede k alto)
    }

    if (local_state % 5 == 0) {
        goto chaotic_exit;
    }
    
    // Altro salto all'indietro condizionale
    if (g_state < 50) {
        g_state++;
        goto mid_maze; 
    }

    end_maze:
    printf("State: %d\n", local_state);
    return;

    chaotic_exit:
    read(0, buffer, 200); // Overflow intenzionale
    return;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        chaotic_function(atoi(argv[1]));
    } else {
        chaotic_function(42);
    }
    return 0;
}
