#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Prototipo per evitare l'errore di compilazione
char *gets(char *s);

void win() {
    printf("\n[!] EXPLOIT SUCCESS: Flusso deviato con successo via LCSAJ!\n");
    exit(0);
}

void vulnerable_function() {
    char buffer[64];
    printf("Inserisci il payload: ");
    gets(buffer); 
}

int main() {
    printf("[*] Attesa input...\n");
    vulnerable_function();
    return 0;
}
