#include <stdio.h>
#include <unistd.h>

void win(int arg) {
    if (arg == 0x1337) {
        puts("🔥 PWNED! Hai rediretto il flusso su win()! 🔥");
    }
}

void vulnerable() {
    char buffer[64];
    // Legge 200 byte dallo Standard Input (tastiera/pipe) dentro buffer[64]
    // Questo permette il buffer overflow E accetta i null bytes!
    read(0, buffer, 200); 
}

int main() {
    puts("Dammi il payload:");
    vulnerable();
    return 0;
}
