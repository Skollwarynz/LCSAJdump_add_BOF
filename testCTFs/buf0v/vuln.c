#include <stdio.h>
#include <unistd.h>
#include <string.h>

void win() {
    execve("/bin/sh", NULL, NULL);
}

void vulnerable(int *i) {
    char buffer[64];
    puts("Are you riscky enough to find the secret? Enter your input: (y/n)");
    char answer[16];
    if (scanf("%15s", answer)!= 1) {
        puts("Invalid input. Exiting.");
        return;
    }
    if (strcmp(answer, "y")==0 ) read(0, buffer, 64);
    else if (strcmp(answer, "n")==0 ) read(0, buffer, *i);
     else puts("Invalid choice. Exiting.");

}

void name(int *i) {
    puts("What's your name you little Nasica?");
    char name[40];
    if (!scanf("%39s", name)) {
        puts("Invalid input. Exciting.");
        return;
    }
    *i = *i+1;
}

void hint() {
    puts("AHAHAHAHAHA!");
}

void menu(int *i) {
    puts("1. Tell me if you're a riscky monkey");
    puts("2. Tell me your name monkey");
    puts("3. Hint");
    puts("4. Exit");

    char choice[16];
    if (scanf("%15s", choice) != 1) {
        puts("Invalid input. Exiting.");
        return;
    }

    if (strcmp(choice, "1")==0 ) vulnerable(i);
    else if (strcmp(choice, "2")==0 ) name(i);
    else if (strcmp(choice, "3")==0 ) hint();
    else if (strcmp(choice, "4")==0 ) _exit(0);
     else puts("Invalid choice. Exiting.");
}

int main() {
    int i = 0;
    puts("=== Monkey Risk 1 - chris1sflaggin ===");
    while (1)
    {
        menu(&i);
    }
    
    return 0;
}
