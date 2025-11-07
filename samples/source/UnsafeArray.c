// Vulnerabilità: scrittura oltre i limiti dell'array
#include <stdio.h>
int main() {
    char buffer[10];
    gets(buffer); // ⚠️ gets è pericolosa: non controlla la lunghezza
    printf("Input: %s\n", buffer);
    return 0;
}
