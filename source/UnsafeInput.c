// Vulnerabilità: uso diretto di input utente come formato
#include <stdio.h>
int main() {
    char userInput[100];
    scanf("%s", userInput);
    printf(userInput); // ⚠️ Se userInput contiene %x, può leggere memoria
    return 0;
}
