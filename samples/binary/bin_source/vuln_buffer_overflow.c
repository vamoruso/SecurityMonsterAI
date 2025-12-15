#include <stdio.h>
#include <string.h>

char *gets(char *);

int main() {
    char buf[16];
    gets(buf);  // 🚨 vulnerabilità
    return 0;
}
// VULNERABILITÀ: Buffer overflow didattico
void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // ⚠️ Vulnerabilità
    printf("Input: %s\n", buffer);
}