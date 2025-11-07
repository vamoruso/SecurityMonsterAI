// SensitiveDataExposure.c
#include <stdio.h>

int main() {
    char password[] = "SuperSecret123";  // 🔴 Hardcoded
    printf("Password: %s\n", password);  // 🔴 Esposta in chiaro
    return 0;
}
