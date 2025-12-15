#include <stdio.h>

int main() {
    // Stringa usata per essere rilevata da YARA o ClamAV
    char* malware_indicator = "Win32/Exploit.Agent.EZ";

    printf("Questo programma non fa nulla di male.\n");
    printf("Ma contiene una firma rilevabile: %s\n", malware_indicator);

    return 0;
}