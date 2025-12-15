/*
  Demo didattico: tentativo di cancellare una cartella
  Scopo: generare un binario con una funzione "pericolosa" da analizzare con radare2.
  Compilabile con MinGW (gcc) o Visual Studio (cl).
*/

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
  #include <windows.h>
#else
  #include <unistd.h>
  #include <sys/stat.h>
#endif

int main(void) {
    // Cartella fittizia (NON reale, solo per esercitazione)
    const char *folder = "C:\\fake_folder";   // su Windows
    // const char *folder = "./fake_folder";  // su Linux/MinGW POSIX

    printf("Tentativo di cancellare la cartella: %s\n", folder);

#ifdef _WIN32
    if (RemoveDirectoryA(folder)) {
        printf("Cartella rimossa con successo.\n");
    } else {
        printf("Impossibile rimuovere la cartella.\n");
    }
#else
    if (rmdir(folder) == 0) {
        printf("Cartella rimossa con successo.\n");
    } else {
        perror("Errore rimozione cartella");
    }
#endif

    return 0;
}
