/*
  Demo didattico: programma con indirizzo fittizio e connessione TCP
  Scopo: mostrare una "connessione malevola" hard-coded da individuare e rimuovere con radare2.
  Compilabile con MinGW (gcc) o Visual Studio (cl).
*/

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
#else
  #include <unistd.h>
  #include <sys/types.h>
  #include <sys/socket.h>
  #include <netdb.h>
#endif

int main(void) {
    // Indirizzo fittizio (NON reale, solo per esercitazione)
    const char *fake_host = "malicious.example.com";
    const char *fake_port = "8080";

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2,2), &wsa);
#endif

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(fake_host, fake_port, &hints, &res) != 0) {
        fprintf(stderr, "Impossibile risolvere host\n");
        return 1;
    }

    int sockfd = (int)socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) {
        fprintf(stderr, "Errore creazione socket\n");
        freeaddrinfo(res);
        return 1;
    }

    // Connessione simulata (fallirà se non esiste il server)
    if (connect(sockfd, res->ai_addr, (int)res->ai_addrlen) != 0) {
        fprintf(stderr, "Connessione fallita a %s:%s\n", fake_host, fake_port);
    } else {
        printf("Connessione stabilita a %s:%s\n", fake_host, fake_port);
    }

#ifdef _WIN32
    closesocket(sockfd);
    WSACleanup();
#else
    close(sockfd);
#endif
    freeaddrinfo(res);

    return 0;
}
