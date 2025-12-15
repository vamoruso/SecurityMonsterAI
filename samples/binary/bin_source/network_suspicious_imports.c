#include <stdio.h>
#include <string.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

int main() {
#ifdef _WIN32
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in server;
    const char *msg = "Hello Suspicious World";

    if (WSAStartup(MAKEWORD(2,2), &wsa) != 0) {
        printf("WSAStartup failed\n");
        return 1;
    }

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) {
        printf("Socket creation failed\n");
        WSACleanup();
        return 1;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(8080);
    server.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(s, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        printf("Connect failed\n");
    } else {
        send(s, msg, strlen(msg), 0);
        printf("Messaggio inviato (Windows).\n");
    }

    closesocket(s);
    WSACleanup();

#else
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in server;
    const char *msg = "Hello Suspicious World";

    server.sin_family = AF_INET;
    server.sin_port = htons(8080);
    server.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(s, (struct sockaddr*)&server, sizeof(server)) < 0) {
        printf("Connect failed\n");
    } else {
        send(s, msg, strlen(msg), 0);
        printf("Messaggio inviato (Linux).\n");
    }

    close(s);
#endif

    return 0;
}
