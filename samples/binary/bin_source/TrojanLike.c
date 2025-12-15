#include <stdio.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
#endif

int main() {
#ifdef _WIN32
    // Su Windows: usa CreateProcess per simulare comportamento Trojan-like
    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (CreateProcess(
        NULL,
        "cmd.exe /c echo Simulazione Trojan",
        NULL, NULL, FALSE,
        0, NULL, NULL,
        &si, &pi)) {
        printf("Processo creato con PID %lu\n", pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("Errore: %lu\n", GetLastError());
    }

#else
    // Su Linux/Unix: usa execve
    char *args[] = {"/bin/echo", "Simulazione Trojan", NULL};
    execve(args[0], args, NULL);
#endif

    return 0;
}


