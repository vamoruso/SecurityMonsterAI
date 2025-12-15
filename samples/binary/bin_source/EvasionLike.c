#include <stdio.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/ptrace.h>
#include <unistd.h>
#endif

int main() {
#ifdef _WIN32
    if (IsDebuggerPresent()) {
        printf("Debugger rilevato (Windows).\n");
    } else {
        printf("Nessun debugger (Windows).\n");
    }
#else
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        printf("Debugger rilevato (Linux).\n");
    } else {
        printf("Nessun debugger (Linux).\n");
    }
#endif
    return 0;
}
