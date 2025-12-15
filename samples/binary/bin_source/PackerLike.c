#include <stdio.h>
#include <string.h>
#include <zlib.h>
//Packer‑like (uso di zlib per compressione)
int main() {
    char src[] = "data to compress";
    char dest[100];
    uLongf destLen = sizeof(dest);

    compress((Bytef*)dest, &destLen, (Bytef*)src, strlen(src));
    printf("Dati compressi.\n");
    return 0;
}
