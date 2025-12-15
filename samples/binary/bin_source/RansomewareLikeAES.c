#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

int main() {
    unsigned char key[16] = "0123456789abcdef";
    unsigned char iv[16]  = "1234567890abcdef";  // IV richiesto per CBC
    unsigned char plaintext[16] = "plaintextblock!!";
    unsigned char ciphertext[32];
    int len, ciphertext_len;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    // Inizializza contesto per AES-128-CBC
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    // Cifra il blocco
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, sizeof(plaintext)-1);
    ciphertext_len = len;

    // Finalizza
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    printf("Blocco cifrato, lunghezza: %d\n", ciphertext_len);
    return 0;
}
