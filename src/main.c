/**
 * \file main.c
 * \author Isaiah Lateer
 *
 * Entry point for the project.
 */

#include <stdlib.h>

#include "aes.h"

#define BUFFER_SIZE 1024

/**
 * Entry point for the project.
 *
 * \return Exit code.
 */
int main() {
    uint8_t key[16] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB,
        0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };

    FILE* in_file = fopen("res/plaintext.txt", "r");
    if (!in_file) {
        fprintf(stderr, "[ERROR] Failed to open input file.\n");
        return EXIT_FAILURE;
    }

    FILE* out_file = fopen("res/ciphertext.aes", "w");
    if (!out_file) {
        fprintf(stderr, "[ERROR] Failed to open output file.\n");
        return EXIT_FAILURE;
    }

    fseek(in_file, 0, SEEK_END);
    uint8_t* ciphertext = malloc(BUFFER_SIZE);
    if (!ciphertext) {
        fprintf(stderr,
            "[ERROR] Failed to allocated memory for the ciphertext buffer.\n");
        fclose(in_file);
        return EXIT_FAILURE;
    }

    const size_t bytes_written = aes_encrypt(key, in_file, BUFFER_SIZE,
        ciphertext);
    fwrite(ciphertext, sizeof(uint8_t), bytes_written, out_file);

    fclose(in_file);
    fclose(out_file);
    return EXIT_SUCCESS;
}
