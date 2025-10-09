/**
 * \file main.c
 * \author Isaiah Lateer
 *
 * Entry point for the project.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"

/**
 * Entry point for the project.
 *
 * \return Exit code.
 */
int main() {
    uint8_t key[16] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB,
        0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
    uint32_t expanded[44] = { 0 };

    expand_key(key, expanded);
    for (int i = 0; i < 44; ++i) {
        printf("0x%08X\n", expanded[i]);
    }

    return EXIT_SUCCESS;
}
