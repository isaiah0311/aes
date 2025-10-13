/**
 * \file main.c
 * \author Isaiah Lateer
 *
 * Entry point for the project.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "aes.h"

/**
 * Processes arguments in order to determin whether to encrypt or decrypt and
 * which files to read from and write to.
 *
 * \param[in] argc Number of arguments.
 * \param[in] argv Arguments.
 * \return Exit code.
 */
int main(int argc, const char** argv) {
    enum direction {
        DIRECTION_UNDEFINED,
        DIRECTION_ENCRYPT,
        DIRECTION_DECRYPT
    };

    bool exit = false;
    enum direction direction = DIRECTION_UNDEFINED;
    uint8_t key[16] = { 0 };
    bool set_key = false;
    FILE* in_file = NULL;
    FILE* out_file = NULL;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-d") == 0) {
            if (direction != DIRECTION_UNDEFINED) {
                fprintf(stderr,
                    "[ERROR] Multiple direction values were given.\n");
                exit = true;
                break;
            } else if (i + 1 < argc) {
                if (strcmp(argv[i + 1], "enc") == 0) {
                    direction = DIRECTION_ENCRYPT;
                } else if (strcmp(argv[i + 1], "dec") == 0) {
                    direction = DIRECTION_DECRYPT;
                } else {
                    fprintf(stderr, "[ERROR] Direction is invalid\n");
                }

                ++i;
            } else {
                fprintf(stderr, "[ERROR] Missing direction value after -m.\n");
                exit = true;
                break;
            }
        } else if (strcmp(argv[i], "-k") == 0) {
            if (set_key) {
                fprintf(stderr, "[ERROR] Multiple key values were given.\n");
                exit = true;
                break;
            } else if (i + 1 < argc) {
                const char* hex = argv[i + 1];
                const size_t char_count = strlen(hex);

                if (char_count > 34) {
                    fprintf(stderr, "[ERROR] Key is too long.\n");
                    exit = true;
                    break;
                }

                size_t byte_count = char_count / 2;
                if (byte_count > 16) {
                    hex += (byte_count - 16) * 2;
                    byte_count = 16;
                }

                for (size_t j = 0; j < byte_count; ++j) {
                    const char bytes[3] = { hex[j * 2], hex[j * 2 + 1], '\0' };
                    char* endptr = NULL;
                    key[16 - byte_count + j] = (uint8_t) strtoul(bytes, &endptr,
                        16);
                    if (endptr == hex) {
                        fprintf(stderr, "[ERROR] Key is not a valid number.\n");
                        exit = true;
                        break;
                    }
                }

                if (exit) {
                    break;
                }

                set_key = true;
                ++i;
            } else {
                fprintf(stderr, "[ERROR] Missing key value after -k.\n");
                exit = true;
                break;
            }
        } else if (strcmp(argv[i], "-i") == 0) {
            if (in_file) {
                fprintf(stderr,
                    "[ERROR] Multiple input file values were given.\n");
                exit = true;
                break;
            } else if (i + 1 < argc) {
                in_file = fopen(argv[i + 1], "r");
                if (!in_file) {
                    fprintf(stderr, "[ERROR] Failed to open input file.\n");
                    exit = true;
                    break;
                }

                ++i;
            } else {
                fprintf(stderr, "[ERROR] Missing input file path after -i.\n");
                exit = true;
                break;
            }
        } else if (strcmp(argv[i], "-o") == 0) {
            if (out_file) {
                fprintf(stderr,
                    "[ERROR] Multiple output file values were given.\n");
                exit = true;
                break;
            } else if (i + 1 < argc) {
                out_file = fopen(argv[i + 1], "w");
                if (!out_file) {
                    fprintf(stderr, "[ERROR] Failed to open output file.\n");
                    exit = true;
                    break;
                }

                ++i;
            } else {
                fprintf(stderr, "[ERROR] Missing output file path after -o.\n");
                exit = true;
                break;
            }
        } else {
            fprintf(stderr, "[WARN] Skipping unknown argument: %s\n", argv[i]);
        }
    }

    if (!exit) {
        if (!set_key) {
            fprintf(stderr, "[ERROR] No key was given.\n");
            exit = true;
        } else if (!in_file) {
            fprintf(stderr, "[ERROR] No input file was given.\n");
            exit = true;
        }
    }

    if (exit) {
        if (in_file) {
            fclose(in_file);
        }

        if (out_file) {
            fclose(out_file);
        }

        return EXIT_FAILURE;
    }

    long byte_count = 0;
    size_t bytes_written = 0;

    switch (direction) {
    case DIRECTION_UNDEFINED:
    case DIRECTION_ENCRYPT:
        fseek(in_file, 0, SEEK_END);
        byte_count = ((ftell(in_file) / 16) + 1) * 16;
        uint8_t* ciphertext = malloc(byte_count);
        if (!ciphertext) {
            fprintf(stderr,
                "[ERROR] Failed to allocated memory for the ciphertext "
                "buffer.\n");
            fclose(in_file);
            return EXIT_FAILURE;
        }

        bytes_written = aes_encrypt(key, in_file, byte_count, ciphertext);

        if (out_file) {
            fwrite(ciphertext, sizeof(uint8_t), bytes_written, out_file);
        } else {
            printf("0x");
            for (size_t i = 0; i < bytes_written; ++i) {
                printf("%02X", ciphertext[i]);
            }

            printf("\n");
        }

        break;
    case DIRECTION_DECRYPT:
        fseek(in_file, 0, SEEK_END);
        byte_count = ftell(in_file);
        uint8_t* plaintext = malloc(byte_count);
        if (!plaintext) {
            fprintf(stderr,
                "[ERROR] Failed to allocated memory for the plaintext "
                "buffer.\n");
            fclose(in_file);
            return EXIT_FAILURE;
        }

        bytes_written = aes_decrypt(key, in_file, byte_count, plaintext);

        if (out_file) {
            fwrite(plaintext, sizeof(uint8_t), bytes_written, out_file);
        } else {
            printf("0x");
            for (size_t i = 0; i < bytes_written; ++i) {
                printf("%02X", plaintext[i]);
            }

            printf("\n");
        }

        break;
    }

    fclose(in_file);
    if (out_file) {
        fclose(out_file);
    }

    return EXIT_SUCCESS;
}
