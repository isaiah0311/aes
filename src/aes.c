/**
 * \file aes.c
 * \author Isaiah Lateer
 *
 * Implementation of the AES interface.
 */

#include "aes.h"

#include <string.h>

static const uint8_t s[256] = { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D,
    0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1,
    0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A,
    0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39,
    0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F,
    0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D,
    0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A,
    0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA,
    0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66,
    0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9,
    0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16 };

static const uint8_t rc[11] = { 0x8D, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36 };

/**
 * Performs a left byte shift on the word, followed by byte substitution, and
 * finally an XOR with a round constant.
 *
 * \param[in] word Word.
 * \param[in] round Round number.
 */
static uint32_t g(uint32_t word, int round) {
    uint8_t bytes[4];
    bytes[0] = (word >> 24) & 0xFF;
    bytes[1] = (word >> 16) & 0xFF;
    bytes[2] = (word >> 8) & 0xFF;
    bytes[3] = word & 0xFF;

    uint8_t tmp = bytes[0];
    bytes[0] = bytes[1];
    bytes[1] = bytes[2];
    bytes[2] = bytes[3];
    bytes[3] = tmp;

    for (int i = 0; i < 4; i++) {
        bytes[i] = s[bytes[i]];
    }

    bytes[0] ^= rc[round];

    return (bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3];
}

/**
 * Fills the first 4 words of the expanded key with the original 128-bit key.
 * The remaining 40 words are calculated in groups of 4, using the previous 4
 * each time in the calculation.
 *
 * \param[in] key 128-bit key.
 * \param[out] expanded 44-word expanded key.
 */
static void expand_key(uint8_t key[16], uint32_t expanded[44]) {
    for (int i = 0; i < 4; ++i) {
        expanded[i] = (key[i * 4] << 24) | (key[(i * 4) + 1] << 16) |
            (key[(i * 4) + 2] << 8) | key[(i * 4) + 3];
    }

    for (int i = 4; i < 44; ++i) {
        if (i % 4 == 0) {
            expanded[i] = g(expanded[i - 1], i / 4) ^ expanded[i - 4];
        } else {
            expanded[i] = expanded[i - 1] ^ expanded[i - 4];
        }
    }
}

/**
 * Converts a block into a state matrix.
 *
 * \param[in] bytes 16-byte block.
 * \param[out] state 4x4 byte matrix.
 */
static void bytes_to_state(const uint8_t bytes[16], uint8_t state[4][4]) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[j][i] = bytes[(i * 4) + j];
        }
    }
}

/**
 * Converts a state matrix into a block.
 *
 * \param[in] state 4x4 byte matrix.
 * \param[out] bytes 16-byte block.
 */
static void state_to_bytes(uint8_t state[4][4], uint8_t bytes[16]) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            bytes[(i * 4) + j] = state[j][i];
        }
    }
}

/**
 * XORs a state matrix with the key for a given round.
 *
 * \param[in,out] state 4x4 byte matrix.
 * \param[in] expanded 44-word expanded key.
 * \param[in] round Round number.
 */
static void add_round_key(uint8_t state[4][4], const uint32_t expanded[44],
    int round) {
    for (int i = 0; i < 4; ++i) {
        const uint32_t word = expanded[(round * 4) + i];
        state[0][i] ^= (word >> 24) & 0xFF;
        state[1][i] ^= (word >> 16) & 0xFF;
        state[2][i] ^= (word >> 8) & 0xFF;
        state[3][i] ^= (word) & 0xFF;
    }
}

/**
 * Substitutes the bytes of a state matrix.
 *
 * \param[in,out] state 4x4 byte matrix.
 */
static void sub_bytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            state[i][j] = s[state[i][j]];
        }
    }
}

/**
 * Shifts the rows of a state matrix.
 *
 * \param[in,out] state 4x4 byte matrix.
 */
static void shift_rows(uint8_t state[4][4]) {
    uint8_t tmp1, tmp2;

    tmp1 = state[1][0];
    for (int i = 0; i < 3; ++i) {
        state[1][i] = state[1][i + 1];
    }

    state[1][3] = tmp1;

    tmp1 = state[2][0];
    tmp2 = state[2][1];
    state[2][0] = state[2][2];
    state[2][1] = state[2][3];
    state[2][2] = tmp1;
    state[2][3] = tmp2;

    tmp1 = state[3][3];
    for (int i = 3; i > 0; --i) {
        state[3][i] = state[3][i - 1];
    }

    state[3][0] = tmp1;
}

/**
 * Performs multiplication in the Galois Field GF(2^8).
 *
 * \param[in,out] state 4x4 byte matrix.
 */
static uint8_t gf(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) {
            p ^= a;
        }

        const uint8_t hi_bit = a & 0x80;
        a <<= 1;

        if (hi_bit) {
            a ^= 0x1B;
        }

        b >>= 1;
    }

    return p;
}

/**
 * Mixes the columns of a state matrix.
 *
 * \param[in,out] state 4x4 byte matrix.
 */
static void mix_columns(uint8_t state[4][4]) {
    for (int i = 0; i < 4; ++i) {
        const uint8_t a[4] = { state[0][i], state[1][i], state[2][i],
            state[3][i] };
        const uint8_t b[4] = { gf(a[0], 2) ^ gf(a[1], 3) ^ a[2] ^ a[3],
            a[0] ^ gf(a[1], 2) ^ gf(a[2], 3) ^ a[3],
            a[0] ^ a[1] ^ gf(a[2], 2) ^ gf(a[3], 3),
            gf(a[0], 3) ^ a[1] ^ a[2] ^ gf(a[3], 2) };

        for (int j = 0; j < 4; ++j) {
            state[j][i] = b[j];
        }
    }
}

/**
 * Expanded the key. Splits the plaintext into 128-bit blocks, which are
 * converted into 4x4 byte matrices. Each of the state matrices are encrypted
 * using the expanded key and placed into the ciphertext buffer.
 *
 * \param[in] key Encryption key.
 * \param[in] plaintext File to be encrypted.
 * \param[in] byte_count Number of bytes in ciphertext.
 * \param[out] ciphertext Encrypted data.
 * \return Number of encrypted bytes.
 */
size_t aes_encrypt(uint8_t key[16], FILE* plaintext, size_t byte_count,
    uint8_t* ciphertext) {
    rewind(plaintext);
    memset(ciphertext, 0, byte_count);

    uint32_t expanded[44] = { 0 };
    expand_key(key, expanded);

    size_t offset = 0;
    while (offset + 16 <= byte_count) {
        uint8_t bytes[16] = { 0 };
        const size_t read_count = fread(bytes, sizeof(uint8_t), 16, plaintext);

        const uint8_t pad_value = 16 - (uint8_t) read_count;
        for (size_t i = read_count; i < 16; ++i) {
            bytes[i] = pad_value;
        }

        uint8_t state[4][4];
        bytes_to_state(bytes, state);

        add_round_key(state, expanded, 0);

        for (int i = 1; i < 10; ++i) {
            sub_bytes(state);
            shift_rows(state);
            mix_columns(state);
            add_round_key(state, expanded, i);
        }

        sub_bytes(state);
        shift_rows(state);
        add_round_key(state, expanded, 10);

        state_to_bytes(state, ciphertext + offset);

        offset += 16;

        if (read_count < 16) {
            break;
        }
    }

    return offset;
}
