/**
 * \file aes.h
 * \author Isaiah Lateer
 *
 * Interface for AES.
 */

#ifndef AES_HEADER
#define AES_HEADER

#include <stdint.h>

/**
 * Performs key expansion, creating a 176-byte (44-word) value from a 128-bit
 * key.
 * 
 * \param[in] key 128-bit key.
 * \param[out] expanded 44-word expanded key.
 */
void expand_key(uint8_t key[16], uint32_t expanded[44]);

#endif
