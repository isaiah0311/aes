/**
 * \file aes.h
 * \author Isaiah Lateer
 *
 * Interface for AES.
 */

#ifndef AES_HEADER
#define AES_HEADER

#include <stdint.h>
#include <stdio.h>

/**
 * Encrypts a file using AES in ECB mode.
 *
 * \param[in] key Encryption key.
 * \param[in] plaintext File to be encrypted.
 * \param[in] byte_count Number of bytes in ciphertext.
 * \param[out] ciphertext Encrypted data.
 * \return Number of encrypted bytes.
 */
size_t aes_ecb_encrypt(uint8_t key[16], FILE* plaintext, size_t byte_count,
    uint8_t* ciphertext);

/**
 * Encrypts a file using AES in CBC mode.
 *
 * \param[in] key Encryption key.
 * \param[in] iv Initialization vector.
 * \param[in] plaintext File to be encrypted.
 * \param[in] byte_count Number of bytes in ciphertext.
 * \param[out] ciphertext Encrypted data.
 * \return Number of encrypted bytes.
 */
size_t aes_cbc_encrypt(uint8_t key[16], uint8_t iv[16], FILE* plaintext,
    size_t byte_count, uint8_t* ciphertext);

/**
 * Decryts a file using AES in ECB mode.
 *
 * \param[in] key Encryption key.
 * \param[in] ciphertext File to be decrypted.
 * \param[in] byte_count Number of bytes in plaintext.
 * \param[out] plaintext Decrypted data.
 * \return Number of decrypted bytes.
 */
size_t aes_ecb_decrypt(uint8_t key[16], FILE* ciphertext, size_t byte_count,
    uint8_t* plaintext);

/**
 * Decryts a file using AES in CBC mode.
 *
 * \param[in] key Encryption key.
 * \param[in] iv Initialization vector.
 * \param[in] ciphertext File to be decrypted.
 * \param[in] byte_count Number of bytes in plaintext.
 * \param[out] plaintext Decrypted data.
 * \return Number of decrypted bytes.
 */
size_t aes_cbc_decrypt(uint8_t key[16], uint8_t iv[16], FILE* ciphertext,
    size_t byte_count, uint8_t* plaintext);

#endif
