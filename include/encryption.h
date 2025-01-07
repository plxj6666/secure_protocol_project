#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <stddef.h>
#include <stdint.h>
#include "sig.h"

#define AES_BLOCK_BITS 128 /* bits of AES algoithm block */
#define AES_BLOCK_SIZE 16  /* bytes of AES algoithm block */
#define AES_KEY_SIZE 16    /* bytes of AES algoithm double key */

/**
    * @brief Generate encryption subkeys
    * @param[in] key original key
    * @param[out] subKeys generated encryption subkeys
    * @return 0 OK
    * @return 1 Failed
    */
int aes_make_enc_subkeys(const unsigned char key[16], unsigned char subKeys[11][16]);

/**
    * @brief Generate decryption subkeys
    * @param[in] key original key
    * @param[out] subKeys generated decryption subkeys
    * @return 0 OK
    * @return 1 Failed
    */
int aes_make_dec_subkeys(const unsigned char key[16], unsigned char subKeys[11][16]);

/**
    * @brief AES encrypt single block
    * @param[in] input plaintext, [length = AES_BLOCK_SIZE]
    * @param[in] subKeys subKeys
    * @param[out] output ciphertext, [length = AES_BLOCK_SIZE]
    */
void aes_encrypt_block(const unsigned char *input, unsigned char subKeys[11][16], unsigned char *output);

/**
    * @brief AES decrypt single block
    * @param[in] input ciphertext, [length = AES_BLOCK_SIZE]
    * @param[in] subKeys subKeys
    * @param[out] output plaintext, [length = AES_BLOCK_SIZE]
    */
void aes_decrypt_block(const unsigned char *input, unsigned char subKeys[11][16], unsigned char *output);

/**
    * @brief AES CBC mode encryption
    * @param[in] input plaintext, [length = inputLength]
    * @param[in] inputLength length of plaintext
    * @param[in] iv initialization vector, [length = AES_BLOCK_SIZE]
    * @param[in] subKeys encryption subkeys
    * @param[out] output ciphertext, [length = inputLength]
    */
void aes_cbc_encrypt(const unsigned char *input, unsigned int inputLength, const unsigned char iv[AES_BLOCK_SIZE], unsigned char subKeys[11][16], unsigned char *output);

/**
    * @brief AES CBC mode decryption
    * @param[in] input ciphertext, [length = inputLength]
    * @param[in] inputLength length of ciphertext
    * @param[in] iv initialization vector, [length = AES_BLOCK_SIZE]
    * @param[in] subKeys decryption subkeys
    * @param[out] output plaintext, [length = inputLength]
    */
void aes_cbc_decrypt(const unsigned char *input, unsigned int inputLength, const unsigned char iv[AES_BLOCK_SIZE], unsigned char subKeys[11][16], unsigned char *output);

/**
    * @brief Encrypt message with AES-128 and add hash and random number
    * @param[in] packet message packet to be encrypted
    * @param[in] key encryption key
    * @param[in] key_len length of the encryption key
    * @return 0 on success, non-zero on failure
    */
int encrypt_message(MessagePacket* packet, const uint8_t* key, size_t key_len);

/**
    * @brief Decrypt message with AES-128 and verify hash and random number
    * @param[in] packet message packet to be decrypted
    * @param[in] key decryption key
    * @param[in] key_len length of the decryption key
    * @return 0 on success, non-zero on failure
    */
int decrypt_message(MessagePacket* packet, const uint8_t* key, size_t key_len);

#endif // ENCRYPTION_H