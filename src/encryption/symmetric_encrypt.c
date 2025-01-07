#include "encryption.h"
#include "../../crypto/include/sha256.h"
#include "../../crypto/include/random_utils.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <wmmintrin.h>

#define AES_128_KEY_EXPAND_ASSIST(temp1, temp2, temp3, rcon) \
    temp2 = _mm_aeskeygenassist_si128(temp1, rcon); \
    temp3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(temp2), _mm_castsi128_ps(temp2), 0xff)); \
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4)); \
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4)); \
    temp1 = _mm_xor_si128(temp1, _mm_slli_si128(temp1, 4)); \
    temp1 = _mm_xor_si128(temp1, temp3)

void print_hex1(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/**
 * @brief Expand AES encryption key
 * @param key Original key
 * @param subKeys Generated encryption subkeys
 */
int aes_make_enc_subkeys(const unsigned char key[16], unsigned char subKeys[11][16])
{
    __m128i temp1, temp2, temp3;

    temp1 = _mm_loadu_si128((const __m128i *)key); // 加载原始密钥
    _mm_storeu_si128((__m128i *)subKeys[0], temp1);

    AES_128_KEY_EXPAND_ASSIST(temp1, temp2, temp3, 0x01);
    _mm_storeu_si128((__m128i *)subKeys[1], temp1);
    AES_128_KEY_EXPAND_ASSIST(temp1, temp2, temp3, 0x02);
    _mm_storeu_si128((__m128i *)subKeys[2], temp1);
    AES_128_KEY_EXPAND_ASSIST(temp1, temp2, temp3, 0x04);
    _mm_storeu_si128((__m128i *)subKeys[3], temp1);
    AES_128_KEY_EXPAND_ASSIST(temp1, temp2, temp3, 0x08);
    _mm_storeu_si128((__m128i *)subKeys[4], temp1);
    AES_128_KEY_EXPAND_ASSIST(temp1, temp2, temp3, 0x10);
    _mm_storeu_si128((__m128i *)subKeys[5], temp1);
    AES_128_KEY_EXPAND_ASSIST(temp1, temp2, temp3, 0x20);
    _mm_storeu_si128((__m128i *)subKeys[6], temp1);
    AES_128_KEY_EXPAND_ASSIST(temp1, temp2, temp3, 0x40);
    _mm_storeu_si128((__m128i *)subKeys[7], temp1);
    AES_128_KEY_EXPAND_ASSIST(temp1, temp2, temp3, 0x80);
    _mm_storeu_si128((__m128i *)subKeys[8], temp1);
    AES_128_KEY_EXPAND_ASSIST(temp1, temp2, temp3, 0x1B);
    _mm_storeu_si128((__m128i *)subKeys[9], temp1);
    AES_128_KEY_EXPAND_ASSIST(temp1, temp2, temp3, 0x36);
    _mm_storeu_si128((__m128i *)subKeys[10], temp1);

    return 0;
}


/**
 * @brief Expand AES decryption key
 * @param key Original key
 * @param subKeys Generated decryption subkeys
 */
int aes_make_dec_subkeys(const unsigned char key[16], unsigned char subKeys[11][16])
{
    __m128i encSubKeys[11];
    aes_make_enc_subkeys(key, (unsigned char(*)[16])encSubKeys);

    // Reverse order of round keys and apply AESNI inverse mix column
    _mm_storeu_si128((__m128i *)subKeys[10], encSubKeys[0]);
    for (int i = 1; i < 10; i++)
    {
        __m128i temp = _mm_aesimc_si128(encSubKeys[10 - i]);
        _mm_storeu_si128((__m128i *)subKeys[i], temp);
    }
    _mm_storeu_si128((__m128i *)subKeys[0], encSubKeys[10]);

    return 0;
}

/**
 * @brief AES encrypt single block
 * @param input Plaintext
 * @param subKeys Encryption subkeys
 * @param output Ciphertext
 */
void aes_encrypt_block(const unsigned char *input, unsigned char subKeys[11][16], unsigned char *output)
{
    __m128i block = _mm_loadu_si128((const __m128i *)input); // Load plaintext
    block = _mm_xor_si128(block, _mm_loadu_si128((const __m128i *)subKeys[0]));

    for (int i = 1; i < 10; i++)
    {
        block = _mm_aesenc_si128(block, _mm_loadu_si128((const __m128i *)subKeys[i]));
    }

    block = _mm_aesenclast_si128(block, _mm_loadu_si128((const __m128i *)subKeys[10]));
    _mm_storeu_si128((__m128i *)output, block); // Store ciphertext
}

/**
 * @brief AES decrypt single block
 * @param input Ciphertext
 * @param subKeys Decryption subkeys
 * @param output Plaintext
 */
void aes_decrypt_block(const unsigned char *input, unsigned char subKeys[11][16], unsigned char *output)
{
    __m128i block = _mm_loadu_si128((const __m128i *)input); // Load ciphertext
    block = _mm_xor_si128(block, _mm_loadu_si128((const __m128i *)subKeys[0]));

    for (int i = 1; i < 10; i++)
    {
        block = _mm_aesdec_si128(block, _mm_loadu_si128((const __m128i *)subKeys[i]));
    }

    block = _mm_aesdeclast_si128(block, _mm_loadu_si128((const __m128i *)subKeys[10]));
    _mm_storeu_si128((__m128i *)output, block); // Store plaintext
}

/**
 * @brief AES CBC mode encryption
 * @param input Plaintext
 * @param inputLength Length of plaintext (must be multiple of 16)
 * @param iv Initialization vector
 * @param subKeys Encryption subkeys
 * @param output Ciphertext
 */
void aes_cbc_encrypt(const unsigned char *input, unsigned int inputLength, const unsigned char iv[AES_BLOCK_SIZE], unsigned char subKeys[11][16], unsigned char *output) {
    // 计算填充后的长度
    unsigned int paddedLength = inputLength + (AES_BLOCK_SIZE - (inputLength % AES_BLOCK_SIZE));
    unsigned char *paddedInput = (unsigned char *)malloc(paddedLength);

    // 复制输入数据
    memcpy(paddedInput, input, inputLength);

    // PKCS#7 填充
    unsigned char paddingValue = AES_BLOCK_SIZE - (inputLength % AES_BLOCK_SIZE);
    for (unsigned int i = inputLength; i < paddedLength; i++) {
        paddedInput[i] = paddingValue;
    }

    printf("加密填充值: %d\n", paddingValue);
    printf("填充后的明文: ");
    print_hex1(paddedInput, paddedLength);

    // 初始化反馈（IV）
    unsigned char feedback[AES_BLOCK_SIZE];
    memcpy(feedback, iv, AES_BLOCK_SIZE);

    // 加密每个块
    for (unsigned int i = 0; i < paddedLength; i += AES_BLOCK_SIZE) {
        // XOR 明文块和反馈块（IV 或前一密文块）
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            paddedInput[i + j] ^= feedback[j];
        }

        // 加密当前块
        aes_encrypt_block(paddedInput + i, subKeys, output + i);

        // 更新反馈为当前密文块
        memcpy(feedback, output + i, AES_BLOCK_SIZE);
    }

    free(paddedInput);
}

/**
     * @brief AES CBC mode decryption
     * @param[in] input ciphertext, [length = inputLength]
     * @param[in] inputLength length of ciphertext
     * @param[in] iv initialization vector, [length = AES_BLOCK_SIZE]
     * @param[in] subKeys decryption subkeys
     * @param[out] output plaintext, [length = inputLength]
     */
void aes_cbc_decrypt(const unsigned char *input, unsigned int inputLength, const unsigned char iv[AES_BLOCK_SIZE], unsigned char subKeys[11][16], unsigned char *output) {
    // 检查输入长度是否为块大小的整数倍
    if (inputLength % AES_BLOCK_SIZE != 0) {
        fprintf(stderr, "Error: Ciphertext length is not a multiple of AES block size.\n");
        return;
    }

    unsigned char feedback[AES_BLOCK_SIZE];
    unsigned char temp[AES_BLOCK_SIZE]; // 保存当前密文块

    // 初始化反馈（IV）
    memcpy(feedback, iv, AES_BLOCK_SIZE);

    for (unsigned int i = 0; i < inputLength; i += AES_BLOCK_SIZE) {
        // 保存当前密文块
        memcpy(temp, input + i, AES_BLOCK_SIZE);

        // 解密当前块
        aes_decrypt_block(input + i, subKeys, output + i);

        // XOR 解密结果与反馈（IV 或前一密文块）
        for (int j = 0; j < AES_BLOCK_SIZE; j++) {
            output[i + j] ^= feedback[j];
        }

        // 更新反馈为当前密文块
        memcpy(feedback, temp, AES_BLOCK_SIZE);
    }

}




// 加密消息
int encrypt_message(MessagePacket* packet, const uint8_t* key, size_t key_len) {
    if (key_len != AES_KEY_SIZE) {
        return -1;
    }

    // 生成随机数
    unsigned char random_bytes[16];
    if (generate_random_bytes(random_bytes, sizeof(random_bytes)) != 0) {
        return -1;
    }

    // 计算消息哈希值
    unsigned char hash[SHA256_DIGEST_SIZE];
    sha256(packet->payload, packet->length, hash);

    // 构造加密前的明文 (随机数 + 哈希值 + 原始消息)
    unsigned int plaintextLength = 16 + SHA256_DIGEST_SIZE + packet->length; // 随机数 + 哈希值 + 原始消息
    unsigned char *plaintext = (unsigned char *)malloc(plaintextLength);
    if (!plaintext) {
        return -1;
    }
    memcpy(plaintext, random_bytes, 16);
    memcpy(plaintext + 16, hash, SHA256_DIGEST_SIZE);
    memcpy(plaintext + 16 + SHA256_DIGEST_SIZE, packet->payload, packet->length);

    // 生成加密子密钥
    unsigned char subKeys[11][16];
    aes_make_enc_subkeys(key, subKeys);

    // 初始化向量 (IV)
    unsigned char iv[AES_BLOCK_SIZE];
    if (generate_random_bytes(iv, sizeof(iv)) != 0) {
        free(plaintext);
        return -1;
    }

    // 计算加密后长度 (PKCS#7 填充在 aes_cbc_encrypt 中完成)
    unsigned int paddedLength = plaintextLength + (AES_BLOCK_SIZE - (plaintextLength % AES_BLOCK_SIZE));
    unsigned char *ciphertext = (unsigned char *)malloc(paddedLength);
    if (!ciphertext) {
        free(plaintext);
        return -1;
    }

    printf("加密使用的 IV: ");
    print_hex1(iv, AES_BLOCK_SIZE);

    // 加密消息
    aes_cbc_encrypt(plaintext, plaintextLength, iv, subKeys, ciphertext);

    // 将 IV 和密文存储到 payload 中
    memcpy(packet->payload, iv, AES_BLOCK_SIZE);
    memcpy(packet->payload + AES_BLOCK_SIZE, ciphertext, paddedLength);

    // 更新消息长度
    packet->length = AES_BLOCK_SIZE + paddedLength;

    // 清理内存
    free(plaintext);
    free(ciphertext);

    return 0;
}


int decrypt_message(MessagePacket* packet, const uint8_t* key, size_t key_len) {
    if (key_len != AES_KEY_SIZE) {
        return -1;
    }

    // 生成解密子密钥
    unsigned char subKeys[11][16];
    aes_make_dec_subkeys(key, subKeys);

    // 提取 IV
    unsigned char iv[AES_BLOCK_SIZE];
    memcpy(iv, packet->payload, AES_BLOCK_SIZE);
    printf("解密使用的 IV: ");
    print_hex1(iv, AES_BLOCK_SIZE);

    // 提取密文
    unsigned int ciphertextLength = packet->length - AES_BLOCK_SIZE;
    if (ciphertextLength % AES_BLOCK_SIZE != 0) {
        fprintf(stderr, "Error: Ciphertext length is not a multiple of AES block size.\n");
        return -1;
    }
    unsigned char *ciphertext = (unsigned char *)malloc(ciphertextLength);
    if (!ciphertext) {
        return -1;
    }
    memcpy(ciphertext, packet->payload + AES_BLOCK_SIZE, ciphertextLength);
    printf("提取的密文: ");
    print_hex1(ciphertext, packet->length - AES_BLOCK_SIZE);

    // 解密消息
    unsigned char *plaintext = (unsigned char *)malloc(ciphertextLength);
    if (!plaintext) {
        free(ciphertext);
        return -1;
    }
    aes_cbc_decrypt(ciphertext, ciphertextLength, iv, subKeys, plaintext);

    // 打印解密后的明文
    printf("解密后的完整明文: ");
    print_hex1(plaintext, ciphertextLength);

    // 提取填充长度
    unsigned char paddingValue = plaintext[ciphertextLength - 1];
    if (paddingValue == 0 || paddingValue > AES_BLOCK_SIZE) {
        fprintf(stderr, "Padding verification failed: invalid padding value (%d).\n", paddingValue);
        free(ciphertext);
        free(plaintext);
        return -1;
    }

    // 验证填充是否正确
    for (unsigned int i = ciphertextLength - paddingValue; i < ciphertextLength; i++) {
        if (plaintext[i] != paddingValue) {
            fprintf(stderr, "Padding verification failed: inconsistent padding.\n");
            free(ciphertext);
            free(plaintext);
            return -1;
        }
    }

    //去除填充后的长度
    unsigned int plaintextLength = ciphertextLength - paddingValue;

    // 提取随机数和哈希值
    unsigned char random_bytes[16];
    unsigned char hash[SHA256_DIGEST_SIZE];
    memcpy(random_bytes, plaintext, 16);
    memcpy(hash, plaintext + 16, SHA256_DIGEST_SIZE);

    // 验证消息哈希值
    unsigned char computed_hash[SHA256_DIGEST_SIZE];
    sha256(plaintext + 16 + SHA256_DIGEST_SIZE, plaintextLength - 16 - SHA256_DIGEST_SIZE, computed_hash);
    if (memcmp(hash, computed_hash, SHA256_DIGEST_SIZE) != 0) {
        fprintf(stderr, "Message hash verification failed.\n");
        free(ciphertext);
        free(plaintext);
        return -1;
    }

    // 更新消息内容和长度
    packet->length = plaintextLength - 16 - SHA256_DIGEST_SIZE;
    memcpy(packet->payload, plaintext + 16 + SHA256_DIGEST_SIZE, packet->length);

    // 清理内存
    free(ciphertext);
    free(plaintext);

    return 0;
}
