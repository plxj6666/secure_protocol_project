#ifndef SHA256_H
#define SHA256_H

#include <stdint.h>
#include <stddef.h>

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];             // 哈希状态
    uint64_t bitlen;               // 处理的数据长度
    uint8_t data[SHA256_BLOCK_SIZE]; // 数据块缓冲区
    uint32_t datalen;              // 当前缓冲区长度
} SHA256_CTX;

void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len);
void sha256_final(SHA256_CTX *ctx, uint8_t *hash);
void sha256(const uint8_t *data, size_t len, uint8_t *hash);

#endif