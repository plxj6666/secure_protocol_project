#include "sha256.h"
#include "sig.h"
#include "key_utils.h"
#include <string.h>

#define HASH_LEN 32  // SHA256哈希长度

// HMAC内部使用的填充常量

#define IPAD 0x36
#define OPAD 0x5C
#define BLOCK_SIZE 64  // SHA256的块大小

// HMAC-SHA256实现
static void hmac_sha256(const unsigned char* key, size_t key_len,
                       const unsigned char* data, size_t data_len,
                       unsigned char* out) {
    SHA256_CTX ctx;
    unsigned char k_ipad[BLOCK_SIZE];
    unsigned char k_opad[BLOCK_SIZE];
    unsigned char inner_hash[HASH_LEN];
    
    // 1. 如果密钥长度>块大小,则使用哈希函数处理密钥
    unsigned char key_buf[BLOCK_SIZE];
    if (key_len > BLOCK_SIZE) {
        sha256(key, key_len, key_buf);
        key = key_buf;
        key_len = HASH_LEN;
    }
    
    // 2. 填充密钥到块大小
    memset(k_ipad, 0, BLOCK_SIZE);
    memset(k_opad, 0, BLOCK_SIZE);
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);
    
    // 3. 异或填充值
    for (int i = 0; i < BLOCK_SIZE; i++) {
        k_ipad[i] ^= IPAD;
        k_opad[i] ^= OPAD;
    }
    
    // 4. 内部哈希
    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, BLOCK_SIZE);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, inner_hash);
    
    // 5. 外部哈希
    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, BLOCK_SIZE);
    sha256_update(&ctx, inner_hash, HASH_LEN);
    sha256_final(&ctx, out);
}

// HKDF提取函数 - 从输入密钥材料(IKM)和盐值生成伪随机密钥(PRK)
static void hkdf_extract(const unsigned char* salt, size_t salt_len,
                        const unsigned char* ikm, size_t ikm_len,
                        unsigned char* prk) {
    // 如果没有提供盐值,使用全零的哈希长度盐值
    unsigned char zero_salt[HASH_LEN] = {0};
    if (!salt || salt_len == 0) {
        salt = zero_salt;
        salt_len = HASH_LEN;
    }
    
    // PRK = HMAC-Hash(salt, IKM)
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
}

// HKDF扩展函数 - 从PRK生成指定长度的输出密钥材料(OKM)
static void hkdf_expand(const unsigned char* prk, 
                       unsigned char* okm, size_t okm_len) {
    unsigned char T[HASH_LEN];
    unsigned char T_tmp[HASH_LEN + 1];
    size_t N = (okm_len + HASH_LEN - 1) / HASH_LEN;
    size_t pos = 0;
    
    // T = T(1) | T(2) | T(3) | ... | T(N)
    // T(0) = empty string
    // T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
    // T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
    // ...
    memset(T, 0, HASH_LEN);
    for (int i = 1; i <= N; i++) {
        size_t tmp_len = 0;
        if (i > 1) {
            memcpy(T_tmp, T, HASH_LEN);
            tmp_len = HASH_LEN;
        }
        T_tmp[tmp_len] = i;
        
        hmac_sha256(prk, HASH_LEN, T_tmp, tmp_len + 1, T);
        
        size_t copy_len = (i != N) ? HASH_LEN : (okm_len - pos);
        memcpy(okm + pos, T, copy_len);
        pos += HASH_LEN;
    }
}

// 密钥派生函数
// 参数:
// - shared_secret: 输入的共享密钥
// - secret_len: 共享密钥的长度
// - salt: 可选的盐值 (可以为空)
// - salt_len: 盐值长度
// - derived_key: 输出的对称密钥 (如 AES 密钥)
// - key_len: 对称密钥的长度 (如 128/256 位)
// 返回值: 成功返回0，失败返回非0
int derive_session_key(const unsigned char* shared_secret, size_t secret_len, 
                       const unsigned char* salt, size_t salt_len, 
                       unsigned char* derived_key, size_t key_len);

// 密钥派生函数实现
int derive_session_key(const unsigned char* shared_secret, size_t secret_len,
                      const unsigned char* salt, size_t salt_len,
                      unsigned char* derived_key, size_t key_len) {
    if (!shared_secret || !derived_key || key_len == 0) {
        return -1;
    }
    
    // 1. 提取阶段 - 从共享密钥和盐值生成PRK
    unsigned char prk[HASH_LEN];
    hkdf_extract(salt, salt_len, shared_secret, secret_len, prk);
    
    // 2. 扩展阶段 - 从PRK生成最终的会话密钥
    hkdf_expand(prk, derived_key, key_len);
    
    // 安全清除中间值
    memset(prk, 0, HASH_LEN);
    
    return 0;
}