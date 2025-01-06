#include "sha256.h"
#include "sig.h"
#include "key_utils.h"


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