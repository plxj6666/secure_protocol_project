#include "sig.h"
#include "stddef.h"

// 对证书进行数字签名
// 参数:
// - cert: 输入的证书结构体
// - private_key: 签名者的私钥 (PEM 格式)
// - signature: 输出的签名 (加密后的摘要)
// - sig_len: 签名长度
// 返回值: 成功返回0，失败返回非0
int sign_certificate(const Certificate* cert, const char* private_key, 
                     unsigned char* signature, size_t* sig_len);




// 验证证书的数字签名
// 参数:
// - cert: 输入的证书结构体
// - public_key: 颁发者的公钥 (PEM 格式)
// 返回值: 成功返回0，失败返回非0
int verify_certificate(const Certificate* cert, const char* public_key);



// 生成共享密钥
// 参数:
// - local_private_key: 本地的私钥 (字节数组格式)
// - peer_public_key: 对方的公钥 (字节数组格式)
// - shared_secret: 输出的共享密钥
// - secret_len: 共享密钥的长度
// 返回值: 成功返回0，失败返回非0
int exchange_keys(const unsigned char* local_private_key, 
                  const unsigned char* peer_public_key, 
                  unsigned char* shared_secret, size_t* secret_len,
                  int socket_fd);



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



// 加密数据包中的 payload
// 参数:
// - packet: 输入的消息包
// - key: 对称密钥
// - key_len: 密钥长度
// 返回值: 成功返回0，失败返回非0
int encrypt_message(MessagePacket* packet, const unsigned char* key, size_t key_len);



// 解密数据包中的 payload
// 参数:
// - packet: 输入的加密消息包
// - key: 对称密钥
// - key_len: 密钥长度
// 返回值: 成功返回0，失败返回非0
int decrypt_message(MessagePacket* packet, const unsigned char* key, size_t key_len);
