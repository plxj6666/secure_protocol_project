#include "sig.h"
#include "stddef.h"
#include <gmp.h>
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
// - cert: 输入的证书链
// 返回值: 成功返回0，失败返回非0
int verify_certificate(const Certificate* cert[]);



// 生成共享密钥
// 参数:
// - local_private_key: 本地的私钥 (字节数组格式)
// - peer_public_key: 对方的公钥 (字节数组格式)
// - shared_secret: 输出的共享密钥
// - secret_len: 共享密钥的长度
// 返回值: 成功返回0，失败返回非0
int exchange_keys(const unsigned char* peer_public_key, 
                  unsigned char* shared_secret, size_t* secret_len,
                  int socket_fd);

// 处理接收到的密钥交换消息
// 参数: 
// - msg: 输入的密钥交换消息
// - private_key: 本地的私钥
// - shared_secret: 输出的共享密钥
// - secret_len: 共享密钥的长度
int handle_key_exchange(const MessagePacket* msg, 
                       const mpz_t d,  // 改为直接使用mpz_t类型
                       const mpz_t n,
                       unsigned char* shared_secret,
                       size_t* secret_len); 

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

// 将 Certificate 结构体填充到 char 数组
// 参数：
// - cert: 输入的证书结构体
// - buffer: 输出的 char 数组
void buffer_to_certificate(const char *buffer, Certificate *cert);
