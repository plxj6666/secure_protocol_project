#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../../crypto/include/sha256.h"
#include "../../crypto/include/random_utils.h"
#include "../../crypto/include/rsa.h"  // RSA_SIZE defined here as 1024
#include "../../include/sig.h"
#include "../../include/key_utils.h"

#define RSA_BYTES (PRIME_SIZE/8)  // 128 bytes for 1024-bit RSA

// 生成共享密钥
// 参数:
// - local_private_key: 本地的私钥 (字节数组格式)
// - peer_public_key: 对方的公钥 (字节数组格式)
// - shared_secret: 输出的共享密钥
// - secret_len: 共享密钥的长度
// - socket_fd: 用于发送消息的socket文件描述符
// 返回值: 成功返回0，失败返回非0
int exchange_keys(const unsigned char* local_private_key, 
                  const unsigned char* peer_public_key, 
                  unsigned char* shared_secret, size_t* secret_len,
                  int socket_fd) // 添加socket参数用于发送消息
{
    // 1. 生成随机数S
    unsigned char random_s[32];
    if (generate_random_bytes(random_s, sizeof(random_s)) != 0) {
        return -1;
    }

    // 2. 初始化RSA变量
    mpz_t message, cipher, n, e;
    mpz_inits(message, cipher, n, e, NULL);

    // 3. 转换peer_public_key到MPZ格式
    buffer_to_mpz(n, RSA_BYTES, peer_public_key);
    mpz_set_ui(e, 65537);  // 固定公钥指数

    // 4. 转换随机数到MPZ格式
    buffer_to_mpz(message, sizeof(random_s), random_s);

    // 5. RSA加密
    encrypt(cipher, message, e, n);

    // 6. 转换加密结果到buffer
    unsigned char encrypted_s[RSA_BYTES];
    size_t enc_len = mpz_to_buffer(cipher, sizeof(encrypted_s), encrypted_s);
    if(enc_len == -1) {
        mpz_clears(message, cipher, n, e, NULL);
        return -1;
    }

    // 7. 构造并发送密钥交换消息
    MessagePacket key_exchange_msg;
    key_exchange_msg.type = KEY_EXCHANGE;
    key_exchange_msg.sequence = seq++;
    key_exchange_msg.ack = r_seq;
    memcpy(key_exchange_msg.payload, encrypted_s, enc_len);
    key_exchange_msg.length = enc_len;

    // 通过socket发送消息
    if (send(socket_fd, &key_exchange_msg, sizeof(key_exchange_msg), 0) == -1) {
        mpz_clears(message, cipher, n, e, NULL);
        return -1;
    }

    // 8. 清理RSA变量
    mpz_clears(message, cipher, n, e, NULL);

    // 9. 设置共享密钥
    memcpy(shared_secret, random_s, sizeof(random_s));
    *secret_len = sizeof(random_s);
    
    return 0;
}

// 处理接收到的密钥交换消息
int handle_key_exchange(const MessagePacket* msg, 
                       const unsigned char* private_key,
                       unsigned char* shared_secret,
                       size_t* secret_len) 
{
    // 1. 初始化RSA变量
    mpz_t message, cipher, n, d;
    mpz_inits(message, cipher, n, d, NULL);

    // 2. 转换private_key到MPZ格式
    buffer_to_mpz(d, RSA_BYTES, private_key);
    buffer_to_mpz(n, RSA_BYTES, private_key + RSA_BYTES);

    // 3. 转换密文到MPZ格式
    buffer_to_mpz(cipher, msg->length, msg->payload);

    // 4. RSA解密
    decrypt(message, cipher, d, n);

    // 5. 转换解密结果到buffer
    *secret_len = 32;  // 预期的随机数长度
    if(mpz_to_buffer(message, *secret_len, shared_secret) == -1) {
        mpz_clears(message, cipher, n, d, NULL);
        return -1;
    }

    // 6. 清理RSA变量
    mpz_clears(message, cipher, n, d, NULL);
    
    return 0;
}