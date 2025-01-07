#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "../../crypto/include/sha256.h"
#include "../../crypto/include/random_utils.h"
#include "../../crypto/include/rsa.h"  // RSA_SIZE defined here as 1024
#include "sig.h"
#include "sys/socket.h"
#include "../../include/key_utils.h"


// 修改函数签名，只需要服务器公钥
int exchange_keys(const unsigned char* server_public_key,
                 unsigned char* shared_secret, 
                 size_t* secret_len,
                 int socket_fd)
{
    // 1. 生成预主密钥(32字节随机数)
    unsigned char pre_master_secret[32];
    if (generate_random_bytes(pre_master_secret, sizeof(pre_master_secret)) != 0) {
        return -1;
    }

    // 2. 使用服务器公钥加密预主密钥
    mpz_t message, cipher, n, e;
    mpz_inits(message, cipher, n, e, NULL);
    
    // 从证书中的公钥初始化RSA参数
    buffer_to_mpz(n, RSA_BYTES * 2, server_public_key);  // 修改为2048位
    buffer_to_mpz(e, RSA_E_BYTES, server_public_key + RSA_BYTES * 2);  // 正确的偏移位置
    
    // 加密预主密钥
    buffer_to_mpz(message, sizeof(pre_master_secret), pre_master_secret);
    encrypt(cipher, message, e, n);  // 使用新的rsa_encrypt函数

    // 3. 构造并发送密钥交换消息
    MessagePacket key_exchange_msg;
    key_exchange_msg.type = KEY_EXCHANGE;
    key_exchange_msg.sequence = client_seq++;
    key_exchange_msg.ack = server_seq;
    
    size_t enc_len = mpz_to_buffer(cipher, RSA_BYTES, key_exchange_msg.payload);
    key_exchange_msg.length = enc_len;

    if (send(socket_fd, &key_exchange_msg, sizeof(key_exchange_msg), 0) == -1) {
        mpz_clears(message, cipher, n, e, NULL);
        return -1;
    }

    // 4. 设置共享密钥(预主密钥)
    memcpy(shared_secret, pre_master_secret, sizeof(pre_master_secret));
    *secret_len = sizeof(pre_master_secret);
    
    // 清理
    mpz_clears(message, cipher, n, e, NULL);
    memset(pre_master_secret, 0, sizeof(pre_master_secret));
    
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
    buffer_to_mpz(n, RSA_BYTES, private_key);
    buffer_to_mpz(d, RSA_BYTES, private_key + RSA_BYTES);

    // 3. 转换密文到MPZ格式
    buffer_to_mpz(cipher, msg->length, msg->payload);

    // 4. RSA解密
    decrypt(message, cipher, d, n);  // 使用新的 rsa_decrypt 函数

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