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

    //输出前32字节内容
    unsigned char temp_buffer[RSA_BYTES * 2];
    mpz_to_buffer(cipher, RSA_BYTES * 2, temp_buffer);
    // 3. 构造并发送密钥交换消息
    MessagePacket key_exchange_msg;
    key_exchange_msg.type = KEY_EXCHANGE;
    key_exchange_msg.sequence = client_seq++;
    key_exchange_msg.ack = server_seq;
    // 先清零payload
    memset(key_exchange_msg.payload, 0, sizeof(key_exchange_msg.payload));
    size_t enc_len = mpz_to_buffer(cipher, RSA_BYTES * 2, key_exchange_msg.payload);
    key_exchange_msg.length = enc_len;
    if (send(socket_fd, &key_exchange_msg, sizeof(key_exchange_msg), 0) == -1) {
        mpz_clears(message, cipher, n, e, NULL);
        return -1;
    }
    printf("客户端: 发送密钥交换消息\n");
    // 4. 设置共享密钥(预主密钥)
    memcpy(shared_secret, pre_master_secret, sizeof(pre_master_secret));
    *secret_len = sizeof(pre_master_secret);
    
    // 清理
    mpz_clears(message, cipher, n, e, NULL);
    memset(pre_master_secret, 0, sizeof(pre_master_secret));
    
    return 0;
}

// 修改函数实现
int handle_key_exchange(const MessagePacket* msg, 
                       const unsigned char * server_private_key_d,
                       const unsigned char * server_public_key_n,
                       unsigned char* shared_secret,
                       size_t* secret_len) 
{
    mpz_t message, cipher;
    mpz_inits(message, cipher, NULL);
    // 转换密文到MPZ格式
    buffer_to_mpz(cipher, msg->length, msg->payload);

    // RSA解密
    mpz_t d, n;
    mpz_inits(d, n, NULL);
    buffer_to_mpz(n, RSA_BYTES * 2, server_public_key_n);
    buffer_to_mpz(d, RSA_BYTES * 2, server_private_key_d);
    decrypt(message, cipher, d, n);

    // 设置正确的密钥长度（32字节预主密钥）
    *secret_len = 32;  
    
    // 从解密结果的低32字节提取预主密钥
    unsigned char temp_buffer[RSA_BYTES * 2];
    mpz_to_buffer(message, RSA_BYTES * 2, temp_buffer);
    // 输出解密后的前32字节
    memcpy(shared_secret, temp_buffer, 32);
    // 清理RSA变量
    mpz_clears(message, cipher, NULL);
    memset(temp_buffer, 0, sizeof(temp_buffer));
    MessagePacket key_ack;
    key_ack.type = KEY_EXCHANGE;
    key_ack.sequence = server_seq++;
    key_ack.ack = client_seq;
    memset(key_ack.payload, 0, sizeof(key_ack.payload));
    if (send(client_socket, &key_ack, sizeof(key_ack), 0) == -1) {
        perror("服务器: 发送密钥交换确认失败");
        return -1;
    }
    return 0;
}