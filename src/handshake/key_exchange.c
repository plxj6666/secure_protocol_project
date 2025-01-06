#include <string.h>
#include <stdio.h>
#include <stdlib.h>
# include "../../crypto/include/sha256.h"
# include "../../include/sig.h"
# include "../../include/key_utils.h"

// 生成共享密钥
// 参数:
// - local_private_key: 本地的私钥 (字节数组格式)
// - peer_public_key: 对方的公钥 (字节数组格式)
// - shared_secret: 输出的共享密钥
// - secret_len: 共享密钥的长度
// 返回值: 成功返回0，失败返回非0
int exchange_keys(const unsigned char* local_private_key, 
                  const unsigned char* peer_public_key, 
                  unsigned char* shared_secret, size_t* secret_len) 
{
    // 1. 生成随机数S (这里应该使用加密安全的随机数生成器)
    unsigned char random_s[32];  // 256位随机数
    for(int i = 0; i < 32; i++) {
        random_s[i] = rand() % 256;  // 注意：实际中应使用crypto安全的随机数生成
    }
    
    // 2. 使用服务器的公钥加密S (这里需要调用RSA加密函数)
    unsigned char encrypted_s[256];  // RSA-2048加密后的长度
    size_t enc_len = 256;
    
    // 加密随机数S (示例代码，实际需要调用真实的RSA加密函数)
    // rsa_encrypt(random_s, 32, peer_public_key, encrypted_s, &enc_len);
    
    // 3. 构造并发送密钥交换消息
    MessagePacket key_exchange_msg;
    key_exchange_msg.type = DATA_TRANSFER;  // 或定义新的消息类型如KEY_EXCHANGE
    memcpy(key_exchange_msg.payload, encrypted_s, enc_len);
    key_exchange_msg.length = enc_len;
    
    // 4. 发送消息到服务器 (使用已有的通信函数)
    recieve(key_exchange_msg);  // 调用server.h中定义的接收函数
    
    // 5. 将生成的随机数S作为共享密钥返回
    memcpy(shared_secret, random_s, 32);
    *secret_len = 32;
    
    return 0;  // 成功返回0
}

// 在server端需要添加处理密钥交换消息的代码:
void handle_key_exchange(MessagePacket message, const unsigned char* server_private_key) {
    // 1. 使用服务器私钥解密收到的随机数S
    unsigned char decrypted_s[32];
    size_t dec_len = 32;
    
    // 解密收到的数据 (示例代码，实际需要调用真实的RSA解密函数)
    // rsa_decrypt(message.payload, message.length, server_private_key, 
    //            decrypted_s, &dec_len);
    
    // 2. 使用解密得到的S作为共享密钥
    // 可以存储在全局变量或上下文中供后续使用
    unsigned char shared_secret[32];
    memcpy(shared_secret, decrypted_s, 32);
}