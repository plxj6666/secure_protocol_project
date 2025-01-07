#ifndef SIG_H
#define SIG_H

#include <stdint.h>

#define PAYLOAD_MAX_SIZE 1024

// 结构体定义
typedef struct {  
    uint8_t type;          // 数据包类型 (1: 握手, 2: 数据传输, 3: 关闭连接)
    uint32_t sequence;     // 序列号，用于重传或排序
    uint16_t length;       // 数据负载的长度
    uint16_t ack;       // 确认号，用于确认收到的数据包
    uint8_t payload[PAYLOAD_MAX_SIZE]; // 实际传输的数据 (加密后)
    uint8_t mac[32];       // 消息认证码 (如 HMAC-SHA256 输出为 32 字节)
} MessagePacket;

// 模拟的X.509证书结构，使用RSA签名算法，1024字节
typedef struct {
    char version[8];           // 版本号，例如 "v3"
    char serial_number[32];    // 证书序列号，唯一标识证书
    char signature_algo[32];   // 签名算法，例如 "sha256WithRSAEncryption"
    char issuer[128];          // 颁发者信息，例如 "C=US, O=ExampleCA, CN=RootCA"
    char subject[128];         // 持有者信息，例如 "C=US, O=ExampleOrg, CN=www.example.org"
    char validity_not_before[32]; // 生效日期，例如 "2023-01-01 00:00:00"
    char validity_not_after[32];  // 失效日期，例如 "2025-12-31 23:59:59"
    unsigned char public_key_n[256];     // 持有者的公钥信息，<n, e>，n为2048位，e为24位
    unsigned char public_key_e[3];
    char extensions[128];      // 扩展字段，例如 "Key Usage: Digital Signature"
    unsigned char signature[32];      // 签名值（加密后的摘要），256位
} Certificate;

// 全局变量声明
extern Certificate root_cert;
extern Certificate server_current_cert;
extern int client_socket;
extern int server_socket;
extern int client_seq;
extern int server_seq;
extern int flag;
extern unsigned char server_session_key[16];
extern unsigned char client_session_key[16];
// 消息类型定义
#define HANDSHAKE_INIT  1   // 握手初始化
#define HANDSHAKE_ACK   2   // 握手确认
#define DATA_TRANSFER   3   // 加密数据传输
#define CLOSE_REQUEST   4   // 关闭连接请求
#define CLOSE_ACK       5   // 关闭连接确认
#define ACK             6   //普通的信息
#define KEY_EXCHANGE    7   //密钥交换
#define HANDSHAKE_FINAL 8   //第三次握手
#define CLOSE_ACK_2     9   //四次挥手需要两次确认

#endif /* SIG_H */
