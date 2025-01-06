<<<<<<< HEAD
#include <cstdint>

#define PAYLOAD_MAX_SIZE 1024

//the structure of data_package
typedef struct {
    uint8_t type;          // 数据包类型 (1: 握手, 2: 数据传输, 3: 关闭连接)
    uint32_t sequence;     // 序列号，用于重传或排序
    uint16_t length;       // 数据负载的长度
    uint8_t payload[PAYLOAD_MAX_SIZE]; // 实际传输的数据 (加密后)
    uint8_t mac[32];       // 消息认证码 (如 HMAC-SHA256 输出为 32 字节)
} MessagePacket;

// 模拟的X.509证书结构，使用RSA签名算法
typedef struct {
    char version[8];           // 版本号，例如 "v3"
    char serial_number[32];    // 证书序列号，唯一标识证书
    char signature_algo[64];   // 签名算法，例如 "sha256WithRSAEncryption"
    char issuer[256];          // 颁发者信息，例如 "C=US, O=ExampleCA, CN=RootCA"
    char subject[256];         // 持有者信息，例如 "C=US, O=ExampleOrg, CN=www.example.org"
    char validity_not_before[32]; // 生效日期，例如 "2023-01-01 00:00:00"
    char validity_not_after[32];  // 失效日期，例如 "2025-12-31 23:59:59"
    char public_key[1024];     // 持有者的公钥信息
    char extensions[512];      // 扩展字段，例如 "Key Usage: Digital Signature"
    char signature[1024];      // 签名值（加密后的摘要）
} Certificate;


//the following defines are the types of the mesage
#define HANDSHAKE_INIT  1   // 握手初始化
#define HANDSHAKE_ACK   2   // 握手确认
#define DATA_TRANSFER   3   // 加密数据传输
#define CLOSE_REQUEST   4   // 关闭连接请求
#define CLOSE_ACK       5   // 关闭连接确认
#define ACK             6   //普通的信息


//the following are the state of c/s
int server_alive = 0;
int client_alive = 0;
int flag = 1;  // 标志变量，用于指示是否关闭连接，初始位于关闭状态
