#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

// 模拟的X.509证书结构，使用RSA签名算法，1024字节
typedef struct {
    char version[8];           // 版本号，例如 "v3"
    char serial_number[32];    // 证书序列号，唯一标识证书
    char signature_algo[32];   // 签名算法，例如 "sha256WithRSAEncryption"
    char issuer[128];          // 颁发者信息，例如 "C=US, O=ExampleCA, CN=RootCA"
    char subject[128];         // 持有者信息，例如 "C=US, O=ExampleOrg, CN=www.example.org"
    char validity_not_before[32]; // 生效日期，例如 "2023-01-01 00:00:00"
    char validity_not_after[32];  // 失效日期，例如 "2025-12-31 23:59:59"
    unsigned char public_key_n[256];     // 持有者的公钥信息，<n, e>，n为2048位，e为1024位
    unsigned char public_key_e[128];
    char extensions[128];      // 扩展字段，例如 "Key Usage: Digital Signature"
    unsigned char signature[32];      // 签名值（加密后的摘要），256位
} Certificate;

#define PAYLOAD_MAX_SIZE 1024

//the structure of data_package
typedef struct {
    uint8_t type;          // 数据包类型 (1: 握手, 2: 数据传输, 3: 关闭连接)
    uint32_t sequence;     // 序列号，用于重传或排序
    uint16_t length;       // 数据负载的长度
    uint8_t payload[PAYLOAD_MAX_SIZE]; // 实际传输的数据 (加密后)
    uint8_t mac[32];       // 消息认证码 (如 HMAC-SHA256 输出为 32 字节)
} MessagePacket;

// 模拟的根证书公钥
const char *root_public_key = "ROOT_PUBLIC_KEY";

Certificate root_cert = {
        .version = "v3",
        .serial_number = {0x03, 0x3A, 0xF1, 0xE6, 0xA7, 0x11, 0xA9, 0xA0, 0xBB, 0x28, 0x64, 0xB1, 0x1D, 0x09, 0xFA, 0xE5},
        .signature_algo = "sha256WithRSAEncryption",
        .issuer = "CN = DigiCert Global Root G2, OU = www.digicert.com, O = DigiCert Inc, C = US",
        .subject = "CN = DigiCert Global Root G2, OU = www.digicert.com, O = DigiCert Inc, C = US",
        .validity_not_before = "2013-08-01 00:00:00",
        .validity_not_after = "2038-1-15 00:00:00",
        .public_key_n =  {
            0xBB, 0x37, 0xCD, 0x34, 0xDC, 0x7B, 0x6B, 0xC9, 0xB2, 0x68, 0x90, 0xAD, 0x4A, 0x75, 0xFF, 0x46,
            0xBA, 0x21, 0x0A, 0x08, 0x8D, 0xF5, 0x19, 0x54, 0xC9, 0xFB, 0x88, 0xDB, 0xF3, 0xAE, 0xF2, 0x3A,
            0x89, 0x91, 0x3C, 0x7A, 0xE6, 0xAB, 0x06, 0x1A, 0x6B, 0xCF, 0xAC, 0x2D, 0xE8, 0x5E, 0x09, 0x24,
            0x44, 0xBA, 0x62, 0x9A, 0x7E, 0xD6, 0xA3, 0xA8, 0x7E, 0xE0, 0x54, 0x75, 0x20, 0x05, 0xAC, 0x50,
            0xB7, 0x9C, 0x63, 0x1A, 0x6C, 0x30, 0xDC, 0xDA, 0x1F, 0x19, 0xB1, 0xD7, 0x1E, 0xDE, 0xFD, 0xD7,
            0xE0, 0xCB, 0x94, 0x83, 0x37, 0xAE, 0xEC, 0x1F, 0x43, 0x4E, 0xDD, 0x7B, 0x2C, 0xD2, 0xBD, 0x2E,
            0xA5, 0x2F, 0xE4, 0xA9, 0xB8, 0xAD, 0x3A, 0xD4, 0x99, 0xA4, 0xB6, 0x25, 0xE9, 0x9B, 0x6B, 0x00,
            0x60, 0x92, 0x60, 0xFF, 0x4F, 0x21, 0x49, 0x18, 0xF7, 0x67, 0x90, 0xAB, 0x61, 0x06, 0x9C, 0x8F,
            0xF2, 0xBA, 0xE9, 0xB4, 0xE9, 0x92, 0x32, 0x6B, 0xB5, 0xF3, 0x57, 0xE8, 0x5D, 0x1B, 0xCD, 0x8C,
            0x1D, 0xAB, 0x95, 0x04, 0x95, 0x49, 0xF3, 0x35, 0x2D, 0x96, 0xE3, 0x49, 0x6D, 0xDD, 0x77, 0xE3,
            0xFB, 0x49, 0x4B, 0xB4, 0xAC, 0x55, 0x07, 0xA9, 0x8F, 0x95, 0xB3, 0xB4, 0x23, 0xBB, 0x4C, 0x6D,
            0x45, 0xF0, 0xF6, 0xA9, 0xB2, 0x95, 0x30, 0xB4, 0xFD, 0x4C, 0x55, 0x8C, 0x27, 0x4A, 0x57, 0x14,
            0x7C, 0x82, 0x9D, 0xCD, 0x73, 0x92, 0xD3, 0x16, 0x4A, 0x06, 0x0C, 0x8C, 0x50, 0xD1, 0x8F, 0x1E,
            0x09, 0xBE, 0x17, 0xA1, 0xE6, 0x21, 0xCA, 0xFD, 0x83, 0xE5, 0x10, 0xBC, 0x83, 0xA5, 0x0A, 0xC4,
            0x67, 0x28, 0xF6, 0x73, 0x14, 0x14, 0x3D, 0x46, 0x76, 0xC3, 0x87, 0x14, 0x89, 0x21, 0x34, 0x4D,
            0xAF, 0x0F, 0x45, 0x0C, 0xA6, 0x49, 0xA1, 0xBA, 0xBB, 0x9C, 0xC5, 0xB1, 0x33, 0x83, 0x29, 0x85
        },
        .public_key_e = {0x01, 0x00, 0x01},
        .extensions = "Key Usage: Digital Signature, Key Encipherment",
        .signature = 0xAB
};

// 模拟的 RSA 验证签名函数，返回 1 表示验证成功，0 表示验证失败
int rsa_verify(const char *public_key_n, const char *public_key_e, const char *message, const char *signature) {
    return 1; 
}

// 将 Certificate 结构体填充到 char 数组
void certificate_to_buffer(const Certificate *cert, char *buffer) {
    size_t offset = 0;

    // 按顺序填充到 buffer
    memcpy(buffer + offset, cert->version, sizeof(cert->version));
    offset += sizeof(cert->version);

    memcpy(buffer + offset, cert->serial_number, sizeof(cert->serial_number));
    offset += sizeof(cert->serial_number);

    memcpy(buffer + offset, cert->signature_algo, sizeof(cert->signature_algo));
    offset += sizeof(cert->signature_algo);

    memcpy(buffer + offset, cert->issuer, sizeof(cert->issuer));
    offset += sizeof(cert->issuer);

    memcpy(buffer + offset, cert->subject, sizeof(cert->subject));
    offset += sizeof(cert->subject);

    memcpy(buffer + offset, cert->validity_not_before, sizeof(cert->validity_not_before));
    offset += sizeof(cert->validity_not_before);

    memcpy(buffer + offset, cert->validity_not_after, sizeof(cert->validity_not_after));
    offset += sizeof(cert->validity_not_after);

    memcpy(buffer + offset, cert->public_key_n, sizeof(cert->public_key_n));
    offset += sizeof(cert->public_key_n);

    memcpy(buffer + offset, cert->public_key_e, sizeof(cert->public_key_e));
    offset += sizeof(cert->public_key_e);

    memcpy(buffer + offset, cert->extensions, sizeof(cert->extensions));
    offset += sizeof(cert->extensions);

    memcpy(buffer + offset, cert->signature, sizeof(cert->signature));
    offset += sizeof(cert->signature);
}

// 从 char 数组解析出 Certificate 结构体
void buffer_to_certificate(const char *buffer, Certificate *cert) {
    size_t offset = 0;

    // 按顺序从 buffer 解析到 Certificate 结构体
    memcpy(cert->version, buffer + offset, sizeof(cert->version));
    offset += sizeof(cert->version);

    memcpy(cert->serial_number, buffer + offset, sizeof(cert->serial_number));
    offset += sizeof(cert->serial_number);

    memcpy(cert->signature_algo, buffer + offset, sizeof(cert->signature_algo));
    offset += sizeof(cert->signature_algo);

    memcpy(cert->issuer, buffer + offset, sizeof(cert->issuer));
    offset += sizeof(cert->issuer);

    memcpy(cert->subject, buffer + offset, sizeof(cert->subject));
    offset += sizeof(cert->subject);

    memcpy(cert->validity_not_before, buffer + offset, sizeof(cert->validity_not_before));
    offset += sizeof(cert->validity_not_before);

    memcpy(cert->validity_not_after, buffer + offset, sizeof(cert->validity_not_after));
    offset += sizeof(cert->validity_not_after);

    memcpy(cert->public_key_n, buffer + offset, sizeof(cert->public_key_n));
    offset += sizeof(cert->public_key_n);

    memcpy(cert->public_key_e, buffer + offset, sizeof(cert->public_key_e));
    offset += sizeof(cert->public_key_e);

    memcpy(cert->extensions, buffer + offset, sizeof(cert->extensions));
    offset += sizeof(cert->extensions);

    memcpy(cert->signature, buffer + offset, sizeof(cert->signature));
    offset += sizeof(cert->signature);
}

// 将时间字符串解析为 time_t 类型
// 自定义时间解析函数
time_t parse_time(const char *time_str) {
    struct tm tm_time;
    memset(&tm_time, 0, sizeof(tm_time));

    // 手动解析时间字符串
    if (sscanf(time_str, "%4d-%2d-%2d %2d:%2d:%2d",
               &tm_time.tm_year, &tm_time.tm_mon, &tm_time.tm_mday,
               &tm_time.tm_hour, &tm_time.tm_min, &tm_time.tm_sec) != 6) {
        fprintf(stderr, "Invalid time format: %s\n", time_str);
        return (time_t)-1;
    }

    // 修正年份和月份
    tm_time.tm_year -= 1900; // tm_year 从 1900 开始计数
    tm_time.tm_mon -= 1;     // tm_mon 从 0 开始计数

    // 转换为 time_t 类型
    return mktime(&tm_time);
}

// 验证证书签名是否有效
int verify_certificate(const Certificate *cert[2], char *message) {
    // 使用根证书公钥验证签名
    if (rsa_verify(root_cert.public_key_n, root_cert.public_key_e, message, cert[0]->signature)) {
        //验证有效期
        time_t current_time = time(NULL); // 获取当前时间
        time_t not_before = parse_time(cert[0]->validity_not_before);
        time_t not_after = parse_time(cert[0]->validity_not_after);

        if (not_before == (time_t)-1 || not_after == (time_t)-1) {
            printf("[Client]: Failed to parse certificate validity dates.\n");
            return 0; // 无效的时间格式
        }

        if (!(current_time >= not_before && current_time <= not_after)) {
            printf("[Client]: Certificate verification failed.\n");
            return 0;
        }
    } 
    else {
        printf("[Client]: Certificate verification failed.\n");
        return 0;
    }

    //验证根证书
    if (memcmp(&root_cert, cert[1], sizeof(Certificate))) {
        printf("[Client]: Untrusted root certificate!\n");
        return 0;
    }
    printf("[Client]: Certificate verification passed.\n");
    return 1;
}

// 测试代码
int main() {
    // 构造一个模拟的证书
    Certificate cert = {
        .version = "v3",
        .serial_number = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF},
        .signature_algo = "sha256WithRSAEncryption",
        .issuer = "C=US, O=ExampleCA, CN=RootCA",
        .subject = "C=US, O=ExampleOrg, CN=www.example.org",
        .validity_not_before = "2023-01-01 00:00:00",
        .validity_not_after = "2025-12-31 23:59:59",
        .public_key_n = {0xAB},
        .public_key_e = {0x01, 0x00, 0x01},
        .extensions = "Key Usage: Digital Signature, Key Encipherment",
        .signature = {0xAB}
    };

    //消息准备
    MessagePacket message;
    certificate_to_buffer(&cert, message.payload);

    // 验证证书
    Certificate server_cert;
    buffer_to_certificate(message.payload, &server_cert);
    Certificate *cert_chain[2] = {&server_cert, &root_cert};
    verify_certificate(cert_chain, message.payload);

    return 0;
}
