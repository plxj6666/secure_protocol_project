#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include "sig.h"

// 模拟的 RSA 验证签名函数，返回 1 表示验证成功，0 表示验证失败
//TODO
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
            printf("[Client]: Certificate has expired.\n");
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
// int main() {
//     // 构造一个模拟的证书
//     Certificate cert = {
//         .version = "v3",
//         .serial_number = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF},
//         .signature_algo = "sha256WithRSAEncryption",
//         .issuer = "C=US, O=ExampleCA, CN=RootCA",
//         .subject = "C=US, O=ExampleOrg, CN=www.example.org",
//         .validity_not_before = "2023-01-01 00:00:00",
//         .validity_not_after = "2025-12-31 23:59:59",
//         .public_key_n = {0xAB},
//         .public_key_e = {0x01, 0x00, 0x01},
//         .extensions = "Key Usage: Digital Signature, Key Encipherment",
//         .signature = {0xAB}
//     };

//     //消息准备
//     MessagePacket message;
//     certificate_to_buffer(&cert, message.payload);

//     // 验证证书
//     Certificate server_cert;
//     buffer_to_certificate(message.payload, &server_cert);

//     Certificate *cert_chain[2] = {&server_cert, &root_cert};        //一定要是证书链 TODO
//     verify_certificate(cert_chain, message.payload);

//     return 0;
// }
