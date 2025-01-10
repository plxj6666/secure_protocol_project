#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <gmp.h>
#include <stddef.h>
#include <time.h>
#include <gmp.h>
#include "sig.h"
#include "rsa.h"
#include "sha256.h"
// 将 Certificate 结构体填充到 char 数组
void certificate_to_buffer(const Certificate *cert, unsigned char *buffer) {
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
void buffer_to_certificate(const unsigned char *buffer, Certificate *cert) {
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

// 模拟的 RSA 验证签名函数，返回 1 表示验证成功，0 表示验证失败，cert为待验证证书
int rsa_verify(const unsigned char *public_key_n, const unsigned char *public_key_e, const Certificate *cert) {
    char cert_signature[256];           // 证书中的签名值
    unsigned char cert_hash[32];        // 证书的哈希值
    unsigned char encrypt_hash[32];             // 验签后的签名值

    memcpy(cert_signature, cert->signature, sizeof(cert->signature));
    memset(cert->signature, 0, sizeof(cert->signature));

    // 先hash
    unsigned char buffer[1024];
    certificate_to_buffer(cert, buffer);
    sha256(buffer, sizeof(Certificate), cert_hash);

    // 后验签
    mpz_t cipher, plaintext, e, n;
    mpz_inits(plaintext, cipher, e, n, NULL); //初始化变量
    buffer_to_mpz(e, sizeof(root_cert.public_key_e), public_key_e);
    buffer_to_mpz(n, sizeof(root_cert.public_key_n), public_key_n);
    buffer_to_mpz(plaintext, sizeof(cert_signature), cert_signature);
    encrypt(cipher, plaintext, e, n);
    mpz_to_buffer(cipher, sizeof(encrypt_hash), encrypt_hash);

    if(memcmp(encrypt_hash, cert_hash, 32) == 0){
        return 1; 
    }
    return 0;
}

// 验证证书签名是否有效
int verify_certificate(const Certificate *cert[2]) { 
    // 使用根证书公钥验证签名
    if (rsa_verify(root_cert.public_key_n, root_cert.public_key_e, cert[0])) {
        //验证有效期
        time_t current_time = time(NULL); // 获取当前时间
        time_t not_before = parse_time(cert[0]->validity_not_before);
        time_t not_after = parse_time(cert[0]->validity_not_after);

        if (not_before == (time_t)-1 || not_after == (time_t)-1) {
            printf("客户端：无效的服务器证书\n");
            return 0; // 无效的时间格式
        }

        if (!(current_time >= not_before && current_time <= not_after)) {
            printf("客户端：服务器证书已过时\n");
            return 0;
        }
    } 
    else {
        printf("客户端：服务器证书验证不通过\n");
        return 0;
    }

    //验证根证书
    if (memcmp(&root_cert, cert[1], sizeof(Certificate))) {
        printf("客户端：根证书验证不通过\n");
        return 0;
    }
    printf("客户端：证书验证通过\n");
    return 1;
}

