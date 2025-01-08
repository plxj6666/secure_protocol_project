#ifndef RSA_H
#define RSA_H

#include <gmp.h>

// 常量定义
#define PRIME_SIZE 1024  // RSA密钥长度
#define RSA_BYTES (PRIME_SIZE/8)  // 128 bytes for 1024-bit RSA
#define RSA_E_BYTES 3

// 基础RSA运算函数
void mod_exp(mpz_t result, mpz_t base, mpz_t exponent, mpz_t modulus);
void gcd(mpz_t result, mpz_t a, mpz_t b);
void mod_inv(mpz_t result, mpz_t a, mpz_t m);

// 密钥生成
void generate_rsa_keys(mpz_t n, mpz_t e, mpz_t d);

// 加密解密
void encrypt(mpz_t cipher, mpz_t plaintext, mpz_t e, mpz_t n);
void decrypt(mpz_t plaintext, mpz_t cipher, mpz_t d, mpz_t n);

// 数据转换
size_t mpz_to_buffer(mpz_t big_num, size_t len, unsigned char buffer[]);
void buffer_to_mpz(mpz_t big_num, size_t bytes, const unsigned char buffer[]);

#endif /* RSA_H */
