#ifndef RSA_H
#define RSA_H

#include <gmp.h>

// 常量定义
#define PRIME_SIZE 1024  // RSA密钥长度
#define RSA_BYTES (PRIME_SIZE/8)  // 128 bytes for 1024-bit RSA
// 函数声明

/**
 * 计算模幂运算: result = base^exponent mod modulus
 */
void mod_exp(mpz_t result, mpz_t base, mpz_t exponent, mpz_t modulus);

/**
 * 计算最大公约数: result = gcd(a,b)
 */
void gcd(mpz_t result, mpz_t a, mpz_t b);

/**
 * 计算模逆: result = a^(-1) mod m
 */
void mod_inv(mpz_t result, mpz_t a, mpz_t m);

/**
 * 生成RSA密钥对
 * @param n 模数
 * @param e 公钥指数
 * @param d 私钥指数
 */
void generate_rsa_keys(mpz_t n, mpz_t e, mpz_t d);

/**
 * RSA加密
 * @param cipher 密文输出
 * @param message 明文输入
 * @param e 公钥指数
 * @param n 模数
 */
void rsa_encrypt(mpz_t cipher, mpz_t message, mpz_t e, mpz_t n);

/**
 * RSA解密
 * @param message 明文输出
 * @param cipher 密文输入
 * @param d 私钥指数
 * @param n 模数
 */
void rsa_decrypt(mpz_t message, mpz_t cipher, mpz_t d, mpz_t n);

#endif /* RSA_H */