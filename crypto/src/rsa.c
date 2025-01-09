#include "rsa.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>


// 计算a^b mod n
void mod_exp(mpz_t result, mpz_t base, mpz_t exponent, mpz_t modulus) {
    mpz_powm(result, base, exponent, modulus);  // 使用GMP的powm函数进行模幂计算
}

// 计算最大公约数
void gcd(mpz_t result, mpz_t a, mpz_t b) {
    mpz_gcd(result, a, b);  // 使用GMP的gcd函数
}

// 计算模逆
void mod_inv(mpz_t result, mpz_t a, mpz_t m) {
    mpz_invert(result, a, m);  // 使用GMP的invert函数计算模逆
}

// 生成RSA密钥对
void generate_rsa_keys(mpz_t n, mpz_t e, mpz_t d) 
{
    mpz_t p, q, phi_n, gcd_result;

    mpz_inits(p, q, phi_n, gcd_result, NULL);

    // 初始化变量
    gmp_randstate_t state;
    gmp_randinit_mt(state);  // 初始化随机数生成器

    // 生成两个大质数p和q
    mpz_urandomb(p, state, PRIME_SIZE);
    mpz_nextprime(p, p);

    mpz_urandomb(q, state, PRIME_SIZE);
    mpz_nextprime(q, q);

    // 计算n = p * q
    mpz_mul(n, p, q);

    // 计算φ(n) = (p-1) * (q-1)
    mpz_sub_ui(p, p, 1);
    mpz_sub_ui(q, q, 1);
    mpz_mul(phi_n, p, q);

    // 选择公钥e（通常选择为65537）
    mpz_set_ui(e, 65537);

    // 计算私钥d，满足 e * d ≡ 1 (mod φ(n))
    mod_inv(d, e, phi_n);

    mpz_clears(p, q, phi_n, gcd_result, NULL);
}

// 加密
void encrypt(mpz_t cipher, mpz_t plaintext, mpz_t e, mpz_t n) {
    mod_exp(cipher, plaintext, e, n);  // 计算 ciphertext = plaintext^e mod n
}

// 解密
void decrypt(mpz_t plaintext, mpz_t cipher, mpz_t d, mpz_t n) {
    mod_exp(plaintext, cipher, d, n);  // 计算 plaintext = ciphertext^d mod n
}

size_t mpz_to_buffer(mpz_t big_num, size_t len, const unsigned char buffer[]){
    size_t bytes;
    mpz_export(buffer, &bytes, 1, 1, 1, 0, big_num);
    if(bytes > len){
        return -1;
    }
    return bytes;
}

void buffer_to_mpz(mpz_t big_num, size_t bytes, const unsigned char buffer[]){
    mpz_import(big_num, bytes, 1, 1, 1, 0, buffer);
}

// // 接口示例
// int main() {
//     // 1.密钥生成
//     mpz_t n, e, d;
//     mpz_t plaintext, ciphertext, decrypted_text;
//     mpz_inits(n, e, d, plaintext, ciphertext, decrypted_text, NULL); //初始化变量
//     generate_rsa_keys(n, e, d); // 生成RSA密钥对
    
//     // 2.加密
//     // 准备变量
//     mpz_set_ui(plaintext, 12345);
//     gmp_printf("Encrypted: %Zx\n", plaintext);
//     encrypt(ciphertext, plaintext, e, n);
//     gmp_printf("Encrypted: %Zx\n", ciphertext);

//     // 3.解密
//     decrypt(decrypted_text, ciphertext, d, n);
//     gmp_printf("Decrypted: %Zx\n", decrypted_text);

//     // 清空
//     mpz_clears(n, e, d, plaintext, ciphertext, decrypted_text, NULL);
//     return 0;
// }
