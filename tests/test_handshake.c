#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../crypto/include/sha256.h"
#include "../include/key_utils.h"

// 打印十六进制值
void print_hex(const unsigned char* data, size_t len) {
    for(size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// 测试HKDF密钥派生
void test_key_derivation() {
    printf("\n测试密钥派生功能:\n");
    
    const unsigned char ikm[] = "argcxiang test shared secret";
    const unsigned char salt[] = "salt value";
    unsigned char derived_key[16];
    size_t key_len = 16;  // AES-128密钥长度
    
    // 测试1: 使用盐值
    printf("\n测试1 - 使用盐值:\n");
    int ret = derive_session_key(ikm, strlen((char*)ikm),
                               salt, strlen((char*)salt),
                               derived_key, key_len);
    
    assert(ret == 0);
    printf("派生密钥: ");
    print_hex(derived_key, key_len);
    
    // 测试2: 不使用盐值
    printf("\n测试2 - 不使用盐值:\n");
    ret = derive_session_key(ikm, strlen((char*)ikm),
                           NULL, 0,
                           derived_key, key_len);
    
    assert(ret == 0);
    printf("派生密钥: ");
    print_hex(derived_key, key_len);
    
    // 测试3: 错误处理
    printf("\n测试3 - 错误处理:\n");
    ret = derive_session_key(NULL, 0, NULL, 0, derived_key, key_len);
    assert(ret == -1);
    printf("空输入测试通过\n");
    
    printf("\n所有测试通过!\n");
}

int main() {
    test_key_derivation();
    return 0;
}
