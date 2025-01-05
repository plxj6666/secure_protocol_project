#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include "../include/sha256.h"

void print_hash(uint8_t *hash) {
    for(int i = 0; i < 32; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

void test_empty_string() {
    uint8_t hash[32];
    const char *input = "";
    // 空字符串的已知SHA256值
    const char *expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    
    sha256((uint8_t*)input, strlen(input), hash);
    
    printf("Empty string test:\n");
    printf("Expected: %s\n", expected);
    printf("Got:      ");
    print_hash(hash);
}

void test_simple_string() {
    uint8_t hash[32];
    const char *input = "hello world";
    // "hello world"的已知SHA256值
    const char *expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
    
    sha256((uint8_t*)input, strlen(input), hash);
    
    printf("\nSimple string test:\n");
    printf("Expected: %s\n", expected);
    printf("Got:      ");
    print_hash(hash);
}

void test_long_string() {
    uint8_t hash[32];
    char input[1000];
    memset(input, 'A', 999);
    input[999] = '\0';
    
    sha256((uint8_t*)input, strlen(input), hash);
    
    printf("\nLong string test (999 'A's):\n");
    printf("Got: ");
    print_hash(hash);
}

// 添加新的测试函数
void test_max_block() {
    // 测试大小为64字节的输入(一个完整数据块)
    uint8_t hash[32];
    char input[64];
    memset(input, 'B', 64);
    
    sha256((uint8_t*)input, 64, hash);
    printf("\nSingle block test (64 bytes):\n");
    printf("Got: ");
    print_hash(hash);
}

void test_large_input() {
    // 测试1MB大小的输入
    uint8_t hash[32];
    const size_t size = 1024 * 1024 * 100; // 1MB
    char *input = malloc(size);
    if(!input) {
        printf("Memory allocation failed\n");
        return;
    }
    
    memset(input, 'C', size);
    sha256((uint8_t*)input, size, hash);
    
    printf("\nLarge input test (1MB):\n");
    printf("Got: ");
    print_hash(hash);
    
    free(input);
}

int main() {
    printf("Running SHA256 tests...\n\n");
    
    test_empty_string();
    test_simple_string();
    test_long_string();
    test_max_block();    // 添加新测试
    test_large_input();  // 添加新测试
    
    printf("\nAll tests completed.\n");
    return 0;
}