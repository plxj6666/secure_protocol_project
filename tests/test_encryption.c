
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../include/encryption.h"

void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void test_encrypt_decrypt() {
    printf("测试消息加密和解密功能:\n");

    // 原始消息
    MessagePacket packet;
    packet.type = DATA_TRANSFER;
    packet.sequence = 1;
    packet.ack = 0;
    const char* message = "Hello, this is a test message!";
    packet.length = strlen(message);
    memcpy(packet.payload, message, packet.length);

    // 加密密钥
    unsigned char key[AES_KEY_SIZE] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                       0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};

    // 加密消息
    int ret = encrypt_message(&packet, key, AES_KEY_SIZE);
    assert(ret == 0);
    printf("加密后的消息: ");
    print_hex(packet.payload, packet.length);

    // 保存原始长度
    size_t original_length = packet.length;

    // 解密消息
    ret = decrypt_message(&packet, key, AES_KEY_SIZE);
    assert(ret == 0);
    printf("解密后的消息:");
    print_hex(packet.payload, packet.length);

    // 验证解密后的消息是否与原始消息一致
    assert(memcmp(packet.payload, message, strlen(message)) == 0);
    printf("消息加密和解密测试通过!\n");
}


int main() {
    test_encrypt_decrypt();
    return 0;
}