#include <stdio.h>
#include "sig.h"

void process_message(const MessagePacket* packet) {
    switch (packet->type) {
        case HANDSHAKE_INIT:
            printf("Processing handshake request.\n");
            // 执行握手请求逻辑
            break;

        case HANDSHAKE_ACK:
            printf("Processing handshake response.\n");
            // 执行握手确认逻辑
            break;

        case DATA_TRANSFER:
            printf("Processing data transfer.\n");
            // 处理加密数据
            break;

        case CLOSE_REQUEST:
            printf("Processing close request.\n");
            // 处理连接关闭逻辑
            break;

        default:
            printf("Unknown message type.\n");
    }
}
