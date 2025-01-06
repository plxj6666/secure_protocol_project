#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "sig.h"
#include "close_connection.h"

#define SERVER_PORT 8080

// 初始化服务器套接字
void init_server_socket() {
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("服务器: 创建套接字失败");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_address, client_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(SERVER_PORT);
    server_address.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr*)&server_address, sizeof(server_address)) == -1) {
        perror("服务器: 绑定失败");
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 5) == -1) {
        perror("服务器: 监听失败");
        exit(EXIT_FAILURE);
    }
    printf("服务器: 正在监听端口 %d...\n", SERVER_PORT);

    socklen_t client_addr_len = sizeof(client_address);
    client_socket = accept(server_socket, (struct sockaddr*)&client_address, &client_addr_len);
    if (client_socket == -1) {
        perror("服务器: 接收客户端连接失败");
        exit(EXIT_FAILURE);
    }
    printf("服务器: 客户端已连接\n");
}

// 接收握手请求
void receive_handshake_request() {
    MessagePacket request;
    if (recv(client_socket, &request, sizeof(request), 0) == -1) {
        perror("服务器: 接收握手请求失败");
        return;
    }

    if (request.type == HANDSHAKE_INIT) {
        printf("服务器: 收到握手请求 (seq: %d, ack: %d)\n", request.sequence, request.ack);

        // TODO: 验证客户端证书并生成密钥

        // 发送握手确认
        MessagePacket response;
        response.type = HANDSHAKE_ACK;
        response.sequence = server_seq++;
        response.ack = request.sequence + 1;
        memset(response.payload, 0, sizeof(response.payload));

        if (send(client_socket, &response, sizeof(response), 0) == -1) {
            perror("服务器: 发送握手确认失败");
        }
        printf("服务器: 已发送握手确认\n");
    }
}

// 接收消息线程
void* receive_thread_func(void* arg) {
    MessagePacket packet;
    while (1) {
        ssize_t bytes_received = recv(client_socket, &packet, sizeof(packet), 0);
        if (bytes_received <= 0) {
            printf("服务器: 客户端断开连接或接收失败。\n");
            break;
        }

        switch (packet.type) {
            case DATA_TRANSFER:
                printf("服务器: 收到客户端消息：%s\n", packet.payload);
                break;
            case CLOSE_REQUEST:
                printf("服务器: 收到客户端关闭请求。\n");
                close_connection(1);
                return NULL;
            default:
                printf("服务器: 收到未知消息类型。\n");
        }
    }
    return NULL;
}

// 发送消息线程
void* send_thread_func(void* arg) {
    while (1) {
        char str[PAYLOAD_MAX_SIZE];
        printf("服务器: 输入消息 (输入 'END' 关闭连接):\n");
        scanf("%s", str);

        if (strcmp(str, "END") == 0) {
            close_connection(1);
            break;
        }

        MessagePacket text;
        text.type = DATA_TRANSFER;
        text.sequence = server_seq++;
        strcpy((char*)text.payload, str);

        if (send(client_socket, &text, sizeof(text), 0) == -1) {
            perror("服务器: 发送消息失败");
        }
    }
    return NULL;
}
