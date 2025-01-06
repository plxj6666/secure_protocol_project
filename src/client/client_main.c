#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "sig.h"
#include "server.h"
#include "client.h"
#include "close_connection.h"

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080

// 初始化客户端套接字
void init_client_socket() {
    client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        perror("客户端: 创建套接字失败");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_address.sin_addr);

    if (connect(client_socket, (struct sockaddr*)&server_address, sizeof(server_address)) == -1) {
        perror("客户端: 无法连接到服务器");
        exit(EXIT_FAILURE);
    }
    printf("客户端: 成功连接到服务器 %s:%d\n", SERVER_IP, SERVER_PORT);
}

// 发送握手请求
void send_handshake_request() {
    MessagePacket request;
    request.type = HANDSHAKE_INIT;
    request.sequence = seq++;
    request.ack = r_seq;
    memset(request.payload, 0, sizeof(request.payload));

    if (send(client_socket, &request, sizeof(request), 0) == -1) {
        perror("客户端: 发送握手请求失败");
    }
    printf("客户端: 发送握手请求 (seq: %d, ack: %d)\n", request.sequence, request.ack);

    // TODO: 在此处加入密钥交换初始化（如生成随机密钥对）
}

// 接收握手确认
void receive_handshake_response() {
    MessagePacket response;
    if (recv(client_socket, &response, sizeof(response), 0) == -1) {
        perror("客户端: 接收握手响应失败");
        return;
    }

    if (response.type == HANDSHAKE_ACK) {
        printf("客户端: 收到握手确认 (seq: %d, ack: %d)\n", response.sequence, response.ack);
        r_seq = response.sequence + 1;

        // TODO: 验证服务器的数字证书并完成密钥交换

        // 发送最终握手确认
        MessagePacket ack;
        ack.type = HANDSHAKE_FINAL;
        ack.sequence = seq++;
        ack.ack = r_seq;
        memset(ack.payload, 0, sizeof(ack.payload));

        if (send(client_socket, &ack, sizeof(ack), 0) == -1) {
            perror("客户端: 发送最终握手确认失败");
        }
        printf("客户端: 发送最终确认 (seq: %d, ack: %d)\n", ack.sequence, ack.ack);
    }
}

// 接收消息线程
void* receive_thread_func(void* arg) {
    MessagePacket packet;
    while (1) {
        ssize_t bytes_received = recv(client_socket, &packet, sizeof(packet), 0);
        if (bytes_received <= 0) {
            printf("客户端: 服务器断开连接或接收失败。\n");
            break;
        }

        switch (packet.type) {
            case DATA_TRANSFER:
                printf("客户端: 收到服务器消息：%s\n", packet.payload);
                break;
            case CLOSE_REQUEST:
                printf("客户端: 收到服务器关闭请求。\n");
                close_connection(0);
                return NULL;
            default:
                printf("客户端: 收到未知消息类型。\n");
        }
    }
    return NULL;
}

// 发送消息线程
void* send_thread_func(void* arg) {
    while (1) {
        char str[PAYLOAD_MAX_SIZE];
        printf("客户端: 输入消息 (输入 'END' 关闭连接):\n");
        scanf("%s", str);

        if (strcmp(str, "END") == 0) {
            close_connection(0);
            break;
        }

        char* encrypted_msg = encrypt_message(str);
        MessagePacket text;
        text.type = DATA_TRANSFER;
        text.sequence = seq++;
        text.ack = r_seq;
        strcpy((char*)text.payload, encrypted_msg);

        if (send(client_socket, &text, sizeof(text), 0) == -1) {
            perror("客户端: 发送消息失败");
        }
    }
    return NULL;
}
