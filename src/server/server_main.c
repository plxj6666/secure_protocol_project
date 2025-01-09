#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <gmp.h>
#include "key_utils.h"
#include "rsa.h"
#include "close_connection.h"
#include "server.h"
#include "sha256.h"
#include "encryption.h"
#define SERVER_PORT 8080 
// 初始化服务器套接字

void init_server_socket() {
    client_seq = 0;
    server_seq = 0;
    flag = 0;
    client_close_sequence = -1;
    close_sequence = -1;
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
void server_receive_handshake_request() {
    MessagePacket request;
    if (recv(client_socket, &request, sizeof(request), 0) == -1) {
        perror("服务器: 接收握手请求失败");
        return;
    }
    if (request.type == HANDSHAKE_INIT) {
        printf("服务器: 收到握手请求 (seq: %d, ack: %d)\n", request.sequence, request.ack);

        // 3. 发送证书和握手确认
        MessagePacket response;
        response.type = HANDSHAKE_ACK;
        response.sequence = server_seq++;
        response.ack = client_seq;
        // 将证书序列化到payload
        memcpy(response.payload, &server_current_cert, sizeof(Certificate));
        response.length = sizeof(Certificate);

        if (send(client_socket, &response, sizeof(response), 0) == -1) {
            perror("服务器: 发送握手确认和证书失败");
            return;
        }

        MessagePacket root_response;
        root_response.type = HANDSHAKE_ACK;
        root_response.sequence = server_seq++;
        root_response.ack = client_seq;
        // 将证书序列化到payload
        memcpy(root_response.payload, &root_cert, sizeof(Certificate));
        root_response.length = sizeof(Certificate);

        if (send(client_socket, &root_response, sizeof(root_response), 0) == -1) {
            perror("服务器: 发送握手确认和证书失败");
            return;
        }
        printf("服务器: 已发送握手确认和证书\n");
        
        // 4. 等待接收客户端的密钥交换消息
        MessagePacket key_msg;
        if (recv(client_socket, &key_msg, sizeof(key_msg), 0) == -1) {
            perror("服务器: 接收密钥交换消息失败");
            return;
        }

        if (key_msg.type == KEY_EXCHANGE) {
            // 生成共享密钥
            unsigned char shared_secret[32];
            size_t secret_len;
            // 从证书中提取服务器公钥和私钥  
            unsigned char server_public_key[RSA_BYTES * 2];
            memcpy(server_public_key, server_current_cert.public_key_n, RSA_BYTES * 2);
            if (handle_key_exchange(&key_msg, server_private_key, server_public_key, shared_secret, &secret_len) != 0) {
                printf("服务器: 密钥交换处理失败\n");
                return;
            }
            printf("服务器: 密钥交换完成\n");
            // 6. 派生会话密钥
            if (derive_session_key(shared_secret, secret_len,
                                NULL, 0,  // 不使用盐值
                                server_session_key, 16) != 0) {
                printf("服务器: 会话密钥派生失败\n");
            }
            printf("服务器: 会话密钥为：");
            print_hex(server_session_key, 16);
            // 7. 清理敏感数据
            memset(shared_secret, 0, sizeof(shared_secret));
        }
        
        // 最终握手确认
        MessagePacket rec_finnal_ack;
        if (recv(client_socket, &rec_finnal_ack, sizeof(rec_finnal_ack), 0) == -1) {
            perror("服务器: 接收握手final确认失败");
            return;
        }
        else {
            if (rec_finnal_ack.type == HANDSHAKE_FINAL) {
                printf("服务器: 收到握手final确认\n");
            }
        }
    }
}

// 接收消息线程
void* server_receive_thread_func(void* arg) {
    MessagePacket packet;
    while (!flag) {
        // 初始化 packet
        memset(&packet, 0, sizeof(packet));

        ssize_t bytes_received = recv(client_socket, &packet, sizeof(packet), 0);
        if(packet.length > 0)
        {
            printf("服务器：接收到的消息\n");
            print_hex(packet.payload, packet.length);
        }

        if (bytes_received <= 0) {
            printf("服务器: 客户端断开连接或接收失败\n");
            flag = 1; //这是强制关闭线程的标志
            continue;
        }

        switch (packet.type) {
            case HANDSHAKE_INIT:
                server_receive_handshake_request(packet);
                break;
            case DATA_TRANSFER:
                // 调用 decrypt_message 解密消息
                if (decrypt_message(&packet, server_session_key, 16) != 0) {
                    printf("服务器: 解密消息失败\n");
                    continue;
                }
                printf("服务器: 收到客户端消息：%.*s\n", packet.length, packet.payload);
                break;
            case CLOSE_REQUEST:
                //close_sequence = packet.sequence + 1;
                handle_close_request(server_socket, packet);
                //close(server_socket);
                break;
            case CLOSE_ACK:
                    close_sequence = packet.sequence + 1;
                    printf("服务器：收到第一次关闭确认 (seq: %d, ack: %d)...\n", packet.sequence, packet.ack);
                break;
            case CLOSE_ACK_2:
                close_sequence = packet.sequence + 1;
                printf("服务器：收到第二次关闭确认 (seq: %d, ack: %d)...\n", packet.sequence, packet.ack);
                send_last_message(server_socket);
                wait_2MSL();
                close(client_socket);
                close(server_socket);
                return NULL;
                break;
            default:
            close(server_socket);
                printf("服务器: 收到未知消息类型。\n");
        }
        printf("服务端: 输入消息 (输入 'END' 关闭连接):\n");
    }
    return NULL;
}

// 发送消息线程
void* server_send_thread_func(void* arg) {
    while (!flag) {
        char str[PAYLOAD_MAX_SIZE];
        printf("服务器: 输入消息 (输入 'END' 关闭连接):\n");
        fgets(str, PAYLOAD_MAX_SIZE, stdin);

        if (strcmp(str, "END\n") == 0) {
            close_sequence = client_seq;
            flag = 1;
            close_connection(1);
            continue;
            break;
        }

        MessagePacket text;
        text.type = DATA_TRANSFER;
        text.sequence = server_seq++;
        text.ack = client_seq;
        text.length = strlen(str);
        strcpy((char*)text.payload, str);
        int encrypt_res = encrypt_message(&text, client_session_key, 16);
        printf("传输的消息: ");
        print_hex(text.payload, text.length);
        if (encrypt_res != 0) {
            printf("服务端：加密消息失败\n");
            break;
        }

        if (send(client_socket, &text, sizeof(text), 0) == -1) {
            perror("服务器: 发送消息失败");
        }
    }
    return NULL;
}
