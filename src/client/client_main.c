#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "server.h"
#include "client.h"
#include "close_connection.h"
#include "rsa.h"
#include "key_utils.h"
#include <gmp.h>
#include <encryption.h>
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080

int s_seq = 0;

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
void client_send_handshake_request() {
    // 1. 发送初始握手请求
    MessagePacket request;
    request.type = HANDSHAKE_INIT;
    request.sequence = client_seq++;
    request.ack = server_seq;
    memset(request.payload, 0, sizeof(request.payload));
    if (send(client_socket, &request, sizeof(request), 0) == -1) {
        perror("客户端: 发送握手请求失败");
        return;
    }
    printf("客户端: 发送握手请求 (seq: %d, ack: %d)\n", request.sequence, request.ack); 
}

// 接收握手确认
void client_receive_handshake_response() {
    MessagePacket cert_msg;
    recv(client_socket, &cert_msg, sizeof(cert_msg), 0);

    MessagePacket root_cert_msg;
    recv(client_socket, &root_cert_msg, sizeof(root_cert_msg), 0);
    
    Certificate server_cert, server_root_cert;
    buffer_to_certificate(cert_msg.payload, &server_cert);
    buffer_to_certificate(root_cert_msg.payload, &server_root_cert);

    Certificate *cert_chain[2] = {&server_cert, &server_root_cert};
    verify_certificate(cert_chain);  // 验证证书
    
    // 从证书中提取服务器公钥  
    unsigned char server_public_key[RSA_BYTES * 2 + RSA_E_BYTES];
    memcpy(server_public_key, server_cert.public_key_n, RSA_BYTES * 2);
    memcpy(server_public_key + RSA_BYTES * 2, server_cert.public_key_e, RSA_E_BYTES);
    
    // 4. 执行密钥交换
    unsigned char shared_secret[32];
    size_t secret_len;
    
    if (exchange_keys(server_cert.public_key_n,  // 从证书中提取的公钥
                    shared_secret, 
                    &secret_len,
                    client_socket) != 0) {
        printf("客户端: 密钥交换失败\n");
        return;
    }
    
    // 等待服务器的密钥交换确认
    printf("客户端: 等待密钥交换确认\n");
    MessagePacket key_ack;
    if (recv(client_socket, &key_ack, sizeof(key_ack), 0) == -1) {
        printf("客户端: 等待密钥交换确认失败\n");
        return;
    }
    
    if (key_ack.type != KEY_EXCHANGE) {
        printf("客户端: 收到意外的消息类型\n");
        return;
    }
    
    printf("客户端: 密钥交换完成并得到确认\n");
    
    // 5. 派生会话密钥
    if (derive_session_key(shared_secret, secret_len,
                        NULL, 0,
                        client_session_key, 16) != 0) {
        printf("客户端: 会话密钥派生失败\n");
    }
    // 输出查看会话密钥
    printf("客户端: 会话密钥为: ");
    print_hex(client_session_key, 16);
    // 6. 清理敏感数据
    memset(shared_secret, 0, sizeof(shared_secret));
    
    // 发送最终握手确认
    MessagePacket ack;
    ack.type = HANDSHAKE_FINAL;
    ack.sequence = client_seq++;
    ack.ack = key_ack.sequence + 1;
    memset(ack.payload, 0, sizeof(ack.payload));

    if (send(client_socket, &ack, sizeof(ack), 0) == -1) {
        perror("客户端: 发送最终握手确认失败");
    }
    printf("客户端: 发送最终确认 (seq: %d, ack: %d)\n", ack.sequence, ack.ack);
}

// 接收消息线程
void* client_receive_thread_func(void* arg) {
    MessagePacket packet;
    while (1) {

        // 初始化 packet
        memset(&packet, 0, sizeof(packet));

        ssize_t bytes_received = recv(client_socket, &packet, sizeof(packet), 0);
        if(packet.length > 0)
        {
            printf("客户端：接收到的消息\n");
            print_hex(packet.payload, packet.length);
        }
        if (bytes_received <= 0) {
            printf("客户端: 服务器断开连接或接收失败。\n");
            break;
        }
        s_seq = packet.sequence + 1;
        switch (packet.type) {
            case DATA_TRANSFER:
                //printf("客户端: 收到服务器消息：%s\n", packet.payload);
                // 调用 decrypt_message 解密消息
                if (decrypt_message(&packet, client_session_key, 16) != 0) {
                    printf("客户端: 解密消息失败\n");
                    continue;
                }
                printf("客户端: 收到服务器消息：%.*s\n", packet.length, packet.payload);
                printf("客户端: 输入消息 (输入 'END' 关闭连接):\n");
                break;
            case CLOSE_REQUEST:
                //client_close_sequence = packet.sequence + 1;
                printf("client_close_sequence: %d\n", client_close_sequence);
                handle_close_request(client_socket, packet);
                //close(client_socket);
                break;
            case CLOSE_ACK:
                client_close_sequence = packet.sequence + 1;
                printf("客户端：收到第一次关闭确认 (seq: %d, ack: %d)...\n", packet.sequence, packet.ack);
                break;
            case CLOSE_ACK_2:
                client_close_sequence = packet.sequence + 1;
                printf("客户端：收到第二次关闭确认 (seq: %d, ack: %d)...\n", packet.sequence, packet.ack);
                send_last_message(server_socket);
                wait_2MSL();
                close(client_socket);               
                break;
            default:
                printf("客户端: 收到未知消息类型。\n");
        }
    }
    return NULL;
}

// 发送消息线程
void* client_send_thread_func(void* arg) {
    while (1) {
        char str[PAYLOAD_MAX_SIZE];
        printf("客户端: 输入消息 (输入 'END' 关闭连接):\n");
        fgets(str, PAYLOAD_MAX_SIZE, stdin);

        if (strcmp(str, "END\n") == 0) {
            client_close_sequence = server_seq;
            flag = 1;
            close_connection(0);
            break;
        }
        MessagePacket text;
        text.type = DATA_TRANSFER;
        text.sequence = client_seq++;
        text.ack = server_seq;
        text.length = strlen(str);
        strcpy((char*)text.payload, str);

        // aes128加密铭文
        // 调用 encrypt_message 加密消息
        int encrypt_res = encrypt_message(&text, client_session_key, 16);
        printf("传输的消息: ");
        print_hex(text.payload, text.length);
        if (encrypt_res != 0) {
            printf("客户端：加密数据失败\n");
            break;
        }

        if (send(client_socket, &text, sizeof(text), 0) == -1) {
            perror("客户端: 发送消息失败");
        }
    }
    return NULL;
}
