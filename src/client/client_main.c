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
#include "../crypto/include/rsa.h"
#include "key_utils.h"
#include <gmp.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8080
char session_key[16];   // 派生密钥，暂且这样写着

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

    // 2. 接收服务器的证书
    MessagePacket cert_msg;
    if (recv(client_socket, &cert_msg, sizeof(cert_msg), 0) == -1) {
        perror("客户端: 接收服务器证书失败");
        return;
    }
    
    // 3. 验证证书并提取公钥
    Certificate server_cert;
    // memcpy(&server_cert, cert_msg.payload, sizeof(Certificate));
    
    // TODO: 实现证书验证
    // verify_certificate(&server_cert, &root_cert);
    
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
    // 5. 派生会话密钥
    if (derive_session_key(shared_secret, secret_len,
                          NULL, 0,
                          session_key, 16) != 0) {
        printf("客户端: 会话密钥派生失败\n");
    }

    printf("客户端: 密钥交换完成\n");
    
    // 6. 清理敏感数据
    memset(shared_secret, 0, sizeof(shared_secret));
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
        

        // TODO: 验证服务器的数字证书并完成密钥交换

        // 发送最终握手确认
        MessagePacket ack;
        ack.type = HANDSHAKE_FINAL;
        ack.sequence = client_seq++;
        ack.ack = server_seq;
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
                // printf("客户端: 收到服务器关闭请求。\n");
                
                // // 发送关闭确认消息 (CLOSE_ACK)
                // MessagePacket ack_1;
                // ack_1.type = CLOSE_ACK;
                // ack_1.sequence = client_seq++;
                // ack_1.ack = server_seq;
                // memset(ack_1.payload, 0, sizeof(ack_1.payload));

                // if (send(client_socket, &ack, sizeof(ack_1), 0) == -1) {
                //     perror("客户端: 发送关闭确认失败");
                // }
                // printf("客户端: 发送关闭确认 (CLOSE_ACK)。\n");

                // // 模拟等待 (TIME_WAIT)
                // usleep(200000);  // 等待 200 毫秒 (可以根据实际需要调整)

                // // 发送第二次关闭确认消息 (CLOSE_ACK_2)
                // MessagePacket ack2;
                // ack2.type = CLOSE_ACK_2;
                // ack2.sequence = client_seq++;
                // ack2.ack = server_seq;
                // memset(ack2.payload, 0, sizeof(ack2.payload));

                // if (send(client_socket, &ack2, sizeof(ack2), 0) == -1) {
                //     perror("客户端: 发送第二次关闭确认失败");
                // }
                // printf("客户端: 发送第二次关闭确认 (CLOSE_ACK_2)。\n");
                handle_close_request(client_socket, packet);
                wait_2MSL();
                close(client_socket);
                return NULL;  // 退出线程
            case CLOSE_ACK_2:
                //此时表明是关闭应答方，收到这个之后就可以关闭连接
                close(client_socket);
                break;
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
        MessagePacket text;
        text.type = DATA_TRANSFER;
        text.sequence = client_seq++;
        text.ack = server_seq;
        // aes128加密铭文
        // encrypted_msg = encrypt(str)......
        char encrypted_msg[PAYLOAD_MAX_SIZE];   // 伪代码，实际应该是加密后的数据
        strcpy((char*)text.payload, encrypted_msg);
        int encrypt_res = encrypt_message(&text,session_key, 16); //session_key被定义成局部变量了，在第一次握手
        if(!encrypt_res)
        {
            //失败后终止发送线程？
            printf("客户端：加密数据失败\n");
            break;
        }

        if (send(client_socket, &text, sizeof(text), 0) == -1) {
            perror("客户端: 发送消息失败");
        }
    }
    return NULL;
}
