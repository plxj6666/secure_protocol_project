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
    // pthread_t handshake_thread;
    // pthread_create(&handshake_thread, NULL, server_receive_handshake_thread, NULL);
    // pthread_detach(handshake_thread);
 
}

// 接收握手请求
void server_receive_handshake_request() {
    MessagePacket request;
    if (recv(client_socket, &request, sizeof(request), 0) == -1) {
        perror("服务器: 接收握手请求失败");
        return;
    }
    printf("I am in server recieve handshake\n");
    if (request.type == HANDSHAKE_INIT) {
        printf("服务器: 收到握手请求 (seq: %d, ack: %d)\n", request.sequence, request.ack);

        // 1. 生成服务器RSA密钥对
        mpz_t n, e, d;
        mpz_inits(n, e, d, NULL);
        generate_rsa_keys(n, e, d);

        // 2. 准备证书        
        // 将服务器公钥写入证书
        // unsigned char buffer[1024];

        // size_t n_len = mpz_to_buffer(n, RSA_BYTES * 2, buffer);
        // size_t e_len = mpz_to_buffer(e, RSA_E_BYTES, buffer + RSA_BYTES * 2);
        // memcpy(server_current_cert.public_key_n, buffer, n_len);
        // memcpy(server_current_cert.public_key_e, buffer + RSA_BYTES * 2, e_len);

        // printf("服务器：证书已生成\n");
        // // 证书签名
        // char cert_hash[32];
        // memset(server_current_cert.signature, 0, sizeof(server_current_cert.signature));
        // certificate_to_buffer(&server_current_cert, buffer);
        // // 先hash
        // sha256(buffer, sizeof(Certificate), cert_hash);
        // // 后签名
        // mpz_t plaintext, cipher;
        // mpz_inits(plaintext, cipher, NULL); //初始化变量
        // buffer_to_mpz(plaintext, sizeof(cert_hash), cert_hash);
        // decrypt(cipher, plaintext, d, n);

        // if(mpz_to_buffer(cipher, sizeof(server_current_cert.signature), server_current_cert.signature) == -1){
        //     printf("服务器：签名失败\n");
        // }
        // printf("服务器：证书发送证书\n");

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
            mpz_clears(n, e, d, NULL);
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
            mpz_clears(n, e, d, NULL);
            return;
        }

        printf("服务器: 已发送握手确认和证书\n");
        
        // 4. 等待接收客户端的密钥交换消息
        MessagePacket key_msg;
        if (recv(client_socket, &key_msg, sizeof(key_msg), 0) == -1) {
            perror("服务器: 接收密钥交换消息失败");
            mpz_clears(n, e, d, NULL);
            return;
        }

        if (key_msg.type == KEY_EXCHANGE) {
            // 生成共享密钥
            unsigned char shared_secret[32];
            size_t secret_len;
            
            // 直接使用已有的密钥对处理密钥交换
            if (handle_key_exchange(&key_msg, d, n, shared_secret, &secret_len) != 0) {
                printf("服务器: 密钥交换处理失败\n");
                mpz_clears(n, e, d, NULL);
                return;
            }

            // 6. 派生会话密钥
            if (derive_session_key(shared_secret, secret_len,
                                NULL, 0,  // 不使用盐值
                                server_session_key, 16) != 0) {
                printf("服务器: 会话密钥派生失败\n");
            }

            printf("服务器: 密钥交换完成\n");
            
            // 7. 清理敏感数据
            memset(shared_secret, 0, sizeof(shared_secret));
        }
        
        // 清理RSA密钥
        mpz_clears(n, e, d, NULL);
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

// void* server_receive_handshake_thread(void* arg) {
//     server_receive_handshake_request();
//     return NULL;
// }

// void server_recieve_final_handshake()
// {
//     MessagePacket request;
//     if (recv(client_socket, &request, sizeof(request), 0) == -1) {
//         perror("服务器: 接收握手final请求失败");
//         return;
//     }
//     if(request.type == HANDSHAKE_FINAL)
//     {
//         // 4. 等待接收客户端的密钥交换消息
//         MessagePacket key_msg;
//         if (recv(client_socket, &key_msg, sizeof(key_msg), 0) == -1) {
//             perror("服务器: 接收密钥交换消息失败");
//             mpz_clears(n, e, d, NULL);
//             return;
//         }

//         if (key_msg.type == KEY_EXCHANGE) {
//             // 5. 生成共享密钥
//             unsigned char shared_secret[32];
//             size_t secret_len;
            
//             // 私钥转换为字节数组
//             unsigned char private_key[RSA_BYTES * 2];
//             mpz_to_buffer(d, RSA_BYTES, private_key);
//             mpz_to_buffer(n, RSA_BYTES, private_key + RSA_BYTES);
//             size_t bit_count = mpz_sizeinbase(num, 2);
            
//             // 处理接收到的密钥交换消息
//             if (handle_key_exchange(&key_msg, private_key, shared_secret, &secret_len) != 0) {
//                 printf("服务器: 密钥交换处理失败\n");
//                 mpz_clears(n, e, d, NULL);
//                 return;
//             }

//             // 6. 派生会话密钥
//             if (derive_session_key(shared_secret, secret_len,
//                                 NULL, 0,  // 不使用盐值
//                                 server_session_key, 16) != 0) {
//                 printf("服务器: 会话密钥派生失败\n");
//             }

//             printf("服务器: 密钥交换完成\n");
            
//             // 7. 清理敏感数据
//             memset(shared_secret, 0, sizeof(shared_secret));
//             memset(private_key, 0, sizeof(private_key));
//         }
        
//         // 清理RSA密钥
//         mpz_clears(n, e, d, NULL);
//     }
// }

// 接收消息线程
void* server_receive_thread_func(void* arg) {
    MessagePacket packet;
    while (1) {
        ssize_t bytes_received = recv(client_socket, &packet, sizeof(packet), 0);
        if (bytes_received <= 0) {
            printf("服务器: 客户端断开连接或接收失败。\n");
            break;
        }

        switch (packet.type) {
            case HANDSHAKE_INIT:
                server_receive_handshake_request(packet);
                break;
            case DATA_TRANSFER:
                printf("服务器: 收到客户端消息：%s\n", packet.payload);
                break;
            case CLOSE_REQUEST:
                handle_close_request(server_socket, packet);
                wait_2MSL();
                close(server_socket);
                return NULL;  // 退出线程
            default:
            close(server_socket);
                printf("服务器: 收到未知消息类型。\n");
        }
    }
    return NULL;
}

// 发送消息线程
void* server_send_thread_func(void* arg) {
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
        text.ack = client_seq;
        strcpy((char*)text.payload, str);

        // int encrypt_res = encrypt_message(&text,session_key, 16); //session_key待定义
        int encrypt_res = 1; //临时代码
        if(!encrypt_res)
        {
            //失败后终止发送线程？
            printf("服务器：加密数据失败\n");
            break;
        }

        if (send(client_socket, &text, sizeof(text), 0) == -1) {
            perror("服务器: 发送消息失败");
        }
    }
    return NULL;
}
