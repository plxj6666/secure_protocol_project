#include <stdio.h>
#include <string.h>
#include "server.h"
#include "client.h"
#include "close_connection.h"

int server_seq = 0; // 服务器序列号

void receive_handshake_request(MessagePacket request) 
{
    if (request.type == HANDSHAKE_INIT) 
    {
        printf("server: 收到握手请求 (seq: %d, ack: %d)...\n", request.sequence, request.ack);

        // 发送握手确认
        MessagePacket response;
        response.type = HANDSHAKE_ACK;
        response.sequence = server_seq++;
        response.ack = request.sequence + 1;
        memset(response.payload, 0, sizeof(response.payload));

        printf("server: 发送握手确认 (seq: %d, ack: %d)...\n", response.sequence, response.ack);
        send_to_client(response);
    }
}

void receive_final_ack(MessagePacket ack) 
{
    if (ack.type == HANDSHAKE_ACK) 
    {
        printf("server: 收到最终确认 (seq: %d, ack: %d)...\n", ack.sequence, ack.ack);
        printf("server: 握手完成，连接已建立。\n");
    }
}

// 发送消息到客户端
void send_to_client(MessagePacket response) 
{
    printf("server: 发送消息到客户端：%s\n", response.payload);
    recieve_from_server(response);  // 客户端接收消息
}

// 接收消息并处理
void recieve(MessagePacket message) 
{
    switch (message.type) 
    {
        case HANDSHAKE_INIT:
            receive_handshake_request();  //收到连接请求
            break;

        case HANDSHAKE_ACK:
            receive_final_ack();       //连接建立完毕
            break;

        case DATA_TRANSFER:
            printf("server: 收到数据包，内容：%s\n", message.payload);
            // 此处可以实现解密逻辑
            MessagePacket response;
            response.type = DATA_TRANSFER;
            strcpy(response.payload, "收到您的消息");
            response.sequence = server_seq++;
            response.ack = message.sequence + 1;
            send_to_client(response);  // 回应客户端
            break;

        case CLOSE_REQUEST:
            printf("server: 收到关闭连接请求。\n");
            close_connection();
            break;

        default:
            MessagePacket text;
            //填充text的内容，发给client
            recieve_from_server(text);
    }
}
