#include <stdio.h>
#include <string.h>
#include "server.h"
#include "sig.h"
#include "close_connection.h"

int seq = 0;   // The sequence of client
int r_seq = 0; // The sequence of server
int finish = 0;

// 模拟加密函数
char* encrypt_message(const char* input) 
{
    static char encrypted[PAYLOAD_MAX_SIZE];
    for (int i = 0; input[i] != '\0'; i++) 
    {
        encrypted[i] = input[i] + 1;  // 简单 Caesar cipher 加密
    }
    return encrypted;
}

// 发送握手请求
void send_handshake_request() 
{
    MessagePacket request;
    request.type = HANDSHAKE_INIT;
    request.sequence = seq;
    request.ack = r_seq;
    memset(request.payload, 0, sizeof(request.payload));

    printf("client: 发送握手请求 (seq: %d, ack: %d)...\n", seq, r_seq);
    seq++;
    recieve(request);  // 发送握手请求到服务器
}

void receive_handshake_response(MessagePacket response) 
{
    if (response.type == HANDSHAKE_ACK) 
    {
        printf("client: 收到握手确认 (seq: %d, ack: %d)...\n", response.sequence, response.ack);
        r_seq = response.sequence + 1;

        // 发送第三次握手的确认
        MessagePacket ack;
        ack.type = HANDSHAKE_FINAL;
        ack.sequence = seq;
        ack.ack = r_seq;
        memset(ack.payload, 0, sizeof(ack.payload));

        printf("client: 发送最终确认 (seq: %d, ack: %d)...\n", seq, r_seq);
        seq++;
        recieve(ack);
    }
}

// 发送普通消息
void send_normal_message(int seq) 
{
    printf("client: 输入消息 (输入 'END' 关闭连接):\n");
    MessagePacket text;
    text.type = DATA_TRANSFER;
    char str[PAYLOAD_MAX_SIZE] = {'\0'};
    scanf("%s", str);

    if (strcmp("END", str) == 0) 
    {
        finish = 1;
        close_connection();  // 调用关闭连接
        return;
    }

    char* res = encrypt_message(str);  // 加密消息，需要换成自己的加密函数
    strcpy(text.payload, res);
    text.sequence = seq;
    text.ack = r_seq;
    seq++;
    recieve(text);  // 发送到服务器
}

// 接收服务器消息
void recieve_from_server(MessagePacket text) 
{
    r_seq = text.sequence + 1;
    switch (text.type) 
    {
        case CLOSE_REQUEST:
            printf("client: 收到服务器关闭请求。\n");
            close_connection();
            finish = 1;
            break;

        default:
            printf("client: 收到服务器消息：%s\n", text.payload);
            send_normal_message(seq);
    }
}

// 客户端主函数
void client() 
{
    send_request_message();  // 主动发起连接

    while (!finish) 
    {
        send_normal_message(seq);
    }

    printf("客户端结束运行。\n");
}