#include <stdio.h>
#include <string.h>
#include "server.h"
#include "sig.h"
#include "close_connection.h"

int seq = 0;   // The sequence of client
int r_seq = 0; // The sequence of server

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
    recieve_from_client(request);  // 发送握手请求到服务器
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
void send_normal_message() 
{
    printf("client: 输入消息 (输入 'END' 关闭连接):\n");
    MessagePacket text;
    text.type = DATA_TRANSFER;
    char str[PAYLOAD_MAX_SIZE] = {'\0'};
    scanf("%s", str);

    if (strcmp("END", str) == 0) 
    {

        close_connection(0);  // 调用关闭连接,代表断开连接请求方是client
        return;
    }

    char* res = encrypt_message(str);  // 加密消息，需要换成自己的加密函数
    strcpy(text.payload, res);
    text.sequence = seq;
    text.ack = r_seq;
    seq++;
    recieve_from_client(text);  // 发送到服务器
}

// 接收服务器消息
void recieve_from_server(MessagePacket text) 
{
    r_seq = text.sequence + 1;
    switch (text.type) 
    {
        case CLOSE_REQUEST:
            printf("client: 收到服务器关闭请求。\n");
            break;

        case CLOSE_ACK:     //收到第一次应答

            break;
        case CLOSE_ACK_2:   //收到第二次应答（对方应该是wait了一段时间后再发出这次挥手的）

            //发送最后一次挥手（其实没有用，因为对方此时已经关机了
            printf("正在释放连接...\n");
            wait_2MSL();
            flag = 0;  // 停止服务
            printf("连接已关闭。\n");
            break;

        default:
            printf("client: 收到服务器消息：%s\n", text.payload);
            send_normal_message(seq);
    }
}
