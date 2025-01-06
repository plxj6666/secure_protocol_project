#include <stdio.h>
#include <string.h>
#include "sig.h"
#include "server.h"
#include "client.h"
#include "close_connection.h"
#include "key_utils.h"
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
void send_to_client() 
{
    printf("server: 输入消息 (输入 'END' 关闭连接):\n");
    MessagePacket text;
    text.type = DATA_TRANSFER;
    char str[PAYLOAD_MAX_SIZE] = {'\0'};
    scanf("%s", str);

    if (strcmp("END", str) == 0) 
    {

        close_connection(1);  // 调用关闭连接,代表断开连接请求方是server
        return;
    }

    char* res = encrypt_message(str);  // 加密消息，需要换成自己的加密函数
    strcpy(text.payload, res);
    //序列号还需要处理
    text.sequence = server_seq;
    server_seq++;
    recieve_from_server(text);  // 客户端接收消息
}

// 接收消息并处理
void recieve_from_client(MessagePacket message) 
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
            printf("server: 收到服务器关闭请求。\n");
            //收到这个关闭连接的请求后
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

        case KEY_EXCHANGE:
            printf("server: 收到密钥交换请求。\n");
            // 处理密钥交换逻辑
            handle_key_exchange(message, server_private_key);
            break;
        default:
            MessagePacket text;
            //填充text的内容，发给client
            recieve_from_server(text);
    }
}
