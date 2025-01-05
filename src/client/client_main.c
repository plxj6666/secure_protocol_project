#include <stdio.h>
#include <string.h>
#include "server.h"
#include "sig.h"
#include "close_connection.h"

int seq = 0;   //the sequence of client
int r_seq = 0; //the sequence of server
int finish = 0;

void send_request_message()
{
    MessagePacket link_start_request;
    link_start_request.type = HANDSHAKE_INIT;
    link_start_request.sequence = seq;
    link_start_request.ack = r_seq;
    memset(link_start_request.payload, 0, sizeof(PAYLOAD_MAX_SIZE);

    seq++;
    recieve(link_start_request);//send to the server

}

void send_normal_message(int seq)
{
    printf("client:\n");
    MessagePacket text;
    text.type = DATA_TRANSFER;
    char str[PAYLOAD_MAX_SIZE] = {'\0'};
    scanf("%s", str);
    if(strcmp(END, str) == 0)
    {
        finish = 1;
        //此处调用close connection
        close_connection(text);
        return ;
    }

    //此处调用加密函数

    char* res = ;    //res 是加密后的结果
    strcpy(text.payload, str);
    text.seq = seq;
    text.ack = r_seq;
    seq++;
    recieve(text);
}

void recieve_from_server(MessagePacket text)
{
    r_seq = text.sequence + 1;
    switch(text.type)
    {
        case: CLOSE_REQUEST
        //...
            break;
            //.....



        default:
            send_normal_message();
    }
    
}//接收服务器发来的信息

void client()
{
    //客户端要主动发起连接
    send_request_message();
    


    //接下来写发送消息的函数
    while(!finish && service)
    {
        send_normal_message(seq);
    }

    return 0;
}