#include <stdio.h>
#include <unistd.h>    
#include <sys/socket.h>
#include "sig.h"
#include "server.h"
#include "client.h"
#include "close_connection.h"

// 模拟 2MSL 等待（确保连接彻底释放）
void wait_2MSL() 
{
    printf("等待 2MSL...\n");
    usleep(200000);  // 模拟延迟 200ms
    printf("2MSL 等待完成。\n");
}

// 客户端或服务器发送关闭连接的请求
void close_connection(int id) 
{
    MessagePacket close_msg;
    close_msg.type = CLOSE_REQUEST;  // 关闭请求消息类型
    close_msg.length = 0;

    if (id == 0) 
    {
        close_msg.sequence = client_seq++;
        close_msg.ack = server_seq;
        memset(close_msg.payload, 0, sizeof(close_msg.payload));
        strcpy((char*)close_msg.payload, "客户端请求关闭连接");
        close_msg.length = strlen((char*)close_msg.payload);
        // 客户端发送关闭连接请求
        if (send(client_socket, &close_msg, sizeof(close_msg), 0) == -1) 
        {
            perror("客户端: 发送关闭请求失败");
            return;
        }
        printf("客户端: 已发送关闭连接请求\n");
    } 
    else if (id == 1) 
    {
        close_msg.sequence = server_seq++;
        close_msg.ack = client_seq;
        memset(close_msg.payload, 0, sizeof(close_msg.payload));
        strcpy((char*)close_msg.payload, "服务器请求关闭连接");
        close_msg.length = strlen((char*)close_msg.payload);
        // 服务器发送关闭连接请求
        if (send(client_socket, &close_msg, sizeof(close_msg), 0) == -1) 
        {
            return ;
            perror("服务器: 发送关闭请求失败");
            return;
        }
        printf("服务器: 已发送关闭连接请求\n");
    }
}


// 服务器或客户端接收到关闭连接请求时的处理逻辑
void handle_close_request(int socket_fd, MessagePacket close_msg) 
{
    printf("收到关闭连接请求 (seq: %d, ack: %d)...\n", close_msg.sequence, close_msg.ack);
    // 第一次关闭确认
    MessagePacket close_ack1;
    close_ack1.length = 0;
    close_ack1.type = CLOSE_ACK;
    memset(close_ack1.payload, 0, sizeof(close_ack1.payload));
    strcpy((char*)close_ack1.payload, "第一次关闭确认");
    close_ack1.length = strlen((char*)close_ack1.payload);
    if(socket_fd == client_socket)
    {
        close_ack1.sequence = client_seq++;
        close_ack1.ack = server_seq;
    }
    else
    {
        close_ack1.sequence = server_seq++;
        close_ack1.ack = client_seq;
    }

    if (send(client_socket, &close_ack1, sizeof(close_ack1), 0) == -1) {
        perror("发送第一次关闭确认失败");
        return;
    }

    //四次挥手要等待一段时间才能够发送第二次确认
    usleep(20000);  // 模拟延迟 20ms，比2MSL小很多

    // 第二次关闭确认
    MessagePacket close_ack2;
    close_ack2.length = 0;
    close_ack2.type = CLOSE_ACK_2;
    memset(close_ack2.payload, 0, sizeof(close_ack2.payload));
    strcpy((char*)close_ack2.payload, "第二次关闭确认");
    close_ack2.length = strlen((char*)close_ack2.payload);
    if(socket_fd == client_socket)
    {
        close_ack2.sequence = client_seq++;
        close_ack2.ack = server_seq;
    }
    else
    {
        close_ack2.sequence = server_seq++;
        close_ack2.ack = client_seq;
    }

    if (send(client_socket, &close_ack2, sizeof(close_ack2), 0) == -1) {
        perror("发送第二次关闭确认失败");
        return;
    }
    
    if(socket_fd == server_socket)
    {
        close(client_socket);
        flag = 1;
        close(server_socket);
        //init_server_socket();
    }
    else
    {
        close(client_socket);
    }
}

void send_last_message(int socket_fd)
{
    MessagePacket close_final;
    close_final.type = ACK;
    memset(close_final.payload, 0, sizeof(close_final.payload));
    strcpy((char*)close_final.payload, "最后一次信息");
    if(socket_fd == client_socket)
    {
        close_final.sequence = client_seq++;
        close_final.ack = server_seq;
    }
    else
    {
        close_final.sequence = server_seq++;
        close_final.ack = client_seq;
    }

    send(client_socket, &close_final, sizeof(close_final), 0);
}