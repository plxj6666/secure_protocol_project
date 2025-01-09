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
    

    if (id == 0) 
    {
        close_msg.sequence = client_seq++;
        close_msg.ack = server_seq;
        // 客户端发送关闭连接请求
        if (send(server_socket, &close_msg, sizeof(close_msg), 0) == -1) 
        {
            perror("客户端: 发送关闭请求失败");
            return;
        }
        printf("客户端: 已发送关闭连接请求\n");
    } 
    else if (id == 1) {
        close_msg.sequence = server_seq++;
        close_msg.ack = client_seq;
        // 服务器发送关闭连接请求
        if (send(client_socket, &close_msg, sizeof(close_msg), 0) == -1) {
            perror("服务器: 发送关闭请求失败");
            return;
        }
        printf("服务器: 已发送关闭连接请求\n");
    }
}

// 服务器或客户端接收到关闭连接请求时的处理逻辑
void handle_close_request(int socket_fd, MessagePacket close_msg) {
    printf("收到关闭连接请求 (seq: %d, ack: %d)...\n", close_msg.sequence, close_msg.ack);

    // 第一次关闭确认
    MessagePacket close_ack1;
    close_ack1.type = CLOSE_ACK;
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

    if (send(socket_fd, &close_ack1, sizeof(close_ack1), 0) == -1) {
        perror("发送第一次关闭确认失败");
        return;
    }
    printf("已发送第一次关闭确认 (seq: %d, ack: %d)...\n", close_ack1.sequence, close_ack1.ack);

    //四次挥手要等待一段时间才能够发送第二次确认
    usleep(20000);  // 模拟延迟 20ms，比2MSL小很多

    // 第二次关闭确认
    MessagePacket close_ack2;
    close_ack2.type = CLOSE_ACK_2;
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

    if (send(socket_fd, &close_ack2, sizeof(close_ack2), 0) == -1) {
        perror("发送第二次关闭确认失败");
        return;
    }
    printf("已发送第二次关闭确认 (seq: %d, ack: %d)...\n", close_ack2.sequence, close_ack2.ack);

    printf("连接已关闭。\n");
}
