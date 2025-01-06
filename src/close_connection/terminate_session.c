#include <stdio.h>
#include <unistd.h>    // 用于 close()
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
    close_msg.sequence = seq++;
    close_msg.ack = r_seq;

    if (id == 0) 
    {
        // 客户端发送关闭连接请求
        if (send(client_socket, &close_msg, sizeof(close_msg), 0) == -1) 
        {
            perror("客户端: 发送关闭请求失败");
            return;
        }
        printf("客户端: 已发送关闭连接请求\n");
    } else if (id == 1) {
        // 服务器发送关闭连接请求
        if (send(server_socket, &close_msg, sizeof(close_msg), 0) == -1) {
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
    close_ack1.sequence = seq++;
    close_ack1.ack = close_msg.sequence + 1;

    if (send(socket_fd, &close_ack1, sizeof(close_ack1), 0) == -1) {
        perror("发送第一次关闭确认失败");
        return;
    }
    printf("已发送第一次关闭确认 (seq: %d, ack: %d)...\n", close_ack1.sequence, close_ack1.ack);

    // 第二次关闭确认
    MessagePacket close_ack2;
    close_ack2.type = CLOSE_ACK_2;
    close_ack2.sequence = seq++;
    close_ack2.ack = close_ack1.sequence + 1;

    if (send(socket_fd, &close_ack2, sizeof(close_ack2), 0) == -1) {
        perror("发送第二次关闭确认失败");
        return;
    }
    printf("已发送第二次关闭确认 (seq: %d, ack: %d)...\n", close_ack2.sequence, close_ack2.ack);

    // 模拟 2MSL 等待，确保对方收到
    wait_2MSL();

    // 关闭套接字
    close(socket_fd);
    printf("连接已关闭。\n");
}
