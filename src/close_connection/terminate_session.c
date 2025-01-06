#include <stdio.h>
#include "sig.h"
#include "server.h"
#include "client.h"
#include "close_connection.h"

// 模拟释放连接
void close_connection(int id) 
{
    if(id)
    {
        //id == 1,server发送断开连接的通知
        MessagePacket start_close;
        start_close.type = CLOSE_REQUEST;
        recieve_from_server(start_close);
    }
    else
    {
        //id == 0，client发送断开连接的通知
        MessagePacket start_close;
        start_close.type = CLOSE_REQUEST;
        recieve_from_cient(start_close);
    }
}

// 模拟 2MSL 的延迟
void wait_2MSL() 
{
    int cnt = 0;
    for (int i = 0; i < 10000; i++) 
    {
        cnt++;
    }
    for (int i = 0; i < 10000; i++) 
    {
        cnt++;
    }
    printf("等待 2MSL 完成。\n");
}
