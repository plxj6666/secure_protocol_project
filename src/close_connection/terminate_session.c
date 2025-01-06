#include <stdio.h>
#include "sig.h"
#include "close_connection.h"

// 模拟释放连接
void close_connection() 
{
    printf("正在释放连接...\n");
    wait_2MSL();
    service = 0;  // 停止服务
    printf("连接已关闭。\n");
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
