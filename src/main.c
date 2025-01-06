#include <stdio.h>
#include "server.h"
#include "client.h"
#include "close_connection.h"

int main() 
{
    printf("握手流程启动...\n");

    flag = 0;   // 启动服务器和客户端,客户可以开始发信息
    
    // 监听是否需要关闭连接
    while (flag == 0) 
    {
        client();  // 启动客户端，与服务器建立连接
        // 此处可以轮询服务状态，等待任意一方请求关闭连接
    }

    return 0;
}
