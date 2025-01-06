#include "cs.h"

// 客户端主函数
void client() 
{
    send_request_message();  // 主动发起连接

    while (!flag)  
    {
        send_normal_message();
    }

    printf("客户端结束运行。\n");
}