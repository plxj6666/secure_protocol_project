#include <stdio.h>
#include "server.h"
#include "sig.h"
#include "close_connection.h"

int main()
{
    //调用client_main.c中的send_request_message(),和server建立连接
    //...

    //如果有任意一方发送了close_connection信息（可以用一个变量标识，若使用，则变量变为1）
    while(flag == 0)
    {
        ;
    }
    //此时这里的代码得到执行，我们要去调用terminate_main.c的相关函数结束连接
    return 0;
}
