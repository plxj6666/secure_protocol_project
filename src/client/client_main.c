#include <stdio.h>
#include "server.h"
#include "sig.h"

void send_request_message()
{
    MessagePacket link_start_request;
    link_start_request.type = HANDSHAKE_INIT;
    memset(link_start_request.payload, 0, sizeof(PAYLOAD_MAX_SIZE);

    recieve(link_start_request);//send to the server
}

void send_normal_message()
{

}

int main()
{
    //客户端要主动发起连接
    send_request_message();
    
    //得到客户端的回应


    //接下来写发送消息的函数
    send_normal_message();

    return 0;
}
