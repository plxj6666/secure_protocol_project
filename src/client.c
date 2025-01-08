#include "sig.h"
#include "client.h"
#include <pthread.h>

// 客户端主函数
int main() 
{
    init_client_socket();  // 初始化套接字
    client_send_handshake_request();  // 发起握手
    client_receive_handshake_response();  // 接收握手确认

    pthread_t receive_thread, send_thread;

    // 创建接收线程
    pthread_create(&receive_thread, NULL,client_receive_thread_func, NULL);
    // 创建发送线程
    pthread_create(&send_thread, NULL, client_send_thread_func, NULL);

    // 等待线程结束
    pthread_join(receive_thread, NULL);
    pthread_join(send_thread, NULL);

    //关闭连接的操作是在client_main.c中
    printf("客户端: 连接已关闭\n");
    return 0;
}
