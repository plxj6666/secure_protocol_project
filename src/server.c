#include "sig.h"
#include "server.h"
#include <stdio.h>
#include <pthread.h>

int main() {
<<<<<<< HEAD
    while(1)
    {
        flag = 0;
        init_server_socket();  // 初始化套接字
        server_receive_handshake_request();  // 接收握手请求
=======
    init_server_socket();  // 初始化套接字
    server_receive_handshake_request();  // 接收握手请求
>>>>>>> f00e12d4b211972296b17fcb18b2a56ca4adb007

        pthread_t receive_thread, send_thread;

        // 创建接收线程
        pthread_create(&receive_thread, NULL, server_receive_thread_func, NULL);
        // 创建发送线程
        pthread_create(&send_thread, NULL, server_send_thread_func, NULL);

        // if(flag)
        // {
        //     pthread_cancel(receive_thread);  // 强制终止接收线程
        //     pthread_cancel(send_thread);     // 强制终止发送线程
        //     continue;
        // }

        // 等待线程结束
        pthread_join(receive_thread, NULL);
        pthread_join(send_thread, NULL);
    }
    
    return 0;
}