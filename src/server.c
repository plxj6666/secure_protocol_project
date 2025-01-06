#include "sig.h"
#include "server.h"
#include <pthread.h>

int main() {
    init_server_socket();  // 初始化套接字
    receive_handshake_request();  // 接收握手请求

    pthread_t receive_thread, send_thread;

    // 创建接收线程
    pthread_create(&receive_thread, NULL, receive_thread_func, NULL);
    // 创建发送线程
    pthread_create(&send_thread, NULL, send_thread_func, NULL);

    // 等待线程结束
    pthread_join(receive_thread, NULL);
    pthread_join(send_thread, NULL);

    close(client_socket);
    close(server_socket);
    printf("服务器: 连接已关闭\n");
    return 0;
}