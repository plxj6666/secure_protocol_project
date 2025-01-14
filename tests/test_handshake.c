#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>
#include <unistd.h>    // 为 sleep() 函数
#include <sys/socket.h>  // 为 close() 函数
#include "../include/sig.h"
#include "../include/client.h"
#include "../include/server.h"

void test_key_exchange() {
    printf("\n开始测试密钥交换流程...\n");

    // 1. 启动服务器线程
    pthread_t server_thread;
    pthread_create(&server_thread, NULL, (void*)init_server_socket, NULL);
    printf("服务器启动完成\n");

    // 2. 等待服务器就绪
    sleep(1);

    // 3. 启动客户端并执行握手
    init_client_socket();
    client_send_handshake_request();
    printf("客户端握手请求已发送\n");

    // 4. 服务器处理握手请求
    client_receive_handshake_response();
    printf("服务器处理握手完成\n");

    // 5. 验证密钥交换结果
    // 比较客户端和服务器的会话密钥是否相同
    extern unsigned char client_session_key[16];
    extern unsigned char server_session_key[16];
    
    assert(memcmp(client_session_key, server_session_key, 16) == 0);
    printf("密钥交换测试通过：客户端和服务器的会话密钥相同\n");

    // 清理资源
    close(client_socket);
    close(server_socket);
    pthread_join(server_thread, NULL);
}

int main() {
    test_key_exchange();
    return 0;
}