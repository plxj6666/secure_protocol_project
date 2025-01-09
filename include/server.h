#ifndef SERVER_H
#define SERVER_H

#include "sig.h"

// 函数声明
void init_server_socket();
void server_receive_handshake_request();
void* server_receive_handshake_thread(void* arg);
void* server_receive_thread_func(void* arg);
void* server_send_thread_func(void* arg);
void server_recieve_final_handshake();
void* server_receive_thread_func(void* arg);
void* server_send_thread_func(void* arg);

#endif /* SERVER_H */
