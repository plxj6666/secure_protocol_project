#include "sig.h"
void init_client_socket();
void client_send_handshake_request();
void client_receive_handshake_response();
void* client_receive_thread_func(void* arg);
void* client_send_thread_func(void* arg);
