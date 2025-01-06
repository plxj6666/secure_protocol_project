#include "sig.h"

void init_server_socket();

void receive_handshake_request();

void* receive_thread_func(void* arg);

void* send_thread_func(void* arg);