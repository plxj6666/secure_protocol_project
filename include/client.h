void init_client_socket();

void send_handshake_request();

void receive_handshake_response();

void* receive_thread_func(void* arg);

void* send_thread_func(void* arg);
