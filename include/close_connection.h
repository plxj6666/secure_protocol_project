
void wait_2MSL();

void close_connection();

void handle_close_request(int socket_fd, MessagePacket close_msg);

void send_last_message(int socket_fd);
