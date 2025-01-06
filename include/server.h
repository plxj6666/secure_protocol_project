#include "sig.h"

void receive_handshake_request(MessagePacket request);

void receive_final_ack(MessagePacket ack);

void send_to_client();

void recieve_from_client(MessagePacket message); //receive the message and do sth.