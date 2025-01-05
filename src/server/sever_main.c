#include <stdio.h>
#include "server.h"
#include "client.h"

void send_to_client()
{
    MessagePacket text;


    recieve_from_server(text);
}

void recieve(MessagePacket message)
{
    switch(message.type)
    {
        case: HANDSHAKE_INIT
            //do sth.
            break;

            //.......


        default:
            send_to_client();
    }
}