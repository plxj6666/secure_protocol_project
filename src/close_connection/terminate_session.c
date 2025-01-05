#include "close_connection.h"

void close_connection()
{
    service = 0;
}

void wait_2MSL()
{
    int cnt = 0;
    for(int i = 0; i < 10000;i++)
    {
        cnt++;
    }
    for(int i = 0; i < 10000;i++)
    {
        cnt++;
    }
}