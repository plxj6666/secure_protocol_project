#include <cstdint>

#define PAYLOAD_MAX_SIZE 1024

//the structure of data_package
typedef struct {
    uint8_t type;          // 数据包类型 (1: 握手, 2: 数据传输, 3: 关闭连接)
    uint32_t sequence;     // 序列号，用于重传或排序
    uint16_t length;       // 数据负载的长度
    uint16_t ack;
    uint8_t payload[PAYLOAD_MAX_SIZE]; // 实际传输的数据 (加密后)
    uint8_t mac[32];       // 消息认证码 (如 HMAC-SHA256 输出为 32 字节)
} MessagePacket;


//the following defines are the types of the mesage
#define HANDSHAKE_INIT  1   // 握手初始化
#define HANDSHAKE_ACK   2   // 握手确认
#define DATA_TRANSFER   3   // 加密数据传输
#define CLOSE_REQUEST   4   // 关闭连接请求
#define CLOSE_ACK       5   // 关闭连接确认


//the following are the state of c/s
int server_alive = 0;
int client_alive = 0;
int service = 0;
char *END = "CLOSE";
