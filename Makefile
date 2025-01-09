CC = gcc
CFLAGS = -I./include -I./crypto/include -Wall -Wextra -maes -g
LDFLAGS = -lgmp -pthread

# 目录设置
SRC_DIR = src
CRYPTO_DIR = crypto
TEST_DIR = tests
BUILD_DIR = build
INCLUDE_DIR = include

# 源文件 (公共部分)
COMMON_SRCS =   $(wildcard $(SRC_DIR)/handshake/*.c) \
                $(wildcard $(SRC_DIR)/close_connection/*.c) \
                $(wildcard $(SRC_DIR)/utils/*.c) \
                $(wildcard $(SRC_DIR)/session_encryption/*.c)       \
                $(wildcard $(CRYPTO_DIR)/src/*.c)   \
                $(SRC_DIR)/sig.c

# 客户端和服务器特定源文件
CLIENT_SRCS = $(SRC_DIR)/client.c $(SRC_DIR)/client/client_main.c
SERVER_SRCS = $(SRC_DIR)/server.c $(SRC_DIR)/server/server_main.c

# 对象文件
COMMON_OBJS = $(COMMON_SRCS:%.c=$(BUILD_DIR)/%.o)
CLIENT_OBJS = $(CLIENT_SRCS:%.c=$(BUILD_DIR)/%.o)
SERVER_OBJS = $(SERVER_SRCS:%.c=$(BUILD_DIR)/%.o)

# 创建必要的构建目录
$(shell mkdir -p $(BUILD_DIR)/src/client \
                 $(BUILD_DIR)/src/server \
                 $(BUILD_DIR)/src/handshake \
                 $(BUILD_DIR)/src/session_encryption \
                 $(BUILD_DIR)/src/close_connection \
                 $(BUILD_DIR)/src/utils \
                 $(BUILD_DIR)/crypto/src \
                 $(BUILD_DIR)/tests)

# 主要目标
all: client server

# 客户端可执行文件
client: $(BUILD_DIR)/client

$(BUILD_DIR)/client: $(COMMON_OBJS) $(CLIENT_OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

# 服务器可执行文件
server: $(BUILD_DIR)/server

$(BUILD_DIR)/server: $(COMMON_OBJS) $(SERVER_OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

# 测试可执行文件
test_handshake: $(BUILD_DIR)/tests/test_handshake

$(BUILD_DIR)/tests/test_handshake: $(BUILD_DIR)/tests/test_handshake.o $(COMMON_OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

# 编译规则
$(BUILD_DIR)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 清理
clean:
	rm -rf $(BUILD_DIR)

.PHONY: all client server test clean test_handshake