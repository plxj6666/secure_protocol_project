CC = gcc
CFLAGS = -I./include -I./crypto/include -Wall
LDFLAGS = -lgmp -pthread

# 目录设置
SRC_DIR = src
CRYPTO_DIR = crypto
TEST_DIR = tests
BUILD_DIR = build
INCLUDE_DIR = include

# 源文件 (排除有main函数的文件)
SRCS =	$(wildcard $(SRC_DIR)/handshake/*.c) \
		$(wildcard $(SRC_DIR)/encryption/*.c) \
		$(wildcard $(SRC_DIR)/close_connection/*.c) \
		$(wildcard $(SRC_DIR)/utils/*.c) \
		$(wildcard $(CRYPTO_DIR)/src/*.c) \
		$(SRC_DIR)/sig.c	\
		$(SRC_DIR)/client/client_main.c	\
		$(SRC_DIR)/server/sever_main.c

# 对象文件
OBJS = $(SRCS:%.c=$(BUILD_DIR)/%.o)

# 测试源文件
TEST_SRCS = $(wildcard $(TEST_DIR)/*.c)
TEST_OBJS = $(TEST_SRCS:%.c=$(BUILD_DIR)/%.o)

# 创建必要的构建目录
$(shell mkdir -p $(BUILD_DIR)/src/client \
                 $(BUILD_DIR)/src/server \
                 $(BUILD_DIR)/src/handshake \
                 $(BUILD_DIR)/src/encryption \
                 $(BUILD_DIR)/src/close_connection \
                 $(BUILD_DIR)/src/utils \
                 $(BUILD_DIR)/crypto/src \
                 $(BUILD_DIR)/tests)

# 测试可执行文件
test_handshake: $(BUILD_DIR)/tests/test_handshake

$(BUILD_DIR)/tests/test_handshake: $(BUILD_DIR)/tests/test_handshake.o $(OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

# 编译规则
$(BUILD_DIR)/%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

# 构建所有测试
test: test_handshake

# 清理
clean:
	rm -rf $(BUILD_DIR)

.PHONY: test clean test_handshake