CC = gcc
CFLAGS = -Wall -Wextra -I./include -I./crypto/include
LDFLAGS = -lm

BUILD_DIR = build
SRC_DIR = src/handshake
CRYPTO_DIR = crypto/src
TEST_DIR = tests

# 源文件
KEY_DERIVATION_SRC = $(SRC_DIR)/key_derivation.c
SHA256_SRC = $(CRYPTO_DIR)/sha256.c
TEST_HANDSHAKE_SRC = $(TEST_DIR)/test_handshake.c

# 目标文件
KEY_DERIVATION_OBJ = $(BUILD_DIR)/key_derivation.o
SHA256_OBJ = $(BUILD_DIR)/sha256.o
TEST_HANDSHAKE_OBJ = $(BUILD_DIR)/test_handshake.o

# 可执行文件
TEST_HANDSHAKE = $(BUILD_DIR)/test_handshake

.PHONY: all clean test

all: test

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(CRYPTO_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(TEST_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_HANDSHAKE): $(KEY_DERIVATION_OBJ) $(SHA256_OBJ) $(TEST_HANDSHAKE_OBJ)
	$(CC) $^ $(LDFLAGS) -o $@

test: $(TEST_HANDSHAKE)

clean:
	rm -rf $(BUILD_DIR)