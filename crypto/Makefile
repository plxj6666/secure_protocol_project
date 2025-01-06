CC = gcc
CFLAGS = -Wall -Wextra -I./include -g
LDFLAGS = -lm

SRC_DIR = src
TEST_DIR = test
BUILD_DIR = build

# Source files
SHA256_SRC = $(SRC_DIR)/sha256.c
RANDOM_SRC = $(SRC_DIR)/random_utils.c
TEST_SHA256_SRC = $(TEST_DIR)/test_sha256.c
TEST_RANDOM_SRC = $(TEST_DIR)/test_random.c

# Object files
SHA256_OBJ = $(BUILD_DIR)/sha256.o
RANDOM_OBJ = $(BUILD_DIR)/random_utils.o
TEST_SHA256_OBJ = $(BUILD_DIR)/test_sha256.o
TEST_RANDOM_OBJ = $(BUILD_DIR)/test_random.o

# Executables
TEST_SHA256_EXE = $(BUILD_DIR)/test_sha256
TEST_RANDOM_EXE = $(BUILD_DIR)/test_random

.PHONY: all clean sha256 random

all: sha256 random

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# SHA256 测试目标
sha256: $(TEST_SHA256_EXE)

$(TEST_SHA256_EXE): $(SHA256_OBJ) $(TEST_SHA256_OBJ)
	$(CC) $^ $(LDFLAGS) -o $@

# Random 测试目标
random: $(TEST_RANDOM_EXE)

$(TEST_RANDOM_EXE): $(RANDOM_OBJ) $(TEST_RANDOM_OBJ)
	$(CC) $^ $(LDFLAGS) -o $@

# 编译规则
$(SHA256_OBJ): $(SHA256_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(RANDOM_OBJ): $(RANDOM_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_SHA256_OBJ): $(TEST_SHA256_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_RANDOM_OBJ): $(TEST_RANDOM_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)