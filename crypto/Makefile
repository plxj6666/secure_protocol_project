CC = gcc
CFLAGS = -Wall -Wextra -I./include
LDFLAGS = 

SRC_DIR = src
TEST_DIR = test
BUILD_DIR = build

# Source files
SHA256_SRC = $(SRC_DIR)/sha256.c
TEST_SRC = $(TEST_DIR)/test_sha256.c

# Object files
SHA256_OBJ = $(BUILD_DIR)/sha256.o
TEST_OBJ = $(BUILD_DIR)/test_sha256.o

# Executable
TEST_EXE = $(BUILD_DIR)/test_sha256

.PHONY: all clean test

all: $(TEST_EXE)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(SHA256_OBJ): $(SHA256_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_OBJ): $(TEST_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_EXE): $(SHA256_OBJ) $(TEST_OBJ)
	$(CC) $^ $(LDFLAGS) -o $@

test: $(TEST_EXE)
	./$(TEST_EXE)

clean:
	rm -rf $(BUILD_DIR)