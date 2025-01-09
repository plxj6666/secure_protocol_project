#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>

// 生成密码学安全的随机数
// len: 需要的随机字节数
// output: 输出缓冲区
// 返回值: 成功返回0，失败返回-1
int generate_secure_random(unsigned char *output, size_t len) {
    int fd;
    size_t total = 0;
    
    // 打开/dev/urandom
    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return -1;
    }

    // 读取随机数据
    while (total < len) {
        ssize_t result = read(fd, output + total, len - total);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return -1;
        }
        total += result;
    }

    close(fd);
    return 0;
}

// 生成指定范围内的随机数
// min: 最小值
// max: 最大值
// 返回值: min到max之间的随机数
int generate_random_range(int min, int max) {
    unsigned char buf[4];
    uint32_t rand_val;
    
    if (generate_secure_random(buf, sizeof(buf)) != 0) {
        return -1;
    }
    
    // 转换为32位无符号整数
    rand_val = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
    // 映射到指定范围
    return min + (rand_val % (max - min + 1));
}

uint64_t generate_random_range_u64(uint64_t min, uint64_t max) {
    unsigned char buf[8];
    uint64_t rand_val;
    
    if (generate_secure_random(buf, sizeof(buf)) != 0) {
        return 0;  // 返回0表示错误
    }
    
    // 转换为64位无符号整数
    rand_val = ((uint64_t)buf[0] << 56) | ((uint64_t)buf[1] << 48) |
               ((uint64_t)buf[2] << 40) | ((uint64_t)buf[3] << 32) |
               ((uint64_t)buf[4] << 24) | ((uint64_t)buf[5] << 16) |
               ((uint64_t)buf[6] << 8)  | (uint64_t)buf[7];
    
    
    // 映射到指定范围
    if (max <= min) return min;
    return min + (rand_val % (max - min + 1));
}

// 生成随机字节数组
// output: 输出缓冲区
// len: 需要的字节数
// 返回值: 成功返回0，失败返回-1
int generate_random_bytes(unsigned char *output, size_t len) {
    return generate_secure_random(output, len);
}