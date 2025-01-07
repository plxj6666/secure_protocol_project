#ifndef RANDOM_UTILS_H
#define RANDOM_UTILS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 生成密码学安全的随机数
 * @param output 输出缓冲区
 * @param len 需要的随机字节数
 * @return 成功返回0，失败返回-1
 */
int generate_secure_random(unsigned char *output, size_t len);

/**
 * 生成指定范围内的随机数
 * @param min 最小值
 * @param max 最大值
 * @return min到max之间的随机数，失败返回-1
 */
int generate_random_range(int min, int max);

/**
 * 生成随机字节数组
 * @param output 输出缓冲区
 * @param len 需要的字节数
 * @return 成功返回0，失败返回-1
 */
int generate_random_bytes(unsigned char *output, size_t len);

/**
 * 生成指定范围内的64位无符号随机数
 * @param min 最小值
 * @param max 最大值
 * @return min到max之间的随机数，失败返回0
 */
uint64_t generate_random_range_u64(uint64_t min, uint64_t max);

#ifdef __cplusplus
}
#endif

#endif /* RANDOM_UTILS_H */