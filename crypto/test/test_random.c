#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <math.h>
#include <stdint.h>
#include "../include/random_utils.h"
void test_secure_random() {
    printf("测试1: 基本随机数生成\n");
    unsigned char buf[32];
    int result = generate_secure_random(buf, sizeof(buf));
    assert(result == 0);
    
    // 验证生成的随机数不全为0或1
    int all_zero = 1, all_one = 1;
    for(int i = 0; i < sizeof(buf); i++) {
        if(buf[i] != 0) all_zero = 0;
        if(buf[i] != 0xFF) all_one = 0;
    }
    assert(!all_zero && !all_one);
    printf("基本随机数生成测试通过\n");
}

void test_random_range() {
    printf("测试2: 32位无符号范围随机数生成\n");
    
    // 测试32位无符号范围
    uint32_t min = 1;
    uint32_t max = 0xFFFFFFFF;  // 32位无符号最大值
    int count = 100000;         // 增加采样次数
    
    // 统计区间分布
    uint64_t sum = 0;
    uint32_t min_found = max;
    uint32_t max_found = min;
    
    // 生成随机数并检查分布
    for(int i = 0; i < count; i++) {
        uint32_t num = (uint32_t)generate_random_range(min, max);
        assert(num >= min && num <= max);
        
        // 更新统计
        sum += num;
        if(num < min_found) min_found = num;
        if(num > max_found) max_found = num;
    }
    
    // 检查分布（期望值应接近范围中点）
    double avg = (double)sum / count;
    double expected_avg = ((double)min + max) / 2;
    double error = (avg - expected_avg) / expected_avg;
    
    // 允许5%的误差
    assert(fabs(error) < 0.05);
    assert(min_found < (max / 4));           // 确保出现较小的数
    assert(max_found > (max * 3 / 4));       // 确保出现较大的数
    
    printf("无符号范围随机数生成测试通过:\n");
    printf("- 平均值: %.2f (期望: %.2f, 误差: %.2f%%)\n", 
           avg, expected_avg, error * 100);
    printf("- 最小值: %u\n", min_found);
    printf("- 最大值: %u\n", max_found);
}

void test_random_range_u64() {
    printf("测试3: 64位无符号范围随机数生成\n");
    
    // 测试64位无符号范围
    uint64_t min = 1ULL;
    uint64_t max = 0xFFFFFFFFFFFFFFFFULL;  // 64位无符号最大值
    int count = 100000;                     // 采样次数
    
    // 统计区间分布
    __uint128_t sum = 0;  // 使用128位整数避免溢出
    uint64_t min_found = max;
    uint64_t max_found = min;
    
    // 生成随机数并检查分布
    for(int i = 0; i < count; i++) {
        uint64_t num = generate_random_range_u64(min, max);
        assert(num >= min && num <= max);
        
        // 更新统计
        sum += num;
        if(num < min_found) min_found = num;
        if(num > max_found) max_found = num;
    }
    
    // 检查分布（期望值应接近范围中点）
    double avg = (double)(sum / count);
    double expected_avg = ((double)min + max) / 2;
    double error = fabs(avg - expected_avg) / expected_avg;
    
    // 允许5%的误差
    assert(error < 0.05);
    assert(min_found < (max / 4));          // 确保出现较小的数
    assert(max_found > (max * 3 / 4));      // 确保出现较大的数
    
    printf("64位无符号范围随机数生成测试通过:\n");
    printf("- 平均值: %.2e (期望: %.2e, 误差: %.2f%%)\n", 
           avg, expected_avg, error * 100);
    printf("- 最小值: %lu\n", min_found);
    printf("- 最大值: %lu\n", max_found);
}

void test_random_bytes() {
    printf("测试3: 随机字节数组生成\n");
    unsigned char bytes1[16];
    unsigned char bytes2[16];
    
    // 生成两组随机字节并比较
    assert(generate_random_bytes(bytes1, sizeof(bytes1)) == 0);
    assert(generate_random_bytes(bytes2, sizeof(bytes2)) == 0);
    assert(memcmp(bytes1, bytes2, sizeof(bytes1)) != 0);
    
    printf("随机字节数组生成测试通过\n");
}

void test_error_handling() {
    printf("测试4: 错误处理\n");
    // 测试空指针
    assert(generate_random_bytes(NULL, 16) != 0);
    // 测试长度为0
    unsigned char buf[1];
    assert(generate_random_bytes(buf, 0) == 0);
    printf("错误处理测试通过\n");
}

int main() {
    printf("开始测试随机数生成功能...\n");
    
    test_secure_random();
    test_random_range();
    test_random_range_u64();  // 添加64位测试
    test_random_bytes();
    test_error_handling();
    
    printf("所有测试通过!\n");
    return 0;
}
