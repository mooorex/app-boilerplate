#pragma once

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>

enum {
    UINT128_MAX_LENGTH = 40,
    DECIMAL_BASE = 10,
    P64_Q = 6,                       // 2^64 % 10
};

#define P64_R  1844674407370955161ULL  // 2^64 / 10

bool format_u128(uint64_t high, uint64_t low, char *dst, size_t dst_len);
bool format_fpu128(uint64_t high, uint64_t low, char *dst, size_t dst_len, uint8_t decimals);
bool format_fpu128_trimmed(uint64_t high,
                           uint64_t low,
                           char *dst,
                           size_t dst_len,
                           uint8_t decimals);
bool process_decimals(char *dst, size_t dst_len, const char *buffer, uint8_t decimals);