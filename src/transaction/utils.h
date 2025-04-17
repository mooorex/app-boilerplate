#pragma once

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>
#include <string.h>

#include "types.h"
#include "../types.h"

#define UINT128_MAX_LENGTH 40
#define UINT64_BYTE_LEN    8
#define UINT128_BYTE_LEN   16
#define MAX_LENGTH         40                      // Accommodates 128-bit maximum
#define BASE               10                      // Decimal
#define P64_R              6                       // 2^64 % 10
#define P64_Q              1844674407370955161ULL  // 2^64 / 10


bool convert_param_to_uint64_le(tx_parameter_t *amount, uint64_t *out);

bool convert_param_amount_to_chars(tx_parameter_t *param,
                                   uint8_t decimals,
                                   bool has_prefix,
                                   char *amount,
                                   size_t amount_len);

static inline bool is_specific_method(const tx_parameter_t *param, const char *method_name) {
    return param->len == strlen(method_name) && memcmp(param->data, method_name, param->len) == 0;
}