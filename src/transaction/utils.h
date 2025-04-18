#pragma once

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>
#include <string.h>

#include "types.h"
#include "../types.h"

#define UINT128_MAX_LENGTH 40
#define BASE               10                      // Decimal
#define P64_R              6                       // 2^64 % 10
#define P64_Q              1844674407370955161ULL  // 2^64 / 10

/**
 * Convert a parameter to a uint64_t in little-endian order.
 *
 * @param[in] amount
 *   Pointer to parameter structure containing the amount.
 * @param[out] out
 *   Pointer to store the converted uint64_t value.
 *
 * @return true if conversion successful, false otherwise.
 */
bool convert_param_to_uint64_le(tx_parameter_t *amount, uint64_t *out);

/**
 * Convert a parameter amount (including PARAM_UINT128 and PARAM_AMOUNT) to a 
 * decimal string representation.
 *
 * @param[in] param
 *   Pointer to parameter structure containing the amount.
 * @param[in] decimals
 *   Number of decimal places to format.
 * @param[in] has_prefix
 *   Whether the parameter has a prefix byte.
 * @param[out] amount
 *   Buffer to store the formatted amount string.
 * @param[in] amount_len
 *   Length of the amount buffer.
 *
 * @return true if conversion successful, false otherwise.
 */
bool convert_param_amount_to_chars(tx_parameter_t *param,
                                   uint8_t decimals,
                                   bool has_prefix,
                                   char *amount,
                                   size_t amount_len);

/**
 * Compare a parameter's method name against a string.
 *
 * @param[in] param
 *   Pointer to parameter structure containing the method name.
 * @param[in] method_name
 *   String to compare against.
 *
 * @return true if method names match, false otherwise.
 */
static inline bool methodcmp(const tx_parameter_t *param, const char *method_name) {
    return param->len == strlen(method_name) && memcmp(param->data, method_name, param->len) == 0;
}