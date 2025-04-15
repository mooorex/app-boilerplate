/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/
#include <stdio.h>

#include "utils.h"
#include "format.h"

#include "../globals.h"

static bool convert_bytes_to_uint64_le(const uint8_t *amount, const size_t len, uint64_t *out) {
    if (amount == NULL || out == NULL) {
        return false;
    }

    if (len > sizeof(uint64_t) || len == 0) {
        return false;
    }

    *out = 0;
    for (size_t i = 0; i < len; i++) {
        *out |= ((uint64_t) amount[i] << (8 * i));
    }

    return true;
}

static bool process_precision(const char *input, int precision, char *output, size_t output_len) {
    // Input validation
    if (!input || !output || output_len == 0 || precision < 0) {
        if (output != NULL && output_len > 0) output[0] = '\0';
        return false;
    }

    size_t len = strlen(input);
    if (len == 0) {  // Handle empty string
        if (output_len > 1)
            strlcpy(output, "0", sizeof(output));
        else if (output_len > 0)
            output[0] = '\0';
        return false;
    }

    // Pre-check if output buffer is sufficient
    size_t max_len = len + (precision > (int) len ? precision - len + 2 : 1);
    if (max_len + 1 > output_len) {
        output[0] = '\0';
        return false;
    }

    char *ptr = output;
    if ((size_t) precision >= len) {
        // Precision >= input length: prepend "0." and pad with zeros
        *ptr++ = '0';
        *ptr++ = '.';
        size_t zeros = precision - len;
        memset(ptr, '0', zeros);  // Use memset instead of loop
        ptr += zeros;
        memcpy(ptr, input, len);
        ptr[len] = '\0';
    } else if (precision == 0) {
        memcpy(ptr, input, len + 1);  // Directly copy with null terminator
    } else {
        // Normal case: insert decimal point
        size_t int_len = len - precision;
        memcpy(ptr, input, int_len);
        ptr += int_len;
        *ptr++ = '.';
        memcpy(ptr, input + int_len, precision);
        ptr[precision] = '\0';
    }

    // Remove trailing zeros after decimal point
    ptr = strchr(output, '.');
    if (ptr) {
        char *end = output + strlen(output);
        while (end > ptr + 1 && *(end - 1) == '0') *(--end) = '\0';
        if (end > output && *(end - 1) == '.') *(--end) = '\0';
    }

    return true;
}

static bool convert_params_to_uint128_le(tx_parameter_t *amount,
                                         bool has_prefix,
                                         uint64_t *low,
                                         uint64_t *high) {
    if (amount == NULL || low == NULL || high == NULL) {
        return false;
    }

    size_t size64 = sizeof(uint64_t);
    if (amount->len > 2 * size64 || amount->len == 0) {
        return false;
    }

    *low = 0;
    *high = 0;
    size_t prefix_len = has_prefix ? 1 : 0;
    size_t high_len = amount->len > size64 + prefix_len ? amount->len - size64 - prefix_len : 0;

    return has_prefix && high_len == 0 ? convert_param_to_uint64_le(amount, low)
               : convert_bytes_to_uint64_le(amount->data + prefix_len, size64, low) &&
                 convert_bytes_to_uint64_le(amount->data + prefix_len + size64, high_len, high);
}


static bool format_u128(uint64_t high, uint64_t low, char *result, size_t buffer_size) {
    if (result == NULL) {
        return false;
    }

    int index = MAX_LENGTH;
    char buffer[MAX_LENGTH];

    buffer[--index] = '\0';

    if (high == 0 && low == 0) {
        buffer[--index] = '0';
    }

    while (high != 0 || low != 0) {
        uint64_t high_quotient = high / BASE;
        uint64_t high_remainder = high % BASE;
        uint64_t low_quotient = low / BASE;
        uint64_t low_remainder = low % BASE;

        uint64_t high_part_q = high_remainder * P64_Q;
        uint64_t high_part_r = high_remainder * P64_R;

        uint64_t curr_q = (high_part_r + low_remainder) / BASE;
        uint64_t curr_r = (high_part_r + low_remainder) % BASE;

        buffer[--index] = '0' + (char) curr_r;

        uint64_t sum_high = 0;
        uint64_t sum_low = high_part_q;

        sum_low += low_quotient;
        if (sum_low < low_quotient) sum_high++;
        sum_low += curr_q;
        if (sum_low < curr_q) sum_high++;

        high = high_quotient + sum_high;
        low = sum_low;
    }

    size_t required_length = MAX_LENGTH - index;
    if (buffer_size < required_length) {
        return false;
    }

    memcpy(result, &buffer[index], required_length);
    return true;
}

static bool format_fpu128_trimmed(char *dst,
                                  size_t dst_len,
                                  uint64_t low,
                                  uint64_t high,
                                  uint8_t decimals) {
    if (dst == NULL) {
        return false;
    }
    if (decimals > UINT128_MAX_LENGTH - 1) {
        return false;
    }

    char buffer[UINT128_MAX_LENGTH] = {0};

    return format_u128(high, low, buffer, sizeof(buffer)) &&
           process_precision(buffer, decimals, dst, dst_len);
}

bool convert_param_to_uint64_le(tx_parameter_t *amount, uint64_t *out) {
    if (amount == NULL || out == NULL) {
        return false;
    }

    if (amount->len > sizeof(uint64_t) || amount->len == 0) {
        return false;
    }

    *out = 0;
    uint8_t amt = amount->data[0];

    if (amt > OPCODE_PUSH_NUMBER && amt <= OPCODE_PUSH_NUMBER + 16) {
        *out = amt - OPCODE_PUSH_NUMBER;
        return true;
    }

    return convert_bytes_to_uint64_le(amount->data + 1, amt, out);
}

bool get_token_value(tx_parameter_t *param,
                     uint8_t decimals,
                     bool has_prefix,
                     char *amount,
                     size_t amount_len) {
    if (param == NULL || amount == 0) {
        return false;
    }

    uint64_t high = 0;
    uint64_t low = 0;

    return (has_prefix || param->len == 2 * sizeof(uint64_t)) &&
            convert_params_to_uint128_le(param, has_prefix, &low, &high) &&
            format_fpu128_trimmed(amount, amount_len, low, high, decimals);
}

bool get_gas_fee(uint64_t gas_price, uint64_t gas_limit) {
    if (gas_price == 0 || gas_limit == 0 || gas_price > UINT64_MAX / gas_limit ||
        !format_fpu64_trimmed(G_context.display_data.gas_fee,
                              sizeof(G_context.display_data.gas_fee),
                              gas_price * gas_limit,
                              9)) {
        return false;
    }
    strlcat(G_context.display_data.gas_fee, ONG_VIEW, sizeof(G_context.display_data.gas_fee));

    return true;
}
