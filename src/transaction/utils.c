/*****************************************************************************
 *   Ledger App Boilerplate.
 *   (c) 2020 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may n`ot use this file except in compliance with the License.
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

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <string.h>   // memmove
#include <stdio.h>

#if defined(TEST) || defined(FUZZ)
#include "assert.h"
#define LEDGER_ASSERT(x, y) assert(x)
#else
#include "ledger_assert.h"
#endif

#include "utils.h"
#include "types.h"
#include "format.h"
#include "globals.h"

bool format_u128(uint64_t high, uint64_t low, char *dst, size_t dst_len) {
    if (dst == NULL) {
        return false;
    }

    int index = UINT128_MAX_LENGTH;
    char buffer[UINT128_MAX_LENGTH] = {0};

    buffer[--index] = '\0';

    if (high == 0 && low == 0) {
        buffer[--index] = '0';
    }

    while (high != 0 || low != 0) {
        uint64_t high_quotient = high / DECIMAL_BASE;
        uint64_t high_remainder = high % DECIMAL_BASE;
        uint64_t low_quotient = low / DECIMAL_BASE;
        uint64_t low_remainder = low % DECIMAL_BASE;

        uint64_t high_part_q = high_remainder * P64_Q;
        uint64_t high_part_r = high_remainder * P64_R;

        uint64_t curr_q = (high_part_r + low_remainder) / DECIMAL_BASE;
        uint64_t curr_r = (high_part_r + low_remainder) % DECIMAL_BASE;

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

    size_t required_length = UINT128_MAX_LENGTH - index;
    if (dst_len < required_length) {
        return false;
    }

    memcpy(dst, buffer + index, required_length);
    return true;
}

bool format_fpu128(uint64_t high, uint64_t low, char *dst, size_t dst_len, uint8_t decimals) {
    if (dst == NULL) {
        return false;
    }
    if (decimals > UINT128_MAX_LENGTH - 1) {
        return false;
    }

    char buffer[UINT128_MAX_LENGTH] = {0};

    return format_u128(high, low, buffer, sizeof(buffer)) &&
           process_decimals(dst, dst_len, buffer, decimals);
}

bool format_fpu128_trimmed(uint64_t high,
                           uint64_t low,
                           char *dst,
                           size_t dst_len,
                           uint8_t decimals) {
    if (!format_fpu128(high, low, dst, dst_len, decimals)) {
        return false;
    }

    size_t len = strlen(dst);

    while (len > 0 && (dst[len - 1] == '0' || dst[len - 1] == '.')) {
        if (dst[len - 1] == '.') {
            dst[len - 1] = '\0';
            return true;
        }
        len--;
    }
    dst[len] = '\0';
    return true;
}

bool process_decimals(char *dst, size_t dst_len, const char *buffer, uint8_t decimals) {
    if (!dst || !buffer) {
        return false;
    }

    size_t digits = strlen(buffer);

    if (digits <= decimals) {
        if (dst_len <= 2 + decimals - digits) {
            return false;
        }
        *dst++ = '0';
        *dst++ = '.';
        for (uint16_t i = 0; i < decimals - digits; i++, dst++) {
            *dst = '0';
        }
        dst_len -= 2 + decimals - digits;
        strncpy(dst, buffer, dst_len);
    } else {
        if (dst_len <= digits + 1 + decimals) {
            return false;
        }

        const size_t shift = digits - decimals;
        memmove(dst, buffer, shift);
        dst[shift] = '.';
        strncpy(dst + shift + 1, buffer + shift, decimals);
    }

    return true;
}
