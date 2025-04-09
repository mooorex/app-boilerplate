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
#include "utils.h"
#include <stdio.h>

#include "utils.h"
#include "base58.h"
#include "lcx_common.h"
#include "lcx_sha256.h"
#include "lcx_ripemd160.h"
#include "crypto_helpers.h"
#include "format.h"
#include "../globals.h"
#include "../ui/types.h"

#if defined(TEST) || defined(FUZZ)
#include "assert.h"
#define LEDGER_ASSERT(x, y) assert(x)
#else
#include "ledger_assert.h"
#endif

uint64_t getBytesValueByLen(buffer_t *buf, uint8_t len) {
    uint8_t *value;
    value = (uint8_t *) (buf->ptr + buf->offset);
    if (!buffer_seek_cur(buf, len)) {
        return 0;
    }
    return getValueByLen(value, len);
}

uint64_t getValueByLen(uint8_t *value,uint8_t len) {

    uint64_t pre_value =0;
    for (int i = 0; i < len; i++) {
        PRINTF("After: data points to %p, value = 0x%02X\n", (void *)value, value[i]);
        pre_value |= ((uint64_t)value[i] << (8 * i));
    }
    return pre_value;
}

void script_hash_to_address(char *out, size_t out_len, const unsigned char *script_hash) {
    static cx_sha256_t data_hash;
    unsigned char data_hash_1[SHA256_HASH_LEN];
    unsigned char data_hash_2[SHA256_HASH_LEN];
    unsigned char address[ADDRESS_LEN_PRE];

    address[0] = ADDRESS_VERSION;
    memcpy(&address[1], script_hash, SCRIPT_HASH_LEN);

    cx_sha256_init(&data_hash);
    CX_ASSERT(cx_hash_no_throw(&data_hash.header,
                               CX_LAST,
                               address,
                               SCRIPT_HASH_LEN + 1,
                               data_hash_1,
                               32));
    cx_sha256_init(&data_hash);
    CX_ASSERT(cx_hash_no_throw(&data_hash.header,
                               CX_LAST,
                               data_hash_1,
                               SHA256_HASH_LEN,
                               data_hash_2,
                               32));

    memcpy(&address[1 + SCRIPT_HASH_LEN], data_hash_2, SCRIPT_HASH_CHECKSUM_LEN);

    base58_encode(address, sizeof(address), out, out_len);
}

void process_precision(const char *input, int precision, char *output, size_t output_len) {
    // Input validation
    if (!input || !output || output_len == 0 || precision < 0) {
        if (output_len > 0) output[0] = '\0';
        return;
    }

    size_t len = strlen(input);
    if (len == 0) {  // Handle empty string
        if (output_len > 1)
            strcpy(output, "0");
        else if (output_len > 0)
            output[0] = '\0';
        return;
    }

    // Pre-check if output buffer is sufficient
    size_t max_len = len + (precision > (int) len ? precision - len + 2 : 1);
    if (max_len + 1 > output_len) {
        output[0] = '\0';
        return;
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
}

bool create_signature_redeem_script(const uint8_t *uncompressed_key, uint8_t *out, size_t out_len) {
    if (out_len != VERIFICATION_SCRIPT_LENGTH) {
        return false;
    }
    const uint8_t *x = &uncompressed_key[1];
    const uint8_t *y = &uncompressed_key[33];
    uint8_t compressed_key[33];
    compressed_key[0] = (y[31] & 1) ? 0x03 : 0x02;
    memcpy(&compressed_key[1], x, 32);
    out[0] = 0x21;
    memcpy(&out[1], compressed_key, sizeof(compressed_key));
    out[34] = 0xac;
    return true;
}

void generate_address_from_public_key(const uint8_t *compressed_key,
                                      size_t key_len,
                                      uint8_t *output_hash) {
    struct {
        cx_ripemd160_t ripe;
    } u;
    uint8_t sha256_hash[SHA256_HASH_LEN];
    cx_hash_sha256(compressed_key, key_len, sha256_hash, sizeof(sha256_hash));
    cx_ripemd160_init(&u.ripe);
    CX_ASSERT(cx_hash_no_throw(&u.ripe.header, CX_LAST, sha256_hash, 32, output_hash, 20));
}

bool ont_address_from_pubkey(char *out, size_t out_len) {
    uint8_t uncompressed_key[65];  /// format (1), x-coordinate (32), y-coodinate (32)
    uint8_t chain_code[32];
    cx_err_t error = bip32_derive_get_pubkey_256(CX_CURVE_256R1,
                                                 G_context.bip32_path,
                                                 G_context.bip32_path_len,
                                                 uncompressed_key,
                                                 chain_code,
                                                 CX_SHA256);

    if (error != CX_OK) {
        return false;
    }
    return ont_address_by_pubkey(uncompressed_key, out, out_len);
}

bool ont_address_by_pubkey(const uint8_t uncompressed_key[static 65], char *out, size_t out_len) {
    uint8_t verification_script[VERIFICATION_SCRIPT_LENGTH] = {0};
    if (!create_signature_redeem_script(uncompressed_key,
                                        verification_script,
                                        sizeof verification_script)) {
        return false;
    }
    uint8_t ripemd160_hash[UINT160_LEN] = {0};
    generate_address_from_public_key(verification_script,
                                     sizeof verification_script,
                                     ripemd160_hash);
    script_hash_to_address(out, out_len, ripemd160_hash);
    return true;
}

void uint128_to_decimal_string(uint64_t high, uint64_t low, char *result, size_t buffer_size) {
    if (result == NULL) {
        return;
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
        return;
    }

    memcpy(result, &buffer[index], required_length);
}

bool get_token_amount(const uint8_t value_len,
                      const uint64_t value[2],
                      const uint8_t decimals,
                      char *amount,
                      size_t amount_len) {
    if (value_len >= OPCODE_VALUE) {
        return format_fpu64_trimmed(amount, amount_len, value[0], decimals);
    } else {
        if (value_len <= UINT64_T_BYTE_LEN) {
            return format_fpu64_trimmed(amount, amount_len, value[0], decimals);
        } else if (value_len > TWO_UINT64_T_BYTE_LEN) {
            return false;
        } else {
            char totalAmount[MAX_LENGTH];
            uint128_to_decimal_string(value[1], value[0], totalAmount, sizeof(totalAmount));
            process_precision(totalAmount, decimals, amount, amount_len);
            explicit_bzero(&totalAmount, sizeof(totalAmount));
            return true;
        }
    }
}

bool get_token_value(uint8_t value_len,
                     uint8_t *data,
                     const uint8_t decimals,
                     char *amount,
                     size_t amount_len) {
    uint8_t value = *data;
    PRINTF("get_token_value00000:%d\n", value);
    if (value_len == 1) {
        return format_fpu64_trimmed(amount, amount_len, getValueByLen(data+1, value_len), decimals);
    } else {
        if (value_len <= UINT64_T_BYTE_LEN) {
            PRINTF("get_token_value1111: %d,:%d\n", value_len, decimals);
            return format_fpu64_trimmed(amount,
                                        amount_len,
                                        getValueByLen(data+1, value_len),
                                        decimals);
        } else if (value_len > TWO_UINT64_T_BYTE_LEN) {
            return false;
        } else {
            char totalAmount[MAX_LENGTH];
            uint128_to_decimal_string(
                getValueByLen(data + UINT64_T_BYTE_LEN, value_len - UINT64_T_BYTE_LEN),
                getValueByLen(data, value_len - UINT64_T_BYTE_LEN),
                totalAmount,
                sizeof(totalAmount));
            process_precision(totalAmount, decimals, amount, amount_len);
            explicit_bzero(&totalAmount, sizeof(totalAmount));
            return true;
        }
    }
}

void get_ong_fee(uint64_t gas_price, uint64_t gas_limit, char *out, size_t out_len) {
    format_fpu64_trimmed(out, out_len, gas_price * gas_limit, 9);
    strlcat(out, ONG_VIEW, out_len);
}