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

#if defined(TEST) || defined(FUZZ)
#include "assert.h"
#define LEDGER_ASSERT(x, y) assert(x)
#else
#include "ledger_assert.h"
#endif

#include "address.h"
#include "types.h"
#include "base58.h"
#include "lcx_common.h"
#include "lcx_sha256.h"
#include "lcx_ripemd160.h"
#include "crypto_helpers.h"
#include "../globals.h"

bool convert_script_hash_to_base58_address(char* out, size_t out_len, const uint8_t* script_hash) {
    LEDGER_ASSERT(out != NULL, "NULL out");
    LEDGER_ASSERT(script_hash != NULL, "NULL script_hash");

    if (out_len < BASE58_ADDRESS_LEN) {
        return false;
    }

    cx_sha256_t data_hash;
    uint8_t data_hash_1[SHA256_HASH_LEN];
    uint8_t data_hash_2[SHA256_HASH_LEN];
    uint8_t address[ADDRESS_LEN_PRE];

    address[0] = ADDRESS_VERSION;
    memcpy(&address[1], script_hash, SCRIPT_HASH_LEN);

    cx_sha256_init(&data_hash);
    if (cx_hash_no_throw(&data_hash.header, CX_LAST, address, SCRIPT_HASH_LEN + 1, data_hash_1, SHA256_HASH_LEN) != CX_OK) {
        return false;
    }

    cx_sha256_init(&data_hash);
    if (cx_hash_no_throw(&data_hash.header, CX_LAST, data_hash_1, SHA256_HASH_LEN, data_hash_2, SHA256_HASH_LEN) != CX_OK) {
        return false;
    }

    memcpy(&address[1 + SCRIPT_HASH_LEN], data_hash_2, SCRIPT_HASH_CHECKSUM_LEN);

    bool result = base58_encode(address, sizeof(address), out, out_len);

    explicit_bzero(data_hash_1, sizeof(data_hash_1));
    explicit_bzero(data_hash_2, sizeof(data_hash_2));
    explicit_bzero(address, sizeof(address));

    return result;
}

bool derive_address_from_bip32_path(char* out, size_t out_len) {
    LEDGER_ASSERT(out != NULL, "NULL out");

    uint8_t uncompressed_key[UNCOMPRESSED_KEY_LEN];
    uint8_t chain_code[CHAIN_CODE_LEN];

    cx_err_t error = bip32_derive_get_pubkey_256(CX_CURVE_256R1,
                                                G_context.bip32_path,
                                                G_context.bip32_path_len,
                                                uncompressed_key,
                                                chain_code,
                                                CX_SHA256);

    if (error != CX_OK) {
        return false;
    }

    bool result = convert_uncompressed_pubkey_to_address(uncompressed_key, out, out_len);

    explicit_bzero(uncompressed_key, sizeof(uncompressed_key));
    explicit_bzero(chain_code, sizeof(chain_code));

    return result;
}

bool convert_uncompressed_pubkey_to_address(const uint8_t uncompressed_key[static UNCOMPRESSED_KEY_LEN], char* out, size_t out_len) {
    LEDGER_ASSERT(uncompressed_key != NULL, "NULL uncompressed_key");
    LEDGER_ASSERT(out != NULL, "NULL out");

    if (out_len < BASE58_ADDRESS_LEN) {
        return false;
    }

    uint8_t verification_script[VERIFICATION_SCRIPT_LENGTH] = {0};
    uint8_t ripemd160_hash[UINT160_LEN] = {0};

    bool result = compress_public_key(uncompressed_key, verification_script, sizeof(verification_script)) &&
                 compute_address_from_verification_script(verification_script, sizeof(verification_script), ripemd160_hash) &&
                 convert_script_hash_to_base58_address(out, out_len, ripemd160_hash);

    explicit_bzero(verification_script, sizeof(verification_script));
    explicit_bzero(ripemd160_hash, sizeof(ripemd160_hash));

    return result;
}

bool compute_address_from_verification_script(const uint8_t *verification_script, 
                                            size_t script_len, 
                                            uint8_t *output_hash) {
    LEDGER_ASSERT(verification_script != NULL, "NULL verification_script");
    LEDGER_ASSERT(output_hash != NULL, "NULL output_hash");

    if (script_len != VERIFICATION_SCRIPT_LENGTH) {
        return false;
    }

    if (verification_script[0] != 0x21 || verification_script[34] != 0xac) {
        return false;
    }

    struct {
        cx_ripemd160_t ripe;
    } u;
    uint8_t sha256_hash[SHA256_HASH_LEN];

    bool result = (cx_hash_sha256(verification_script, script_len, sha256_hash, sizeof(sha256_hash)) == CX_OK) &&
                 (cx_ripemd160_init(&u.ripe) == CX_OK) &&
                 (cx_hash_no_throw(&u.ripe.header, CX_LAST, sha256_hash, SHA256_HASH_LEN, output_hash, UINT160_LEN) == CX_OK);

    explicit_bzero(sha256_hash, sizeof(sha256_hash));
    explicit_bzero(&u, sizeof(u));

    return result;
}

bool compress_public_key(const uint8_t *uncompressed_key, uint8_t* out, size_t out_len) {
    LEDGER_ASSERT(uncompressed_key != NULL, "NULL uncompressed_key");
    LEDGER_ASSERT(out != NULL, "NULL out");

    if (out_len != VERIFICATION_SCRIPT_LENGTH) {
        return false;
    }

    if (uncompressed_key[0] != 0x04) {
        return false;
    }

    const uint8_t *x = &uncompressed_key[1];
    const uint8_t *y = &uncompressed_key[33];
    uint8_t compressed_key[COMPRESSED_KEY_LEN];

    compressed_key[0] = (y[31] & 1) ? 0x03 : 0x02;
    memcpy(&compressed_key[1], x, 32);

    out[0] = 0x21;
    memcpy(&out[1], compressed_key, sizeof(compressed_key));
    out[34] = 0xac;

    explicit_bzero(compressed_key, sizeof(compressed_key));

    return true;
}
