#pragma once

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t

#define SHA256_HASH_LEN            32
#define ADDRESS_VERSION            23
#define SCRIPT_HASH_LEN            20
#define SCRIPT_HASH_CHECKSUM_LEN   4
#define ADDRESS_LEN_PRE            (1 + SCRIPT_HASH_LEN + SCRIPT_HASH_CHECKSUM_LEN)
#define VERIFICATION_SCRIPT_LENGTH 35
#define BASE58_ADDRESS_LEN         34
#define UNCOMPRESSED_KEY_LEN       65
#define COMPRESSED_KEY_LEN         33
#define CHAIN_CODE_LEN             32
#define UINT160_LEN                20

bool convert_script_hash_to_base58_address(char* out, size_t out_len, const uint8_t* script_hash);

bool derive_address_from_bip32_path(char* out, size_t out_len);

bool convert_uncompressed_pubkey_to_address(
    const uint8_t uncompressed_key[static UNCOMPRESSED_KEY_LEN],
    char* out,
    size_t out_len);
