#pragma once

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>
#include <string.h>

#include "buffer.h"
#include "types.h"
#include "../types.h"

#define ADDRESS_LEN  20
#define PEER_PUBKEY_LEN   66
#define PAYLOAD_MIN_LENGTH_LIMIT 44
#define PAYLOAD_TRANSFER_LEN  54
#define PAYLOAD_TRANSFER_FROM_LEN  58

#define MAX_RESULT_SIZE 20
#define VALUE_SIZE 8
#define OPCODE_VALUE  81
#define OPCODE_OPERATION_CODE  13139050 //6a7cc8
#define UINT64_T_BYTE_LEN 8
#define TWO_UINT64_T_BYTE_LEN 16

/** the length of a SHA256 hash */
#define SHA256_HASH_LEN 32

/** the current version of the address field */
#define ADDRESS_VERSION 23

/** length of tx.output.script_hash */
#define SCRIPT_HASH_LEN 20

/** length of the checksum used to convert a script_hash into an Address. */
#define SCRIPT_HASH_CHECKSUM_LEN 4

/** length of a Address before encoding, which is the length of <address_version>+<script_hash>+<checksum> */
#define ADDRESS_LEN_PRE (1 + SCRIPT_HASH_LEN + SCRIPT_HASH_CHECKSUM_LEN)

#define VERIFICATION_SCRIPT_LENGTH 35

#define UINT160_LEN 20

#define MAX_LENGTH 40                //Accommodates 128-bit maximum
#define BASE 10                      //Decimal
#define P64_R 6                      //2^64 % 10
#define P64_Q 1844674407370955161ULL //2^64 / 10

uint64_t getBytesValueByLen(buffer_t *buf,uint8_t len);

uint64_t getValueByLen(uint8_t *value,uint8_t len);

void script_hash_to_address(char* out, size_t out_len, const unsigned char* script_hash);


void process_precision(const char *input, int precision, char *output, size_t output_len);


bool create_signature_redeem_script(const uint8_t *uncompressed_key, uint8_t* out, size_t out_len);
void generate_address_from_public_key(const uint8_t *compressed_key, size_t key_len, uint8_t *output_hash);

bool ont_address_from_pubkey(char* out, size_t out_len);
/**
 * Convert public key to ont address.
 * @param[in]  public_key
 *   Pointer to byte buffer with public key.
 *   The public key is represented as 65 bytes with 1 byte for format and 32 bytes for
 *   each coordinate.
 * @param[out] out
 *   Pointer to output byte buffer for address.
 * @param[in]  out_len
 *   Length of output byte buffer.
 *
 * @return true if success, false otherwise.
 *
 */
bool ont_address_by_pubkey(const uint8_t public_key[static 65],char* out, size_t out_len);

void uint128_to_decimal_string(uint64_t high, uint64_t low, char* result, size_t buffer_size);

bool get_token_amount(const uint8_t value_len,const uint64_t value[2],const uint8_t decimals,char* amount,size_t amount_len);

bool get_token_value(uint8_t value_len,uint8_t *data,const uint8_t decimals,char* amount,size_t amount_len);

bool get_ong_fee(uint64_t gas_price,uint64_t gas_limit);