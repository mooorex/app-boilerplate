#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

#define PARAMETERS_NUM 20
#define MAX_TICKER_LEN 8

enum {
    ADDRESS_LEN = 20,
    PK_LEN = 66,
    MAX_TX_LEN = 510,
    MAX_PARAM_LEN = 66,
};

enum {
    GAS_PRICE_MIN = 2500,
    GAS_LIMIT_MIN = 20000,
};

enum {
    HEADER_LENGTH = 42,
    NATIVE_CONTRACT_CONSTANT_LENGTH = 47,
    NEOVM_CONTRACT_CONSTANT_LENGTH = 22,
};

enum {
    OPCODE_PUSH_NUMBER = 0x50  // PUSHN = OPCODE_PUSH_NUMBER + N, 1<=N<=16
};

static const uint8_t OPCODE_SYSCALL[] = {0x00, 0x68};
static const uint8_t OPCODE_APPCALL[] = {0x67};
static const uint8_t OPCODE_PACK[] = {0xc1};
static const uint8_t OPCODE_END[] = {0x00};
static const uint8_t OPCODE_ST_BEGIN[] = {0x00, 0xc6, 0x6b};
static const uint8_t OPCODE_ST_END[] = {0x6c};
static const uint8_t OPCODE_PARAM_END[] = {0x6a, 0x7c, 0xc8};
static const uint8_t OPCODE_PARAM_ST_END[] = {0x6a, 0x7c, 0xc8, 0x6c};
static const uint8_t NATIVE_INVOKE[] = {0x16, 'O', 'n', 't', 'o', 'l', 'o', 'g', 'y', '.', 'N', 'a',
                                        't',  'i', 'v', 'e', '.', 'I', 'n', 'v', 'o', 'k', 'e'};

typedef enum {
    PARSING_OK = 1,
    WRONG_LENGTH_ERROR = -2,
    BYTECODE_PARSING_ERROR = -3,
    PARSING_TX_NOT_DEFINED = -4,
    PERSONAL_MESSAGE_PARSING_ERROR = -6
} parser_status_e;

typedef enum {
    UNKNOWN_CONTRACT,
    NATIVE_CONTRACT,
    NEOVM_CONTRACT,
    WASMVM_CONTRACT,
} tx_contract_type_e;

typedef enum {
    PARAM_END,  // Marks the end of parameters, not an actual parameter
    PARAM_ADDR,
    PARAM_PUBKEY,
    PARAM_AMOUNT,
    PARAM_UINT128,
    PARAM_ONTID,
    PARAM_PK_AMOUNT_PAIRS,      // PARAM_PUBKEY, PARAM_AMOUNT
    PARAM_TRANSFER_STATE,       // PARAM_ADDR, PARAM_ADDR, PARAM_AMOUNT
    PARAM_TRANSFER_STATE_LIST,  // PARAM_TRANSFER_STATE * n
} tx_parameter_type_e;

typedef struct {
    uint8_t version;
    uint8_t tx_type;
    uint32_t nonce;
    uint64_t gas_price;
    uint64_t gas_limit;
    uint8_t *payer;
} transaction_header_t;

typedef struct {
    uint8_t *data;
    tx_parameter_type_e type;
    uint8_t len;
} tx_parameter_t;

typedef struct {
    tx_contract_type_e type;
    tx_parameter_t addr;
    uint8_t token_decimals;
    char ticker[MAX_TICKER_LEN];
} tx_contract_t;

typedef struct {
    tx_parameter_t name;
    tx_parameter_t parameters[PARAMETERS_NUM];
} tx_method_t;

typedef struct {
    transaction_header_t header;
    tx_contract_t contract;
    tx_method_t method;
} transaction_t;
