#pragma once

#include "tx_types.h"

// Address constants
static const uint8_t ONT_ADDR[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static const uint8_t ONG_ADDR[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
static const uint8_t GOV_ADDR[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07};
static const uint8_t WING_ADDR[] = {0x80, 0xef, 0x58, 0x6e, 0xf5, 0xff, 0xf2, 0xb1, 0xea, 0x83,
                                    0x78, 0x39, 0xd6, 0x62, 0xa5, 0x27, 0xcd, 0x9f, 0xc5, 0x00};

// #ifdef DEBUG
static const uint8_t WTK_ADDR[] = {0x77, 0xF1, 0xFF, 0xE3, 0xAD, 0xA5, 0xDD, 0x78, 0x62, 0xF9,
                                   0x60, 0x1F, 0x5A, 0x0A, 0x05, 0x8A, 0x6B, 0xD8, 0x27, 0x43};
static const uint8_t MYT_ADDR[] = {0xff, 0x92, 0xa1, 0xa3, 0x41, 0x8d, 0x53, 0x68, 0x40, 0x05,
                                   0xaf, 0x98, 0xd5, 0xf1, 0xad, 0xd0, 0x5f, 0x15, 0xed, 0x19};
// #endif

// Common method name constants
#define METHOD_TRANSFER "transfer"
#define METHOD_TRANSFER_FROM "transferFrom"
#define METHOD_APPROVE "approve"
#define METHOD_TRANSFER_V2 "transferV2"
#define METHOD_TRANSFER_FROM_V2 "transferFromV2"
#define METHOD_APPROVE_V2 "approveV2"
#define METHOD_REGISTER_CANDIDATE "registerCandidate"
#define METHOD_QUIT_NODE "quitNode"
#define METHOD_ADD_INIT_POS "addInitPos"
#define METHOD_REDUCE_INIT_POS "reduceInitPos"
#define METHOD_CHANGE_MAX_AUTH "changeMaxAuthorization"
#define METHOD_SET_FEE_PERCENTAGE "setFeePercentage"
#define METHOD_AUTHORIZE_FOR_PEER "authorizeForPeer"
#define METHOD_UNAUTHORIZE_FOR_PEER "unAuthorizeForPeer"
#define METHOD_WITHDRAW "withdraw"
#define METHOD_WITHDRAW_FEE "withdrawFee"

typedef struct {
    const char *name;
    const tx_parameter_type_e *parameters;
} tx_method_signature_t;

typedef struct {
    const uint8_t *contract_addr;
    uint8_t token_decimals;
    const tx_method_signature_t *methods;
} payload_t;

// Method arrays
static const tx_method_signature_t native_token_methods[] = {
    {.name = METHOD_TRANSFER,
     .parameters = (const tx_parameter_type_e[]) {PARAM_TRANSFER_STATE_LIST, PARAM_END}},
    {.name = METHOD_TRANSFER_FROM,
     .parameters = (const tx_parameter_type_e[]) {PARAM_ADDR, PARAM_TRANSFER_STATE, PARAM_END}},
    {.name = METHOD_APPROVE,
     .parameters = (const tx_parameter_type_e[]) {PARAM_ADDR, PARAM_ADDR, PARAM_AMOUNT, PARAM_END}},
    {.name = METHOD_TRANSFER_V2,
     .parameters = (const tx_parameter_type_e[]) {PARAM_TRANSFER_STATE_LIST, PARAM_END}},
    {.name = METHOD_TRANSFER_FROM_V2,
     .parameters = (const tx_parameter_type_e[]) {PARAM_ADDR, PARAM_TRANSFER_STATE, PARAM_END}},
    {.name = METHOD_APPROVE_V2,
     .parameters = (const tx_parameter_type_e[]) {PARAM_ADDR, PARAM_ADDR, PARAM_AMOUNT, PARAM_END}},
    {.name = NULL}
};

static const tx_method_signature_t neovm_oep4_token_methods[] = {
    {.name = METHOD_TRANSFER,
     .parameters = (const tx_parameter_type_e[]) {PARAM_AMOUNT, PARAM_ADDR, PARAM_ADDR, PARAM_END}},
    {.name = METHOD_TRANSFER_FROM,
     .parameters = (const tx_parameter_type_e[]) {PARAM_AMOUNT, PARAM_ADDR, PARAM_ADDR, PARAM_ADDR, PARAM_END}},
    {.name = METHOD_APPROVE,
     .parameters = (const tx_parameter_type_e[]) {PARAM_AMOUNT, PARAM_ADDR, PARAM_ADDR, PARAM_END}},
    {.name = NULL}
};

static const tx_method_signature_t wasmvm_oep4_token_methods[] = {
    {.name = METHOD_TRANSFER,
     .parameters = (const tx_parameter_type_e[]) {PARAM_ADDR, PARAM_ADDR, PARAM_UINT128, PARAM_END}},
    {.name = METHOD_TRANSFER_FROM,
     .parameters = (const tx_parameter_type_e[]) {PARAM_ADDR, PARAM_ADDR, PARAM_ADDR, PARAM_UINT128, PARAM_END}},
    {.name = METHOD_APPROVE,
     .parameters = (const tx_parameter_type_e[]) {PARAM_ADDR, PARAM_ADDR, PARAM_UINT128, PARAM_END}},
    {.name = NULL}
};


static const tx_method_signature_t native_governance_methods[] = {
    {.name = METHOD_REGISTER_CANDIDATE,
     .parameters = (const tx_parameter_type_e[]) {PARAM_PUBKEY, PARAM_ADDR, PARAM_AMOUNT, PARAM_ONTID, PARAM_AMOUNT, PARAM_END}},
    {.name = METHOD_QUIT_NODE,
     .parameters = (const tx_parameter_type_e[]) {PARAM_PUBKEY, PARAM_ADDR, PARAM_END}},
    {.name = METHOD_ADD_INIT_POS,
     .parameters = (const tx_parameter_type_e[]) {PARAM_PUBKEY, PARAM_ADDR, PARAM_AMOUNT, PARAM_END}},
    {.name = METHOD_REDUCE_INIT_POS,
     .parameters = (const tx_parameter_type_e[]) {PARAM_PUBKEY, PARAM_ADDR, PARAM_AMOUNT, PARAM_END}},
    {.name = METHOD_CHANGE_MAX_AUTH,
     .parameters = (const tx_parameter_type_e[]) {PARAM_PUBKEY, PARAM_ADDR, PARAM_AMOUNT, PARAM_END}},
    {.name = METHOD_SET_FEE_PERCENTAGE,
     .parameters = (const tx_parameter_type_e[]) {PARAM_PUBKEY, PARAM_ADDR, PARAM_AMOUNT, PARAM_AMOUNT, PARAM_END}},
    {.name = METHOD_AUTHORIZE_FOR_PEER,
     .parameters = (const tx_parameter_type_e[]) {PARAM_ADDR, PARAM_PK_AMOUNT_PAIRS, PARAM_END}},
    {.name = METHOD_UNAUTHORIZE_FOR_PEER,
     .parameters = (const tx_parameter_type_e[]) {PARAM_ADDR, PARAM_PK_AMOUNT_PAIRS, PARAM_END}},
    {.name = METHOD_WITHDRAW,
     .parameters = (const tx_parameter_type_e[]) {PARAM_ADDR, PARAM_PK_AMOUNT_PAIRS, PARAM_END}},
    {.name = METHOD_WITHDRAW_FEE,
     .parameters = (const tx_parameter_type_e[]) {PARAM_ADDR, PARAM_END}},
    {.name = NULL}
};

// For native tokens, ONG's decimals are 9, while ONT's decimals are 0. Later, three new methods
// were added: transferV2, transferFromV2, and approveV2. The decimals for these new methods are
// increased by 9 based on the original value.
static const payload_t txPayload[] = {
    {.contract_addr = ONT_ADDR, .token_decimals = 0, .methods = native_token_methods},

    {.contract_addr = ONG_ADDR, .token_decimals = 9, .methods = native_token_methods},

    {.contract_addr = GOV_ADDR, .methods = native_governance_methods},

    {.contract_addr = WING_ADDR, .methods = neovm_oep4_token_methods}

    // #ifdef DEBUG
    ,
    {.contract_addr = WTK_ADDR, .methods = wasmvm_oep4_token_methods},
    {.contract_addr = MYT_ADDR, .token_decimals = 18, .methods = neovm_oep4_token_methods}
    // #endif
};
