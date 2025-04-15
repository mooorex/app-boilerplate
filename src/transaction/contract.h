#pragma once

#include "tx_types.h"

#define ADDRESS_LEN 20

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

typedef struct {
    uint8_t contract_addr[ADDRESS_LEN];
    uint8_t token_decimals;
    tx_method_signature_t methods[11];
} payload_storage_t;

static inline void get_ont_addr(uint8_t *addr) {
    const uint8_t ont[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    memcpy(addr, ont, ADDRESS_LEN);
}

static inline void get_ong_addr(uint8_t *addr) {
    const uint8_t ong[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
    memcpy(addr, ong, ADDRESS_LEN);
}

static inline void get_gov_addr(uint8_t *addr) {
    const uint8_t gov[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07};
    memcpy(addr, gov, ADDRESS_LEN);
}

static inline void get_wing_addr(uint8_t *addr) {
    const uint8_t wing[] = {0x80, 0xef, 0x58, 0x6e, 0xf5, 0xff, 0xf2, 0xb1, 0xea, 0x83,
                            0x78, 0x39, 0xd6, 0x62, 0xa5, 0x27, 0xcd, 0x9f, 0xc5, 0x00};
    memcpy(addr, wing, ADDRESS_LEN);
}

static inline void get_wtk_addr(uint8_t *addr) {
    const uint8_t wtk[] = {0x77, 0xF1, 0xFF, 0xE3, 0xAD, 0xA5, 0xDD, 0x78, 0x62, 0xF9,
                           0x60, 0x1F, 0x5A, 0x0A, 0x05, 0x8A, 0x6B, 0xD8, 0x27, 0x43};
    memcpy(addr, wtk, ADDRESS_LEN);
}

static inline void get_myt_addr(uint8_t *addr) {
    const uint8_t myt[] = {0xff, 0x92, 0xa1, 0xa3, 0x41, 0x8d, 0x53, 0x68, 0x40, 0x05,
                           0xaf, 0x98, 0xd5, 0xf1, 0xad, 0xd0, 0x5f, 0x15, 0xed, 0x19};
    memcpy(addr, myt, ADDRESS_LEN);
}

void get_native_token_methods(tx_method_signature_t *methods, size_t *count);
void get_neovm_oep4_token_methods(tx_method_signature_t *methods, size_t *count);
void get_wasmvm_oep4_token_methods(tx_method_signature_t *methods, size_t *count);
void get_native_governance_methods(tx_method_signature_t *methods, size_t *count);
void get_tx_payload(payload_t *payload, size_t *count, payload_storage_t *storage);