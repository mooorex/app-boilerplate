#pragma once

#include "tx_types.h"

#define ADDRESS_LEN 20
#define MAX_METHOD_NUM 11
#define PREDEFINED_CONTRACT_NUM 6


#define ONG_TICKER "ONG"    //native, gas token
#define ONT_TICKER "ONT"    //native, staking token
#define ONG_DECIMALS 9      // 18 for transferV2, transferFromV2, approveV2
#define ONT_DECIMALS 0      // 9 for transferV2, transferFromV2, approveV2
#define TOKEN_AMOUNT 1000000000000000000ULL  // the amount of ONT, also the max amount of ONG


#define ONT_ADDR ("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")
#define ONG_ADDR ("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02")
#define GOV_ADDR ("\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07")
#define WING_ADDR ("\x80\xef\x58\x6e\xf5\xff\xf2\xb1\xea\x83\x78\x39\xd6\x62\xa5\x27\xcd\x9f\xc5\x00")
#define WTK_ADDR ("\x77\xF1\xFF\xE3\xAD\xA5\xDD\x78\x62\xF9\x60\x1F\x5A\x0A\x05\x8A\x6B\xD8\x27\x43")
#define MYT_ADDR ("\xff\x92\xa1\xa3\x41\x8d\x53\x68\x40\x05\xaf\x98\xd5\xf1\xad\xd0\x5f\x15\xed\x19")

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
    uint8_t token_decimals;
    const char *ticker;
    uint8_t contract_addr[ADDRESS_LEN];
    tx_method_signature_t methods[MAX_METHOD_NUM];
} payload_t;


//Add the predefined contracts and their methods in this function
//Don't forget to modify the PREDEFINED_CONTRACT_NUM if you add a new contract
void get_tx_payload(payload_t *storage);