#include <string.h>
#include "contract.h"

void get_native_token_methods(tx_method_signature_t *methods, size_t *count) {
    static const tx_parameter_type_e transfer_params[] = {PARAM_TRANSFER_STATE_LIST, PARAM_END};
    static const tx_parameter_type_e transfer_from_params[] = {PARAM_ADDR,
                                                               PARAM_TRANSFER_STATE,
                                                               PARAM_END};
    static const tx_parameter_type_e approve_params[] = {PARAM_ADDR,
                                                         PARAM_ADDR,
                                                         PARAM_AMOUNT,
                                                         PARAM_END};

    methods[0].name = METHOD_TRANSFER;
    methods[0].parameters = transfer_params;
    methods[1].name = METHOD_TRANSFER_FROM;
    methods[1].parameters = transfer_from_params;
    methods[2].name = METHOD_APPROVE;
    methods[2].parameters = approve_params;
    methods[3].name = METHOD_TRANSFER_V2;
    methods[3].parameters = transfer_params;
    methods[4].name = METHOD_TRANSFER_FROM_V2;
    methods[4].parameters = transfer_from_params;
    methods[5].name = METHOD_APPROVE_V2;
    methods[5].parameters = approve_params;
    methods[6].name = NULL;
    *count = 7;
}

void get_neovm_oep4_token_methods(tx_method_signature_t *methods, size_t *count) {
    static const tx_parameter_type_e transfer_params[] = {PARAM_AMOUNT,
                                                          PARAM_ADDR,
                                                          PARAM_ADDR,
                                                          PARAM_END};
    static const tx_parameter_type_e transfer_from_params[] = {PARAM_AMOUNT,
                                                               PARAM_ADDR,
                                                               PARAM_ADDR,
                                                               PARAM_ADDR,
                                                               PARAM_END};
    static const tx_parameter_type_e approve_params[] = {PARAM_AMOUNT,
                                                         PARAM_ADDR,
                                                         PARAM_ADDR,
                                                         PARAM_END};

    methods[0].name = METHOD_TRANSFER;
    methods[0].parameters = transfer_params;
    methods[1].name = METHOD_TRANSFER_FROM;
    methods[1].parameters = transfer_from_params;
    methods[2].name = METHOD_APPROVE;
    methods[2].parameters = approve_params;
    methods[3].name = NULL;
    *count = 4;
}

void get_wasmvm_oep4_token_methods(tx_method_signature_t *methods, size_t *count) {
    static const tx_parameter_type_e transfer_params[] = {PARAM_ADDR,
                                                          PARAM_ADDR,
                                                          PARAM_UINT128,
                                                          PARAM_END};
    static const tx_parameter_type_e transfer_from_params[] = {PARAM_ADDR,
                                                               PARAM_ADDR,
                                                               PARAM_ADDR,
                                                               PARAM_UINT128,
                                                               PARAM_END};
    static const tx_parameter_type_e approve_params[] = {PARAM_ADDR,
                                                         PARAM_ADDR,
                                                         PARAM_UINT128,
                                                         PARAM_END};

    methods[0].name = METHOD_TRANSFER;
    methods[0].parameters = transfer_params;
    methods[1].name = METHOD_TRANSFER_FROM;
    methods[1].parameters = transfer_from_params;
    methods[2].name = METHOD_APPROVE;
    methods[2].parameters = approve_params;
    methods[3].name = NULL;
    *count = 4;
}

void get_native_governance_methods(tx_method_signature_t *methods, size_t *count) {
    static const tx_parameter_type_e register_params[] =
        {PARAM_PUBKEY, PARAM_ADDR, PARAM_AMOUNT, PARAM_ONTID, PARAM_AMOUNT, PARAM_END};
    static const tx_parameter_type_e quit_params[] = {PARAM_PUBKEY, PARAM_ADDR, PARAM_END};
    static const tx_parameter_type_e add_init_params[] = {PARAM_PUBKEY,
                                                          PARAM_ADDR,
                                                          PARAM_AMOUNT,
                                                          PARAM_END};
    static const tx_parameter_type_e reduce_init_params[] = {PARAM_PUBKEY,
                                                             PARAM_ADDR,
                                                             PARAM_AMOUNT,
                                                             PARAM_END};
    static const tx_parameter_type_e change_max_params[] = {PARAM_PUBKEY,
                                                            PARAM_ADDR,
                                                            PARAM_AMOUNT,
                                                            PARAM_END};
    static const tx_parameter_type_e set_fee_params[] = {PARAM_PUBKEY,
                                                         PARAM_ADDR,
                                                         PARAM_AMOUNT,
                                                         PARAM_AMOUNT,
                                                         PARAM_END};
    static const tx_parameter_type_e auth_params[] = {PARAM_ADDR, PARAM_PK_AMOUNT_PAIRS, PARAM_END};
    static const tx_parameter_type_e withdraw_params[] = {PARAM_ADDR,
                                                          PARAM_PK_AMOUNT_PAIRS,
                                                          PARAM_END};
    static const tx_parameter_type_e withdraw_fee_params[] = {PARAM_ADDR, PARAM_END};

    methods[0].name = METHOD_REGISTER_CANDIDATE;
    methods[0].parameters = register_params;
    methods[1].name = METHOD_QUIT_NODE;
    methods[1].parameters = quit_params;
    methods[2].name = METHOD_ADD_INIT_POS;
    methods[2].parameters = add_init_params;
    methods[3].name = METHOD_REDUCE_INIT_POS;
    methods[3].parameters = reduce_init_params;
    methods[4].name = METHOD_CHANGE_MAX_AUTH;
    methods[4].parameters = change_max_params;
    methods[5].name = METHOD_SET_FEE_PERCENTAGE;
    methods[5].parameters = set_fee_params;
    methods[6].name = METHOD_AUTHORIZE_FOR_PEER;
    methods[6].parameters = auth_params;
    methods[7].name = METHOD_UNAUTHORIZE_FOR_PEER;
    methods[7].parameters = auth_params;
    methods[8].name = METHOD_WITHDRAW;
    methods[8].parameters = withdraw_params;
    methods[9].name = METHOD_WITHDRAW_FEE;
    methods[9].parameters = withdraw_fee_params;
    methods[10].name = NULL;
    *count = 11;
}

void get_tx_payload(payload_t *payload, size_t *count, payload_storage_t *storage) {
    size_t method_count;

    get_ont_addr(storage[0].contract_addr);
    payload[0].contract_addr = storage[0].contract_addr;
    payload[0].token_decimals = 0;
    payload[0].methods = storage[0].methods;
    get_native_token_methods((tx_method_signature_t *) payload[0].methods, &method_count);

    get_ong_addr(storage[1].contract_addr);
    payload[1].contract_addr = storage[1].contract_addr;
    payload[1].token_decimals = 9;
    payload[1].methods = storage[1].methods;
    get_native_token_methods((tx_method_signature_t *) payload[1].methods, &method_count);

    get_gov_addr(storage[2].contract_addr);
    payload[2].contract_addr = storage[2].contract_addr;
    payload[2].token_decimals = 0;
    payload[2].methods = storage[2].methods;
    get_native_governance_methods((tx_method_signature_t *) payload[2].methods, &method_count);

    get_wing_addr(storage[3].contract_addr);
    payload[3].contract_addr = storage[3].contract_addr;
    payload[3].token_decimals = 9;
    payload[3].methods = storage[3].methods;
    get_neovm_oep4_token_methods((tx_method_signature_t *) payload[3].methods, &method_count);

    get_wtk_addr(storage[4].contract_addr);
    payload[4].contract_addr = storage[4].contract_addr;
    payload[4].token_decimals = 9;
    payload[4].methods = storage[4].methods;
    get_wasmvm_oep4_token_methods((tx_method_signature_t *) payload[4].methods, &method_count);

    get_myt_addr(storage[5].contract_addr);
    payload[5].contract_addr = storage[5].contract_addr;
    payload[5].token_decimals = 18;
    payload[5].methods = storage[5].methods;
    get_neovm_oep4_token_methods((tx_method_signature_t *) payload[5].methods, &method_count);
    *count = 6;
}