/*******************************************************************************
 *   Ontology Ledger App
 *   (c) 2025 OGD
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
 ********************************************************************************/

#include <string.h>
#include "contract.h"
#include "../ui/types.h"

void get_native_token_methods(tx_method_signature_t *methods) {
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
}

void get_neovm_oep4_token_methods(tx_method_signature_t *methods) {
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
}

void get_wasmvm_oep4_token_methods(tx_method_signature_t *methods) {
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
}

void get_native_governance_methods(tx_method_signature_t *methods) {
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
}

void get_tx_payload(payload_t *storage) {
    memcpy(storage[0].contract_addr, ONT_ADDR, ADDRESS_LEN);
    storage[0].token_decimals = ONT_DECIMALS;
    storage[0].ticker = ONT_TICKER;
    get_native_token_methods((tx_method_signature_t *) storage[0].methods);

    memcpy(storage[1].contract_addr, ONG_ADDR, ADDRESS_LEN);
    storage[1].token_decimals = ONG_DECIMALS;
    storage[1].ticker = ONG_TICKER;  //it's the gas token
    get_native_token_methods((tx_method_signature_t *) storage[1].methods);

    memcpy(storage[2].contract_addr, GOV_ADDR, ADDRESS_LEN);
    //not the token decimals, it's the one of the token operated by the contract
    storage[2].token_decimals = ONT_DECIMALS;
    //not the token ticker, it's the one of the token operated by the contract
    storage[2].ticker = ONT_TICKER;
    get_native_governance_methods((tx_method_signature_t *) storage[2].methods);

    memcpy(storage[3].contract_addr, WING_ADDR, ADDRESS_LEN);
    storage[3].token_decimals = 9;
    storage[3].ticker = "WING";
    get_neovm_oep4_token_methods((tx_method_signature_t *) storage[3].methods);

// #ifdef DEBUG
    memcpy(storage[4].contract_addr, WTK_ADDR, ADDRESS_LEN);
    storage[4].token_decimals = 9;
    storage[4].ticker = "";
    get_wasmvm_oep4_token_methods((tx_method_signature_t *) storage[4].methods);

    memcpy(storage[5].contract_addr, MYT_ADDR, ADDRESS_LEN);
    storage[5].token_decimals = 18;
    storage[5].ticker = "";
    get_neovm_oep4_token_methods((tx_method_signature_t *) storage[5].methods);
// #endif
}







