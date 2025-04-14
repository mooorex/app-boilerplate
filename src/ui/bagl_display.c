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

#ifdef HAVE_BAGL

#include <stdbool.h>
#include <string.h>

#include "os.h"
#include "ux.h"
#include "glyphs.h"
#include "io.h"
#include "bip32.h"
#include "format.h"

#include "display.h"
#include "constants.h"
#include "../globals.h"
#include "../sw.h"
#include "action/validate.h"
#include "../transaction/tx_types.h"
#include "../menu.h"
#include "../transaction/utils.h"
#include "../transaction/contract.h"
#include "types.h"

#define MAX_BUFFER_LEN 40
#define NUM_BUFFERS    4  // amount, address, from, to, extra
#define MAX_CONFIGS    5  // Max number of param_config_t entries per method
#define MAX_PARAMETERS 5
#define MAX_NUM_STEPS  10

typedef enum {
    BUFFER_AMOUNT = 0,
    BUFFER_ADDRESS,
    BUFFER_FROM,
    BUFFER_TO,
    BUFFER_EXTRA  // For node_amount, decimals, etc.
} buffer_index_e;

static char g_buffers[NUM_BUFFERS][MAX_BUFFER_LEN];
static char g_content[68];
static action_validate_cb g_validate_callback;
static const ux_flow_step_t *ux_display_tx_flow[MAX_NUM_STEPS];

// Configuration for parameter parsing
typedef struct {
    const char *tag;
    tx_parameter_type_e type;
    uint8_t param_idx;
    buffer_index_e buffer_idx;  // Used only for buffer-based params
    bool use_content;           // Flag to indicate g_content usage
    const ux_flow_step_t *step;
} param_config_t;

// Method display structure
typedef struct {
    const char *method_name;
    const char *title;
    const char *content;
    void (*param_handler)(transaction_t *tx,
                          uint8_t *step_index,
                          param_config_t *configs,
                          uint8_t config_count);
    param_config_t *configs;
    uint8_t config_count;
} method_display_t;

// UX Steps
UX_STEP_NOCB(ux_display_confirm_addr_step, pn, {&C_icon_eye, "Confirm Address"});
UX_STEP_NOCB(ux_display_review_step, pnn, {&C_icon_eye, "Review", "Transaction"});
UX_STEP_NOCB(ux_display_amount_step,
             bnnn_paging,
             {.title = AMOUNT, .text = g_buffers[BUFFER_AMOUNT]});
UX_STEP_NOCB(ux_display_address_step,
             bnnn_paging,
             {.title = ADDRESS, .text = g_buffers[BUFFER_ADDRESS]});
UX_STEP_NOCB(ux_display_from_step, bnnn_paging, {.title = FROM, .text = g_buffers[BUFFER_FROM]});
UX_STEP_NOCB(ux_display_to_step, bnnn_paging, {.title = TO, .text = g_buffers[BUFFER_TO]});
UX_STEP_NOCB(ux_display_sender_step,
             bnnn_paging,
             {.title = SENDER, .text = g_buffers[BUFFER_ADDRESS]});
UX_STEP_NOCB(ux_display_peer_pubkey_step, bnnn_paging, {.title = PEER_PUBKEY, .text = g_content});
UX_STEP_NOCB(ux_display_signer_step,
             bnnn_paging,
             {.title = SIGNER, .text = G_context.display_data.signer});
UX_STEP_NOCB(ux_display_fee_step,
             bnnn_paging,
             {.title = FEE_ONG, .text = G_context.display_data.gas_fee});
UX_STEP_NOCB(ux_display_gas_fee_step,
             bnnn_paging,
             {.title = GAS_FEE, .text = G_context.display_data.gas_fee});
UX_STEP_NOCB(ux_display_stake_fee_step, bnnn_paging, {.title = STAKE_FEE, .text = STAKE_FEE_ONG});
UX_STEP_NOCB(ux_display_node_amount_step,
             bnnn_paging,
             {.title = NODE_AMOUNT, .text = g_buffers[BUFFER_AMOUNT]});
UX_STEP_NOCB(ux_display_max_authorize_step,
             bnnn_paging,
             {.title = MAX_AUTHORIZE, .text = g_buffers[BUFFER_AMOUNT]});
UX_STEP_NOCB(ux_display_peer_cost_step,
             bnnn_paging,
             {.title = PEER_COST, .text = g_buffers[BUFFER_AMOUNT]});
UX_STEP_NOCB(ux_display_stake_cost_step,
             bnnn_paging,
             {.title = STAKE_COST, .text = g_buffers[BUFFER_AMOUNT]});
UX_STEP_NOCB(ux_display_pos_step, bnnn_paging, {.title = POS, .text = g_buffers[BUFFER_AMOUNT]});
UX_STEP_NOCB(ux_display_withdraw_step,
             bnnn_paging,
             {.title = TOTAL_WITHDRAW, .text = G_context.display_data.amount});
UX_STEP_NOCB(ux_display_decimals_step,
             bnnn_paging,
             {.title = DECIMALS, .text = g_buffers[BUFFER_EXTRA]});
UX_STEP_NOCB(ux_display_personal_msg_step, bnnn_paging, {.title = MSG, .text = g_content});
UX_STEP_NOCB(ux_display_blind_signing_step,
             bnnn_paging,
             {.title = BLIND_SIGNING, .text = g_content});
UX_STEP_CB(ux_display_approve_step,
           pb,
           (*g_validate_callback)(true),
           {&C_icon_validate_14, "Approve"});
UX_STEP_CB(ux_display_reject_step,
           pb,
           (*g_validate_callback)(false),
           {&C_icon_crossmark, "Reject"});
UX_STEP_CB(ux_display_tx_approve_step,
           pb,
           validate_transaction(true),
           {&C_icon_validate_14, "Approve"});
UX_STEP_CB(ux_display_tx_reject_step,
           pb,
           validate_transaction(false),
           {&C_icon_crossmark, "Reject"});

// Validation callbacks
static void ui_action_validate_pubkey(bool choice) {
    validate_pubkey(choice);
    ui_menu_main();
}

static void ui_action_validate_transaction(bool choice) {
    validate_transaction(choice);
}

static void ui_action_validate_personal_msg(bool choice) {
    validate_personal_msg(choice);
    ui_menu_main();
}

// Utility functions
static void clear_buffers(void) {
    for (uint8_t i = 0; i < NUM_BUFFERS; i++) {
        explicit_bzero(g_buffers[i], MAX_BUFFER_LEN);
    }
    explicit_bzero(g_content, sizeof(g_content));
}

static void parse_param_to_buffer(transaction_t *tx,
                                  tx_parameter_type_e type,
                                  uint8_t param_idx,
                                  char *buffer,
                                  size_t buffer_len) {
    if (tx == NULL || buffer == NULL) {
        PRINTF("Error: Null pointer in parse_param_to_buffer\n");
        return;
    }
    if (param_idx >= MAX_PARAMETERS) {
        PRINTF("Error: param_idx %u out of bounds\n", param_idx);
        return;
    }

    tx_parameter_t *param = &tx->method.parameters[param_idx];
    if (param->data == NULL) {
        PRINTF("Error: param->data is NULL for idx %u\n", param_idx);
        return;
    }

    explicit_bzero(buffer, buffer_len);
    switch (type) {
        case PARAM_ADDR:
            script_hash_to_address(buffer, buffer_len, param->data);
            break;
        case PARAM_UINT128:
        case PARAM_AMOUNT: {
            uint8_t ont_addr[ADDRESS_LEN], ong_addr[ADDRESS_LEN], gov_addr[ADDRESS_LEN];
            get_ont_addr(ont_addr);
            get_ong_addr(ong_addr);
            get_gov_addr(gov_addr);
            get_token_value(param->len,
                            param->data,
                            tx->contract.token_decimals,
                            tx->contract.type,
                            buffer,
                            buffer_len);
            if (memcmp(tx->contract.addr.data, ont_addr, ADDRESS_LEN) == 0)
                strlcat(buffer, ONT_VIEW, buffer_len);
            else if (memcmp(tx->contract.addr.data, ong_addr, ADDRESS_LEN) == 0)
                strlcat(buffer, ONG_VIEW, buffer_len);
            else if (memcmp(tx->contract.addr.data, gov_addr, ADDRESS_LEN) == 0) {
                if (tx->method.name.len == strlen(METHOD_SET_FEE_PERCENTAGE) &&
                    memcmp(tx->method.name.data, METHOD_SET_FEE_PERCENTAGE, tx->method.name.len) ==
                        0) {
                    strlcat(buffer, PERCENTAGE, buffer_len);
                } else {
                    strlcat(buffer, ONT_VIEW, buffer_len);
                }
            }
            break;
        }
        case PARAM_PUBKEY:
            if (param->len <= buffer_len) {
                memcpy(buffer, param->data, param->len);
                buffer[param->len] = '\0';
            } else {
                PRINTF("Error: PUBKEY length %u exceeds buffer_len %u\n", param->len, buffer_len);
            }
            break;
        default:
            PRINTF("Warning: Unknown param type %d\n", type);
            break;
    }
}

static void add_step(uint8_t *index, const ux_flow_step_t *step) {
    if (*index < MAX_NUM_STEPS && step != NULL) {
        ux_display_tx_flow[(*index)++] = step;
    }
}

static void handle_params(transaction_t *tx,
                          uint8_t *step_index,
                          param_config_t *configs,
                          uint8_t config_count) {
    param_config_t local_configs[MAX_CONFIGS];
    memcpy(local_configs, configs, config_count * sizeof(param_config_t));

    if (memcmp(tx->method.name.data, METHOD_TRANSFER, strlen(METHOD_TRANSFER)) == 0 ||
        memcmp(tx->method.name.data, METHOD_TRANSFER_V2, strlen(METHOD_TRANSFER_V2)) == 0 ||
        memcmp(tx->method.name.data, METHOD_APPROVE, strlen(METHOD_APPROVE)) == 0 ||
        memcmp(tx->method.name.data, METHOD_APPROVE_V2, strlen(METHOD_APPROVE_V2)) == 0) {
        switch (tx->contract.type) {
            case NATIVE_CONTRACT:
            case WASMVM_CONTRACT: {
                local_configs[0].param_idx = 2;  // AMOUNT
                local_configs[1].param_idx = 0;  // FROM
                local_configs[2].param_idx = 1;  // TO
                break;
            }
            case NEOVM_CONTRACT:
                local_configs[0].param_idx = 0;  // AMOUNT
                local_configs[1].param_idx = 1;  // FROM
                local_configs[2].param_idx = 2;  // TO
                break;
            default:
                PRINTF("Error: Unknown contract type %d\n", tx->contract.type);
                return;  // Or set default indices, e.g., NATIVE_CONTRACT
        }
    } else if (memcmp(tx->method.name.data,METHOD_TRANSFER_FROM,strlen(METHOD_TRANSFER_FROM)) == 0 ||
               memcmp(tx->method.name.data,METHOD_TRANSFER_FROM_V2,strlen(METHOD_TRANSFER_FROM_V2)) == 0) {
        switch (tx->contract.type) {
            case NATIVE_CONTRACT:
            case WASMVM_CONTRACT:{
                local_configs[0].param_idx = 3;  // AMOUNT
                local_configs[1].param_idx = 0;  // SENDER
                local_configs[2].param_idx = 1;  // FROM
                local_configs[3].param_idx = 2;  // TO
                break;
            }
            case NEOVM_CONTRACT:
                local_configs[0].param_idx = 0;  // AMOUNT
                local_configs[1].param_idx = 1;  // SENDER
                local_configs[2].param_idx = 2;  // FROM
                local_configs[3].param_idx = 3;  // TO
                break; 
            default:
                PRINTF("Error: Unknown contract type %d\n", tx->contract.type);
                return;
        }
    }
    // Parse parameters and add steps
    for (uint8_t i = 0; i < config_count; i++) {
        if (local_configs[i].use_content) {
            parse_param_to_buffer(tx,
                                  local_configs[i].type,
                                  local_configs[i].param_idx,
                                  g_content,
                                  sizeof(g_content));
        } else {
            parse_param_to_buffer(tx,
                                  local_configs[i].type,
                                  local_configs[i].param_idx,
                                  g_buffers[local_configs[i].buffer_idx],
                                  MAX_BUFFER_LEN);
        }
        add_step(step_index, local_configs[i].step);
    }

    // Handle special cases
    if (memcmp(tx->method.name.data,METHOD_REGISTER_CANDIDATE,strlen(METHOD_REGISTER_CANDIDATE)) == 0) {
        add_step(step_index, &ux_display_stake_fee_step);
    } else if (memcmp(tx->method.name.data,METHOD_AUTHORIZE_FOR_PEER,strlen(METHOD_AUTHORIZE_FOR_PEER)) == 0 ||
               memcmp(tx->method.name.data,METHOD_UNAUTHORIZE_FOR_PEER,strlen(METHOD_UNAUTHORIZE_FOR_PEER)) == 0 ||
               memcmp(tx->method.name.data,METHOD_WITHDRAW,strlen(METHOD_WITHDRAW)) == 0) {  

        uint8_t pubkey_num =
            get_data_value(tx->method.parameters[1].data, tx->method.parameters[1].len);
        if (pubkey_num >= 1) {
            format_u64(g_buffers[BUFFER_AMOUNT], MAX_BUFFER_LEN, pubkey_num);
            add_step(step_index, &ux_display_node_amount_step);
        }
        memcpy(g_content,tx->method.parameters[2].data, tx->method.parameters[2].len);
        add_step(step_index, &ux_display_peer_pubkey_step);
        if (memcmp(tx->method.name.data,METHOD_WITHDRAW,strlen(METHOD_WITHDRAW)) == 0) { 
            strlcat(G_context.display_data.amount, ONT_VIEW, sizeof(G_context.display_data.amount));
            add_step(step_index, &ux_display_withdraw_step);
        }
    }
}

static const method_display_t *get_method_display(const transaction_t *tx) {
    static method_display_t method;
    static param_config_t configs[MAX_CONFIGS];

    if (tx == NULL) {
        PRINTF("Error: tx is NULL\n");
        explicit_bzero(&method, sizeof(method));
        return NULL;
    }

    const uint8_t *method_data = tx->method.name.data;
    size_t method_len = tx->method.name.len;

    if (method_data == NULL || method_len == 0) {
        PRINTF("Error: method_data is NULL or len=0\n");
        explicit_bzero(&method, sizeof(method));
        return NULL;
    }

    if (method_len == strlen(METHOD_TRANSFER) &&
        memcmp(method_data, METHOD_TRANSFER, method_len) == 0) {
        method.method_name = METHOD_TRANSFER;
        method.title = TRANSFER_TITLE;
        ;
        method.content = TRANSFER_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {AMOUNT,
                                       PARAM_AMOUNT,
                                       2,
                                       BUFFER_AMOUNT,
                                       false,
                                       &ux_display_amount_step};
        configs[1] =
            (param_config_t) {FROM, PARAM_ADDR, 0, BUFFER_FROM, false, &ux_display_from_step};
        configs[2] = (param_config_t) {TO, PARAM_ADDR, 1, BUFFER_TO, false, &ux_display_to_step};
        method.configs = configs;
        method.config_count = 3;
    } else if (method_len == strlen(METHOD_TRANSFER_V2) &&
               memcmp(method_data, METHOD_TRANSFER_V2, method_len) == 0) {
        method.method_name = METHOD_TRANSFER_V2;
        method.title = TRANSFER_TITLE;
        method.content = TRANSFER_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {AMOUNT,
                                       PARAM_AMOUNT,
                                       2,
                                       BUFFER_AMOUNT,
                                       false,
                                       &ux_display_amount_step};
        configs[1] =
            (param_config_t) {FROM, PARAM_ADDR, 0, BUFFER_FROM, false, &ux_display_from_step};
        configs[2] = (param_config_t) {TO, PARAM_ADDR, 1, BUFFER_TO, false, &ux_display_to_step};
        method.configs = configs;
        method.config_count = 3;
    } else if (method_len == strlen(METHOD_TRANSFER_FROM) &&
               memcmp(method_data, METHOD_TRANSFER_FROM, method_len) == 0) {
        method.method_name = METHOD_TRANSFER_FROM;
        method.title = TRANSFER_FROM_TITLE;
        method.content = TRANSFER_FROM_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {AMOUNT,
                                       PARAM_AMOUNT,
                                       3,
                                       BUFFER_AMOUNT,
                                       false,
                                       &ux_display_amount_step};
        configs[1] = (param_config_t) {SENDER,
                                       PARAM_ADDR,
                                       0,
                                       BUFFER_ADDRESS,
                                       false,
                                       &ux_display_sender_step};
        configs[2] =
            (param_config_t) {FROM, PARAM_ADDR, 1, BUFFER_FROM, false, &ux_display_from_step};
        configs[3] = (param_config_t) {TO, PARAM_ADDR, 2, BUFFER_TO, false, &ux_display_to_step};
        method.configs = configs;
        method.config_count = 4;
    } else if (method_len == strlen(METHOD_TRANSFER_FROM_V2) &&
               memcmp(method_data, METHOD_TRANSFER_FROM_V2, method_len) == 0) {
        method.method_name = METHOD_TRANSFER_FROM_V2;
        method.title = TRANSFER_FROM_TITLE;
        method.content = TRANSFER_FROM_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {AMOUNT,
                                       PARAM_AMOUNT,
                                       3,
                                       BUFFER_AMOUNT,
                                       false,
                                       &ux_display_amount_step};
        configs[1] = (param_config_t) {SENDER,
                                       PARAM_ADDR,
                                       0,
                                       BUFFER_ADDRESS,
                                       false,
                                       &ux_display_sender_step};
        configs[2] =
            (param_config_t) {FROM, PARAM_ADDR, 1, BUFFER_FROM, false, &ux_display_from_step};
        configs[3] = (param_config_t) {TO, PARAM_ADDR, 2, BUFFER_TO, false, &ux_display_to_step};
        method.configs = configs;
        method.config_count = 4;
    } else if (method_len == strlen(METHOD_APPROVE) &&
               memcmp(method_data, METHOD_APPROVE, method_len) == 0) {
        method.method_name = METHOD_APPROVE;
        method.title = APPROVE_TITLE;
        method.content = APPROVE_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {AMOUNT,
                                       PARAM_AMOUNT,
                                       2,
                                       BUFFER_AMOUNT,
                                       false,
                                       &ux_display_amount_step};
        configs[1] =
            (param_config_t) {FROM, PARAM_ADDR, 0, BUFFER_FROM, false, &ux_display_from_step};
        configs[2] = (param_config_t) {TO, PARAM_ADDR, 1, BUFFER_TO, false, &ux_display_to_step};
        method.configs = configs;
        method.config_count = 3;
    } else if (method_len == strlen(METHOD_APPROVE_V2) &&
               memcmp(method_data, METHOD_APPROVE_V2, method_len) == 0) {
        method.method_name = METHOD_APPROVE_V2;
        method.title = APPROVE_TITLE;
        method.content = APPROVE_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {AMOUNT,
                                       PARAM_AMOUNT,
                                       2,
                                       BUFFER_AMOUNT,
                                       false,
                                       &ux_display_amount_step};
        configs[1] =
            (param_config_t) {FROM, PARAM_ADDR, 0, BUFFER_FROM, false, &ux_display_from_step};
        configs[2] = (param_config_t) {TO, PARAM_ADDR, 1, BUFFER_TO, false, &ux_display_to_step};
        method.configs = configs;
        method.config_count = 3;
    } else if (method_len == strlen(METHOD_REGISTER_CANDIDATE) &&
               memcmp(method_data, METHOD_REGISTER_CANDIDATE, method_len) == 0) {
        method.method_name = METHOD_REGISTER_CANDIDATE;
        method.title = REGISTER_CANDIDATE_TITLE;
        method.content = REGISTER_CANDIDATE_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {ADDRESS,
                                       PARAM_ADDR,
                                       1,
                                       BUFFER_ADDRESS,
                                       false,
                                       &ux_display_address_step};
        configs[1] =
            (param_config_t) {PEER_PUBKEY, PARAM_PUBKEY, 0, 0, true, &ux_display_peer_pubkey_step};
        method.configs = configs;
        method.config_count = 2;
    } else if (method_len == strlen(METHOD_QUIT_NODE) &&
               memcmp(method_data, METHOD_QUIT_NODE, method_len) == 0) {
        method.method_name = METHOD_QUIT_NODE;
        method.title = QUIT_NODE_TITLE;
        method.content = QUIT_NODE_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {ADDRESS,
                                       PARAM_ADDR,
                                       1,
                                       BUFFER_ADDRESS,
                                       false,
                                       &ux_display_address_step};
        configs[1] =
            (param_config_t) {PEER_PUBKEY, PARAM_PUBKEY, 0, 0, true, &ux_display_peer_pubkey_step};

        method.configs = configs;
        method.config_count = 2;
    } else if (method_len == strlen(METHOD_ADD_INIT_POS) &&
               memcmp(method_data, METHOD_ADD_INIT_POS, method_len) == 0) {
        method.method_name = METHOD_ADD_INIT_POS;
        method.title = ADD_INIT_POS_TITLE;
        method.content = ADD_INIT_POS_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {ADDRESS,
                                       PARAM_ADDR,
                                       1,
                                       BUFFER_ADDRESS,
                                       false,
                                       &ux_display_address_step};
        configs[1] =
            (param_config_t) {PEER_PUBKEY, PARAM_PUBKEY, 0, 0, true, &ux_display_peer_pubkey_step};
        configs[2] =
            (param_config_t) {POS, PARAM_AMOUNT, 2, BUFFER_AMOUNT, false, &ux_display_pos_step};
        method.configs = configs;
        method.config_count = 3;
    } else if (method_len == strlen(METHOD_REDUCE_INIT_POS) &&
               memcmp(method_data, METHOD_REDUCE_INIT_POS, method_len) == 0) {
        method.method_name = METHOD_REDUCE_INIT_POS;
        method.title = REDUCE_INIT_POS_TITLE;
        method.content = REDUCE_INIT_POS_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {ADDRESS,
                                       PARAM_ADDR,
                                       1,
                                       BUFFER_ADDRESS,
                                       false,
                                       &ux_display_address_step};
        configs[1] =
            (param_config_t) {PEER_PUBKEY, PARAM_PUBKEY, 0, 0, true, &ux_display_peer_pubkey_step};
        configs[2] = (param_config_t) {AMOUNT,
                                       PARAM_AMOUNT,
                                       2,
                                       BUFFER_AMOUNT,
                                       false,
                                       &ux_display_amount_step};
        method.configs = configs;
        method.config_count = 3;
    } else if (method_len == strlen(METHOD_CHANGE_MAX_AUTH) &&
               memcmp(method_data, METHOD_CHANGE_MAX_AUTH, method_len) == 0) {
        method.method_name = METHOD_CHANGE_MAX_AUTH;
        method.title = CHANGE_MAX_AUTHORIZATION_TITLE;
        method.content = CHANGE_MAX_AUTHORIZATION_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {ADDRESS,
                                       PARAM_ADDR,
                                       1,
                                       BUFFER_ADDRESS,
                                       false,
                                       &ux_display_address_step};
        configs[1] =
            (param_config_t) {PEER_PUBKEY, PARAM_PUBKEY, 0, 0, true, &ux_display_peer_pubkey_step};
        configs[2] = (param_config_t) {MAX_AUTHORIZE,
                                       PARAM_AMOUNT,
                                       2,
                                       BUFFER_AMOUNT,
                                       false,
                                       &ux_display_max_authorize_step};
        method.configs = configs;
        method.config_count = 3;
    } else if (method_len == strlen(METHOD_SET_FEE_PERCENTAGE) &&
               memcmp(method_data, METHOD_SET_FEE_PERCENTAGE, method_len) == 0) {
        method.method_name = METHOD_SET_FEE_PERCENTAGE;
        method.title = SET_FEE_PERCENTAGE_TITLE;
        method.content = SET_FEE_PERCENTAGE_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {ADDRESS,
                                       PARAM_ADDR,
                                       1,
                                       BUFFER_ADDRESS,
                                       false,
                                       &ux_display_address_step};
        configs[1] =
            (param_config_t) {PEER_PUBKEY, PARAM_PUBKEY, 0, 0, true, &ux_display_peer_pubkey_step};
        configs[2] = (param_config_t) {PEER_COST,
                                       PARAM_AMOUNT,
                                       2,
                                       BUFFER_AMOUNT,
                                       false,
                                       &ux_display_peer_cost_step};
        configs[3] = (param_config_t) {STAKE_COST,
                                       PARAM_AMOUNT,
                                       3,
                                       BUFFER_AMOUNT,
                                       false,
                                       &ux_display_stake_cost_step};
        method.configs = configs;
        method.config_count = 4;
    } else if (method_len == strlen(METHOD_AUTHORIZE_FOR_PEER) &&
               memcmp(method_data, METHOD_AUTHORIZE_FOR_PEER, method_len) == 0) {
        method.method_name = METHOD_AUTHORIZE_FOR_PEER;
        method.title = AUTHORIZE_FOR_PEER_TITLE;
        method.content = AUTHORIZE_FOR_PEER_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {ADDRESS,
                                       PARAM_ADDR,
                                       0,
                                       BUFFER_ADDRESS,
                                       false,
                                       &ux_display_address_step};
        method.configs = configs;
        method.config_count = 1;
    } else if (method_len == strlen(METHOD_UNAUTHORIZE_FOR_PEER) &&
               memcmp(method_data, METHOD_UNAUTHORIZE_FOR_PEER, method_len) == 0) {
        method.method_name = METHOD_UNAUTHORIZE_FOR_PEER;
        method.title = UN_AUTHORIZE_FOR_PEER_TITLE;
        method.content = UN_AUTHORIZE_FOR_PEER_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {ADDRESS,
                                       PARAM_ADDR,
                                       0,
                                       BUFFER_ADDRESS,
                                       false,
                                       &ux_display_address_step};
        method.configs = configs;
        method.config_count = 1;
    } else if (method_len == strlen(METHOD_WITHDRAW) &&
               memcmp(method_data, METHOD_WITHDRAW, method_len) == 0) {
        method.method_name = METHOD_WITHDRAW;
        method.title = WITHDRAW_TITLE;
        method.content = WITHDRAW_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {ADDRESS,
                                       PARAM_ADDR,
                                       0,
                                       BUFFER_ADDRESS,
                                       false,
                                       &ux_display_address_step};
        /*
        configs[1] = (param_config_t) {TOTAL_WITHDRAW,
                                       PARAM_AMOUNT,
                                       2,
                                       BUFFER_AMOUNT,
                                       false,
                                       &ux_display_withdraw_step};
        */
        method.configs = configs;
        method.config_count = 1;
    } else if (method_len == strlen(METHOD_WITHDRAW_FEE) &&
               memcmp(method_data, METHOD_WITHDRAW_FEE, method_len) == 0) {
        method.method_name = METHOD_WITHDRAW_FEE;
        method.title = WITHDRAW_FEE_TITLE;
        method.content = WITHDRAW_FEE_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {ADDRESS,
                                       PARAM_ADDR,
                                       0,
                                       BUFFER_ADDRESS,
                                       false,
                                       &ux_display_address_step};
        method.configs = configs;
        method.config_count = 1;
    } else {
        PRINTF("No matching method found\n");
        explicit_bzero(&method, sizeof(method));
        return NULL;
    }

    PRINTF("Match found: %s\n", method.method_name);
    return &method;
}

static void create_transaction_flow(transaction_t *tx) {
    if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        return;
    }

    clear_buffers();
    memset(ux_display_tx_flow, 0, sizeof(ux_display_tx_flow));
    uint8_t index = 0;

    add_step(&index, &ux_display_review_step);
    const method_display_t *method = get_method_display(tx);
    if (method) {
        method->param_handler(tx, &index, method->configs, method->config_count);
    }
    add_step(&index,
             strcmp(method->method_name, METHOD_REGISTER_CANDIDATE) == 0 ? &ux_display_gas_fee_step
                                                                         : &ux_display_fee_step);
    add_step(&index, &ux_display_signer_step);
    add_step(&index, &ux_display_tx_approve_step);
    add_step(&index, &ux_display_tx_reject_step);
    add_step(&index, FLOW_END_STEP);
}

UX_FLOW(ux_display_blind_signed_flow,
        &ux_display_review_step,
        &ux_display_blind_signing_step,
        &ux_display_signer_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

int ui_bagl_display_blind_transaction_bs_choice(void) {
    if (G_context.req_type != CONFIRM_TRANSACTION) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    clear_buffers();
    strlcpy(g_content, BLIND_SIGN_TX_MSG, sizeof(g_content));
    g_validate_callback = ui_action_validate_transaction;

    ux_flow_init(0, ux_display_blind_signed_flow, NULL);
    return 0;
}

int ui_display_transaction(bool is_blind_signed) {
    if (is_blind_signed) {
        return ui_bagl_display_blind_transaction_bs_choice();
    } else {
        create_transaction_flow(&G_context.tx_info.transaction);
        ux_flow_init(0, ux_display_tx_flow, NULL);
    }
    return 0;
}

UX_FLOW(ux_display_pubkey_flow,
        &ux_display_confirm_addr_step,
        &ux_display_address_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

int ui_display_address(void) {
    if (G_context.req_type != CONFIRM_ADDRESS || G_context.state != STATE_NONE) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    clear_buffers();
    if (!ont_address_by_pubkey(G_context.pk_info.raw_public_key,
                               g_buffers[BUFFER_ADDRESS],
                               MAX_BUFFER_LEN)) {
        return io_send_sw(SW_DISPLAY_ADDRESS_FAIL);
    }

    g_validate_callback = ui_action_validate_pubkey;
    ux_flow_init(0, ux_display_pubkey_flow, NULL);
    return 0;
}

UX_FLOW(ux_display_personal_msg_flow,
        &ux_display_review_step,
        &ux_display_personal_msg_step,
        &ux_display_signer_step,
        &ux_display_approve_step,
        &ux_display_reject_step);

int ui_display_bagl_personal_msg_choice(void) {
    if (G_context.req_type != CONFIRM_MESSAGE || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    clear_buffers();
    size_t max_copy_len = sizeof(g_content) - 1;
    size_t copy_len = MIN(G_context.personal_msg_info.raw_msg_len, max_copy_len);
    memcpy(g_content, G_context.personal_msg_info.msg_info.personal_msg, copy_len);
    g_content[copy_len] = '\0';

    g_validate_callback = ui_action_validate_personal_msg;
    ux_flow_init(0, ux_display_personal_msg_flow, NULL);
    return 0;
}

int ui_display_personal_msg(void) {
    return ui_display_bagl_personal_msg_choice();
}

#endif