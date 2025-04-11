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

#ifdef HAVE_NBGL

#include <stdbool.h>  // bool
#include <string.h>   // memset, strcmp

#include "os.h"
#include "glyphs.h"
#include "os_io_seproxyhal.h"
#include "nbgl_use_case.h"
#include "io.h"
#include "bip32.h"
#include "format.h"

#include "display.h"
#include "constants.h"
#include "globals.h"
#include "sw.h"
#include "address.h"
#include "validate.h"
#include "tx_types.h"
#include "menu.h"
#include "types.h"
#include "../transaction/contract.h"
#include "../transaction/utils.h"

#define MAX_BUFFER_LEN 68
#define NUM_BUFFERS    11
#define MAX_CONFIGS    4  // Max number of param_config_t entries per method
#define MAX_PARAMETERS 5

typedef enum {
    BUFFER_AMOUNT = 0,
    BUFFER_ADDRESS,
    BUFFER_FROM,
    BUFFER_TO,
    BUFFER_PEER_PUBKEY,
    BUFFER_PEER_PUBKEY_1,
    BUFFER_PEER_PUBKEY_2,
    BUFFER_PUBKEY_NUMBER,
    BUFFER_TITLE,
    BUFFER_TITLE_TWO,
    BUFFER_TITLE_THREE
} buffer_index_e;

static char g_buffers[NUM_BUFFERS][MAX_BUFFER_LEN];
static nbgl_contentTagValue_t pairs[10];
static nbgl_contentTagValueList_t pairList;

// Configuration for parameter parsing
typedef struct {
    const char *tag;
    tx_parameter_type_e type;
    uint8_t param_idx;  // Default index, may be adjusted at runtime
    buffer_index_e buffer_idx;
} param_config_t;

// Updated method_display_t to pass method_name to handler
typedef struct {
    const char *method_name;
    const char *title;
    const char *content;
    void (*param_handler)(transaction_t *tx,
                          nbgl_contentTagValue_t *pairs,
                          uint8_t *nbPairs,
                          param_config_t *configs,
                          uint8_t config_count,
                          const char *method_name);
    param_config_t *configs;
    uint8_t config_count;
} method_display_t;

// Function declarations
void parse_param_to_pair(transaction_t *tx,
                         nbgl_contentTagValue_t *pair,
                         const char *tag,
                         tx_parameter_type_e type,
                         uint8_t param_idx,
                         char *buffer,
                         size_t buffer_len);
static void parse_params(transaction_t *tx,
                         nbgl_contentTagValue_t *pairs,
                         uint8_t *nbPairs,
                         param_config_t *configs,
                         uint8_t config_count);

// Static functions
static void clear_buffers(void) {
    for (uint8_t i = 0; i < NUM_BUFFERS; i++) {
        explicit_bzero(g_buffers[i], MAX_BUFFER_LEN);
    }
}

static void parse_params(transaction_t *tx,
                         nbgl_contentTagValue_t *tag_pairs,
                         uint8_t *nbPairs,
                         param_config_t *configs,
                         uint8_t config_count) {
    for (uint8_t i = 0; i < config_count; i++) {
        parse_param_to_pair(tx,
                            &tag_pairs[(*nbPairs)++],
                            configs[i].tag,
                            configs[i].type,
                            configs[i].param_idx,
                            g_buffers[configs[i].buffer_idx],
                            MAX_BUFFER_LEN);
    }
}

// Unified handler function
static void handle_params(transaction_t *tx,
                          nbgl_contentTagValue_t *tag_pairs,
                          uint8_t *nbPairs,
                          param_config_t *configs,
                          uint8_t config_count,
                          const char *method_name) {
    param_config_t local_configs[MAX_CONFIGS];
    memcpy(local_configs, configs, config_count * sizeof(param_config_t));

    if (strcmp(method_name, METHOD_TRANSFER) == 0 || strcmp(method_name, METHOD_TRANSFER_V2) == 0) {
        local_configs[1].param_idx = (tx->contract.type == NEOVM_CONTRACT) ? 1 : 0;  // FROM
        local_configs[2].param_idx = (tx->contract.type == NEOVM_CONTRACT) ? 2 : 1;  // TO
    } else if (strcmp(method_name, METHOD_TRANSFER_FROM) == 0 ||
               strcmp(method_name, METHOD_TRANSFER_FROM_V2) == 0) {
        local_configs[0].param_idx = (tx->contract.type == NEOVM_CONTRACT) ? 0 : 3;  // AMOUNT
        local_configs[1].param_idx = (tx->contract.type == NEOVM_CONTRACT) ? 1 : 0;  // SENDER
        local_configs[2].param_idx = (tx->contract.type == NEOVM_CONTRACT) ? 2 : 1;  // FROM
        local_configs[3].param_idx = (tx->contract.type == NEOVM_CONTRACT) ? 3 : 2;  // TO
    } else if (strcmp(method_name, METHOD_APPROVE) == 0 ||
               strcmp(method_name, METHOD_APPROVE_V2) == 0) {
        local_configs[1].param_idx = (tx->contract.type == NEOVM_CONTRACT) ? 1 : 0;  // FROM
        local_configs[2].param_idx = (tx->contract.type == NEOVM_CONTRACT) ? 2 : 1;  // TO
    }

    parse_params(tx, tag_pairs, nbPairs, local_configs, config_count);

    if (strcmp(method_name, METHOD_REGISTER_CANDIDATE) == 0) {
        tag_pairs[*nbPairs].item = STAKE_FEE;
        tag_pairs[*nbPairs].value = STAKE_FEE_ONG;
        (*nbPairs)++;
    } else if (strcmp(method_name, METHOD_AUTHORIZE_FOR_PEER) == 0 ||
               strcmp(method_name, METHOD_UNAUTHORIZE_FOR_PEER) == 0 ||
               strcmp(method_name, METHOD_WITHDRAW) == 0) {
        uint8_t pubkey_num =
            getValueByLen(tx->method.parameters[1].data, tx->method.parameters[1].len);
        if (pubkey_num >= 1) {
            parse_param_to_pair(tx,
                                &tag_pairs[*nbPairs],
                                NBGL_PEER_PUBKEY " 1",
                                PARAM_PUBKEY,
                                2,
                                g_buffers[BUFFER_PEER_PUBKEY],
                                MAX_BUFFER_LEN);
            (*nbPairs)++;
        }
        if (pubkey_num >= 2) {
            parse_param_to_pair(tx,
                                &tag_pairs[*nbPairs],
                                NBGL_PEER_PUBKEY " 2",
                                PARAM_PUBKEY,
                                3,
                                g_buffers[BUFFER_PEER_PUBKEY_1],
                                MAX_BUFFER_LEN);
            (*nbPairs)++;
        }
        if (pubkey_num >= 3) {
            parse_param_to_pair(tx,
                                &tag_pairs[*nbPairs],
                                NBGL_PEER_PUBKEY " 3",
                                PARAM_PUBKEY,
                                4,
                                g_buffers[BUFFER_PEER_PUBKEY_2],
                                MAX_BUFFER_LEN);
            (*nbPairs)++;
        }
        if (pubkey_num > 1) {
            format_u64(g_buffers[BUFFER_PUBKEY_NUMBER], MAX_BUFFER_LEN, pubkey_num);
            tag_pairs[*nbPairs].item = NODE_AMOUNT;
            tag_pairs[*nbPairs].value = g_buffers[BUFFER_PUBKEY_NUMBER];
            (*nbPairs)++;
        }
        if (strcmp(method_name, METHOD_WITHDRAW) == 0) {
            parse_param_to_pair(tx,
                                &tag_pairs[*nbPairs],
                                TOTAL_WITHDRAW,
                                PARAM_AMOUNT,
                                2,
                                g_buffers[BUFFER_AMOUNT],
                                MAX_BUFFER_LEN);
            (*nbPairs)++;
        }
    }
}

void parse_param_to_pair(transaction_t *tx,
                         nbgl_contentTagValue_t *pair,
                         const char *tag,
                         tx_parameter_type_e type,
                         uint8_t param_idx,
                         char *buffer,
                         size_t buffer_len) {
    if (tx == NULL || pair == NULL || tag == NULL || buffer == NULL) {
        PRINTF("Error: Null pointer in parse_param_to_pair\n");
        return;
    }
    if (param_idx >= MAX_PARAMETERS) {  // Assume MAX_PARAMETERS is defined in tx_types.h
        PRINTF("Error: param_idx %u out of bounds\n", param_idx);
        return;
    }

    pair->item = tag;
    pair->value = buffer;
    explicit_bzero(buffer, buffer_len);

    tx_parameter_t *param = &tx->method.parameters[param_idx];
    if (param->data == NULL) {
        PRINTF("Error: param->data is NULL for idx %u\n", param_idx);
        return;
    }

    switch (type) {
        case PARAM_ADDR:
            script_hash_to_address(buffer, buffer_len, param->data);
            break;
        case PARAM_AMOUNT: {
            uint8_t ont_addr[ADDRESS_LEN], ong_addr[ADDRESS_LEN];
            get_ont_addr(ont_addr);
            get_ong_addr(ong_addr);
            get_token_value(param->len,
                            param->data,
                            tx->contract.token_decimals,
                            buffer,
                            buffer_len);
            if (memcmp(tx->contract.addr.data, ont_addr, ADDRESS_LEN) == 0)
                strlcat(buffer, ONT_VIEW, buffer_len);
            else if (memcmp(tx->contract.addr.data, ong_addr, ADDRESS_LEN) == 0)
                strlcat(buffer, ONG_VIEW, buffer_len);
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

static const method_display_t *get_method_display(const transaction_t *tx) {
    static method_display_t method;
    static param_config_t configs[MAX_CONFIGS]; // Now static

    if (tx == NULL) {
        PRINTF("Error: tx is NULL\n");
        return NULL;
    }

    const uint8_t *method_data = tx->method.name.data;
    size_t method_len = tx->method.name.len;

    if (method_data == NULL || method_len == 0) {
        PRINTF("Error: method_data is NULL or len=0\n");
        return NULL;
    }

    if (method_len == strlen(METHOD_TRANSFER) &&
        memcmp(method_data, METHOD_TRANSFER, method_len) == 0) {
        method.method_name = METHOD_TRANSFER;
        method.title = OEP4_TX_TITLE;
        method.content = OEP4_TX_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {AMOUNT, PARAM_AMOUNT, 2, BUFFER_AMOUNT};
        configs[1] = (param_config_t) {FROM, PARAM_ADDR, 0, BUFFER_FROM};
        configs[2] = (param_config_t) {TO, PARAM_ADDR, 1, BUFFER_TO};
        method.configs = configs;
        method.config_count = 3;
    } else if (method_len == strlen(METHOD_TRANSFER_V2) &&
               memcmp(method_data, METHOD_TRANSFER_V2, method_len) == 0) {
        method.method_name = METHOD_TRANSFER_V2;
        method.title = NATIVE_ONG_OR_ONT_TRANSFER_TITLE;
        method.content = NATIVE_ONG_OR_ONT_TRANSFER_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {AMOUNT, PARAM_AMOUNT, 2, BUFFER_AMOUNT};
        configs[1] = (param_config_t) {FROM, PARAM_ADDR, 0, BUFFER_FROM};
        configs[2] = (param_config_t) {TO, PARAM_ADDR, 1, BUFFER_TO};
        method.configs = configs;
        method.config_count = 3;
    } else if (method_len == strlen(METHOD_TRANSFER_FROM) &&
               memcmp(method_data, METHOD_TRANSFER_FROM, method_len) == 0) {
        method.method_name = METHOD_TRANSFER_FROM;
        method.title = TRANSFER_FROM_TITLE;
        method.content = TRANSFER_FROM_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {AMOUNT, PARAM_AMOUNT, 3, BUFFER_AMOUNT};
        configs[1] = (param_config_t) {SENDER, PARAM_ADDR, 0, BUFFER_ADDRESS};
        configs[2] = (param_config_t) {FROM, PARAM_ADDR, 1, BUFFER_FROM};
        configs[3] = (param_config_t) {TO, PARAM_ADDR, 2, BUFFER_TO};
        method.configs = configs;
        method.config_count = 4;
    } else if (method_len == strlen(METHOD_TRANSFER_FROM_V2) &&
               memcmp(method_data, METHOD_TRANSFER_FROM_V2, method_len) == 0) {
        method.method_name = METHOD_TRANSFER_FROM_V2;
        method.title = TRANSFER_FROM_TITLE;
        method.content = TRANSFER_FROM_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {AMOUNT, PARAM_AMOUNT, 3, BUFFER_AMOUNT};
        configs[1] = (param_config_t) {SENDER, PARAM_ADDR, 0, BUFFER_ADDRESS};
        configs[2] = (param_config_t) {FROM, PARAM_ADDR, 1, BUFFER_FROM};
        configs[3] = (param_config_t) {TO, PARAM_ADDR, 2, BUFFER_TO};
        method.configs = configs;
        method.config_count = 4;
    } else if (method_len == strlen(METHOD_APPROVE) &&
               memcmp(method_data, METHOD_APPROVE, method_len) == 0) {
        method.method_name = METHOD_APPROVE;
        method.title = SIGN_APPROVE_TX_TITLE;
        method.content = SIGN_APPROVE_TX_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {AMOUNT, PARAM_AMOUNT, 2, BUFFER_AMOUNT};
        configs[1] = (param_config_t) {FROM, PARAM_ADDR, 0, BUFFER_FROM};
        configs[2] = (param_config_t) {TO, PARAM_ADDR, 1, BUFFER_TO};
        method.configs = configs;
        method.config_count = 3;
    } else if (method_len == strlen(METHOD_APPROVE_V2) &&
               memcmp(method_data, METHOD_APPROVE_V2, method_len) == 0) {
        method.method_name = METHOD_APPROVE_V2;
        method.title = SIGN_APPROVE_TX_TITLE;
        method.content = SIGN_APPROVE_TX_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {AMOUNT, PARAM_AMOUNT, 2, BUFFER_AMOUNT};
        configs[1] = (param_config_t) {FROM, PARAM_ADDR, 0, BUFFER_FROM};
        configs[2] = (param_config_t) {TO, PARAM_ADDR, 1, BUFFER_TO};
        method.configs = configs;
        method.config_count = 3;
    } else if (method_len == strlen(METHOD_REGISTER_CANDIDATE) &&
               memcmp(method_data, METHOD_REGISTER_CANDIDATE, method_len) == 0) {
        method.method_name = METHOD_REGISTER_CANDIDATE;
        method.title = REGISTER_CANDIDATE_TITLE;
        method.content = REGISTER_CANDIDATE_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {NBGL_PEER_PUBKEY, PARAM_PUBKEY, 0, BUFFER_PEER_PUBKEY};
        configs[1] = (param_config_t) {ADDRESS, PARAM_ADDR, 1, BUFFER_ADDRESS};
        method.configs = configs;
        method.config_count = 2;
    } else if (method_len == strlen(METHOD_QUIT_NODE) &&
               memcmp(method_data, METHOD_QUIT_NODE, method_len) == 0) {
        method.method_name = METHOD_QUIT_NODE;
        method.title = QUIT_NODE_TITLE;
        method.content = QUIT_NODE_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {NBGL_PEER_PUBKEY, PARAM_PUBKEY, 0, BUFFER_PEER_PUBKEY};
        configs[1] = (param_config_t) {ADDRESS, PARAM_ADDR, 1, BUFFER_ADDRESS};
        method.configs = configs;
        method.config_count = 2;
    } else if (method_len == strlen(METHOD_ADD_INIT_POS) &&
               memcmp(method_data, METHOD_ADD_INIT_POS, method_len) == 0) {
        method.method_name = METHOD_ADD_INIT_POS;
        method.title = ADD_INIT_POS_TITLE;
        method.content = ADD_INIT_POS_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {NBGL_PEER_PUBKEY, PARAM_PUBKEY, 0, BUFFER_PEER_PUBKEY};
        configs[1] = (param_config_t) {ADDRESS, PARAM_ADDR, 1, BUFFER_ADDRESS};
        configs[2] = (param_config_t) {POS, PARAM_AMOUNT, 2, BUFFER_AMOUNT};
        method.configs = configs;
        method.config_count = 3;
    } else if (method_len == strlen(METHOD_REDUCE_INIT_POS) &&
               memcmp(method_data, METHOD_REDUCE_INIT_POS, method_len) == 0) {
        method.method_name = METHOD_REDUCE_INIT_POS;
        method.title = REDUCE_INIT_POS_TITLE;
        method.content = REDUCE_INIT_POS_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {NBGL_PEER_PUBKEY, PARAM_PUBKEY, 0, BUFFER_PEER_PUBKEY};
        configs[1] = (param_config_t) {ADDRESS, PARAM_ADDR, 1, BUFFER_ADDRESS};
        configs[2] = (param_config_t) {AMOUNT, PARAM_AMOUNT, 2, BUFFER_AMOUNT};
        method.configs = configs;
        method.config_count = 3;
    } else if (method_len == strlen(METHOD_CHANGE_MAX_AUTH) &&
               memcmp(method_data, METHOD_CHANGE_MAX_AUTH, method_len) == 0) {
        method.method_name = METHOD_CHANGE_MAX_AUTH;
        method.title = CHANGE_MAX_AUTHORIZATION_TITLE;
        method.content = CHANGE_MAX_AUTHORIZATION_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {NBGL_PEER_PUBKEY, PARAM_PUBKEY, 0, BUFFER_PEER_PUBKEY};
        configs[1] = (param_config_t) {ADDRESS, PARAM_ADDR, 1, BUFFER_ADDRESS};
        configs[2] = (param_config_t) {MAX_AUTHORIZE, PARAM_AMOUNT, 2, BUFFER_AMOUNT};
        method.configs = configs;
        method.config_count = 3;
    } else if (method_len == strlen(METHOD_SET_FEE_PERCENTAGE) &&
               memcmp(method_data, METHOD_SET_FEE_PERCENTAGE, method_len) == 0) {
        method.method_name = METHOD_SET_FEE_PERCENTAGE;
        method.title = SET_FEE_PERCENTAGE_TITLE;
        method.content = SET_FEE_PERCENTAGE_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {NBGL_PEER_PUBKEY, PARAM_PUBKEY, 0, BUFFER_PEER_PUBKEY};
        configs[1] = (param_config_t) {ADDRESS, PARAM_ADDR, 1, BUFFER_ADDRESS};
        configs[2] = (param_config_t) {PEER_COST, PARAM_AMOUNT, 2, BUFFER_AMOUNT};
        method.configs = configs;
        method.config_count = 3;
    } else if (method_len == strlen(METHOD_AUTHORIZE_FOR_PEER) &&
               memcmp(method_data, METHOD_AUTHORIZE_FOR_PEER, method_len) == 0) {
        method.method_name = METHOD_AUTHORIZE_FOR_PEER;
        method.title = AUTHORIZE_FOR_PEER_TITLE;
        method.content = AUTHORIZE_FOR_PEER_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {ADDRESS, PARAM_ADDR, 0, BUFFER_ADDRESS};
        method.configs = configs;
        method.config_count = 1;
    } else if (method_len == strlen(METHOD_UNAUTHORIZE_FOR_PEER) &&
               memcmp(method_data, METHOD_UNAUTHORIZE_FOR_PEER, method_len) == 0) {
        method.method_name = METHOD_UNAUTHORIZE_FOR_PEER;
        method.title = UN_AUTHORIZE_FOR_PEER_TITLE;
        method.content = UN_AUTHORIZE_FOR_PEER_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {ADDRESS, PARAM_ADDR, 0, BUFFER_ADDRESS};
        method.configs = configs;
        method.config_count = 1;
    } else if (method_len == strlen(METHOD_WITHDRAW) &&
               memcmp(method_data, METHOD_WITHDRAW, method_len) == 0) {
        method.method_name = METHOD_WITHDRAW;
        method.title = WITHDRAW_TITLE;
        method.content = WITHDRAW_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {ADDRESS, PARAM_ADDR, 0, BUFFER_ADDRESS};
        method.configs = configs;
        method.config_count = 1;
    } else if (method_len == strlen(METHOD_WITHDRAW_FEE) &&
               memcmp(method_data, METHOD_WITHDRAW_FEE, method_len) == 0) {
        method.method_name = METHOD_WITHDRAW_FEE;
        method.title = WITHDRAW_FEE_TITLE;
        method.content = WITHDRAW_FEE_CONTENT;
        method.param_handler = handle_params;
        configs[0] = (param_config_t) {ADDRESS, PARAM_ADDR, 0, BUFFER_ADDRESS};
        method.configs = configs;
        method.config_count = 1;
    } else {
        PRINTF("No matching method found\n");
        return NULL;
    }

    PRINTF("Match found: %s\n", method.method_name);
    return &method;
}

static void review_choice(bool confirm) {
    validate_transaction(confirm);
    nbgl_useCaseReviewStatus(
        confirm ? STATUS_TYPE_TRANSACTION_SIGNED : STATUS_TYPE_TRANSACTION_REJECTED,
        ui_menu_main);
}

static int ui_display_transaction_bs_choice(bool is_blind_signed) {
    if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    clear_buffers();
    explicit_bzero(&pairList, sizeof(pairList));
    pairList.pairs = pairs;

    if (is_blind_signed) {
        pairs[0].item = BLIND_SIGN_TX;
        pairs[0].value = BLIND_SIGNING;
        pairs[1].item = SIGNER;
        pairs[1].value = G_context.display_data.signer;
        pairList.nbPairs = 2;
        nbgl_useCaseReviewBlindSigning(TYPE_TRANSACTION,
                                       &pairList,
                                       &ICON_APP_BOILERPLATE,
                                       BLIND_SIGNING_TITLE,
                                       NULL,
                                       BLIND_SIGNING_CONTENT,
                                       NULL,
                                       review_choice);
    } else {
        const method_display_t *method = get_method_display(&G_context.tx_info.transaction);
        if (!method) {
            return io_send_sw(SW_INVALID_TRANSACTION);
        }
        pairList.nbPairs = 0;
        method->param_handler(&G_context.tx_info.transaction,
                              pairs,
                              &pairList.nbPairs,
                              method->configs,
                              method->config_count,
                              method->method_name);

        const char *fee_tag =
            (strcmp(method->method_name, METHOD_REGISTER_CANDIDATE) == 0) ? GAS_FEE : FEE_ONG;
        pairs[pairList.nbPairs].item = fee_tag;
        pairs[pairList.nbPairs].value = G_context.display_data.gas_fee;
        pairList.nbPairs++;

        pairs[pairList.nbPairs].item = SIGNER;
        pairs[pairList.nbPairs].value = G_context.display_data.signer;
        pairList.nbPairs++;

        nbgl_useCaseReview(TYPE_TRANSACTION,
                           &pairList,
                           &ICON_APP_BOILERPLATE,
                           method->title,
                           NULL,
                           method->content,
                           review_choice);
    }
    return 0;
}

int ui_display_transaction(void) {
    return ui_display_transaction_bs_choice(false);
}

int ui_display_blind_signed_transaction(void) {
    return ui_display_transaction_bs_choice(true);
}
#endif