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
#if defined(TARGET_STAX) || defined(TARGET_FLEX)
#define NUM_BUFFERS   155
#define MAX_PAIR_LIST 155
#elif defined(TARGET_NANOX) || defined(TARGET_NANOS2)
#define NUM_BUFFERS   95
#define MAX_PAIR_LIST 95
#else
#warning "No target device defined"
#endif
#define MAX_CONFIGS    7  // Max number of param_config_t entries per method
#define MAX_PARAMETERS 5

static char g_buffers[NUM_BUFFERS][MAX_BUFFER_LEN];
static nbgl_contentTagValue_t pairs[MAX_PAIR_LIST];
static nbgl_contentTagValueList_t pairList;
static char gas_fee[20];
static char signer[40];

// Configuration for parameter parsing
typedef struct {
    const char *item;
    uint8_t pos;
} param_config_t;

// Updated method_display_t to pass method_name to handler
typedef struct {
    const char *title;
    const char *finish_title;
    param_config_t *configs;
    uint8_t config_count;
} method_display_t;

// Function declarations
void parse_param_to_pair(transaction_t *tx,
                         uint8_t param_idx,
                         nbgl_contentTagValue_t *pair,
                         const char *item,
                         char *buffer,
                         size_t buffer_len);

// Static functions
static void clear_buffers(void) {
    for (uint16_t i = 0; i < NUM_BUFFERS; i++) {
        explicit_bzero(g_buffers[i], MAX_BUFFER_LEN);
    }
}

// Unified handler function
static bool handle_params(transaction_t *tx,
                          nbgl_contentTagValue_t *tag_pairs,
                          uint8_t *nbPairs,
                          param_config_t *configs,
                          uint8_t config_count) {
    if (tx == NULL || tag_pairs == NULL || nbPairs == NULL || configs == NULL) {
        PRINTF("Error: Null pointer in handle_params\n");
        return false;
    }

    for (uint8_t i = 0; i < config_count; i++) {
        parse_param_to_pair(tx,
                            i,
                            &tag_pairs[configs[i].pos],
                            configs[i].item,
                            g_buffers[i],
                            MAX_BUFFER_LEN);
    }
    *nbPairs = config_count;

    if (is_specific_method(&tx->method.name, METHOD_REGISTER_CANDIDATE)) {
        tag_pairs[*nbPairs].item = STAKE_FEE;
        tag_pairs[*nbPairs].value = STAKE_FEE_ONG;
        (*nbPairs)++;
    } else if (is_specific_method(&tx->method.name, METHOD_AUTHORIZE_FOR_PEER) ||
               is_specific_method(&tx->method.name, METHOD_UNAUTHORIZE_FOR_PEER) ||
               is_specific_method(&tx->method.name, METHOD_WITHDRAW)) {
        uint64_t pubkey_num = 0;
        if (!convert_param_to_uint64_le(&tx->method.parameters[1], &pubkey_num) ||
            pubkey_num == 0) {
            return false;
        }
        size_t curr = 1;

        parse_param_to_pair(tx,
                            2,
                            &tag_pairs[(*nbPairs)++],
                            NBGL_PEER_PUBKEY " 1",
                            g_buffers[curr++],
                            MAX_BUFFER_LEN);

        if (pubkey_num >= 2) {
            parse_param_to_pair(tx,
                                3,
                                &tag_pairs[(*nbPairs)++],
                                NBGL_PEER_PUBKEY " 2",
                                g_buffers[curr++],
                                MAX_BUFFER_LEN);
        }
        if (pubkey_num >= 3) {
            parse_param_to_pair(tx,
                                4,
                                &tag_pairs[(*nbPairs)++],
                                NBGL_PEER_PUBKEY " 3",
                                g_buffers[curr++],
                                MAX_BUFFER_LEN);
        }
        if (pubkey_num > 1) {
            format_u64(g_buffers[curr], MAX_BUFFER_LEN, pubkey_num);
            tag_pairs[*nbPairs].item = NODE_AMOUNT;
            tag_pairs[*nbPairs].value = g_buffers[curr++];
            (*nbPairs)++;
        }
        if (is_specific_method(&tx->method.name, METHOD_WITHDRAW)) {
            strlcat(G_context.display_data.amount, ONT_VIEW, sizeof(G_context.display_data.amount));
            tag_pairs[*nbPairs].item = TOTAL_WITHDRAW;
            tag_pairs[*nbPairs].value = G_context.display_data.amount;
            (*nbPairs)++;
        }
    }
    if (tx->contract.type == NATIVE_CONTRACT &&
        (is_specific_method(&tx->method.name, METHOD_TRANSFER) ||
         is_specific_method(&tx->method.name, METHOD_TRANSFER_V2))) {
        uint8_t state_num = 1;
        while (tx->method.parameters[3 * state_num].data != NULL) {
            for (uint8_t i = 0; i < 3; i++) {
                parse_param_to_pair(tx,
                                    i + 3 * state_num,
                                    &tag_pairs[configs[i].pos + 3 * state_num],
                                    configs[i].item,

                                    g_buffers[i + 3 * state_num],
                                    MAX_BUFFER_LEN);
            }
            state_num++;
            *nbPairs += 3;
        }
    }
    return true;
}

void parse_param_to_pair(transaction_t *tx,
                         uint8_t param_idx,
                         nbgl_contentTagValue_t *pair,
                         const char *item,
                         char *buffer,
                         size_t buffer_len) {
    if (tx == NULL || pair == NULL || item == NULL || buffer == NULL) {
        PRINTF("Error: Null pointer in parse_param_to_pair\n");
        return;
    }
    // if (param_idx >= MAX_PARAMETERS) {
    //     PRINTF("Error: param_idx %u out of bounds\n", param_idx);
    //     return;
    // }

    pair->item = item;
    pair->value = buffer;
    explicit_bzero(buffer, buffer_len);

    tx_parameter_t *param = &tx->method.parameters[param_idx];
    if (param->data == NULL) {
        PRINTF("Error: param->data is NULL for idx %u\n", param_idx);
        return;
    }

    switch (param->type) {
        case PARAM_ADDR:
            convert_script_hash_to_base58_address(buffer, buffer_len, param->data);
            break;
        case PARAM_UINT128:
        case PARAM_AMOUNT: {
            convert_param_amount_to_chars(param,
                                          tx->contract.token_decimals,
                                          tx->contract.type != WASMVM_CONTRACT,
                                          buffer,
                                          buffer_len);
            if (is_specific_method(&tx->method.name, METHOD_SET_FEE_PERCENTAGE)) {
                strlcat(buffer, PERCENTAGE, buffer_len);
            } else {
                strlcat(buffer, " ", buffer_len);
                strlcat(buffer, tx->contract.ticker, buffer_len);
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
            PRINTF("Warning: Unknown param type %d\n", param->type);
            break;
    }
}

static const method_display_t *get_method_display(const transaction_t *tx) {
    static method_display_t method;
    static param_config_t configs[MAX_CONFIGS];

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

    if (is_specific_method(&tx->method.name, METHOD_TRANSFER)) {
        method.title = TRANSFER_TITLE;
        method.finish_title = TRANSFER_CONTENT;
        if (tx->contract.type != NEOVM_CONTRACT) {
            configs[0] = (param_config_t) {FROM, 1};
            configs[1] = (param_config_t) {TO, 2};
            configs[2] = (param_config_t) {AMOUNT, 0};
        } else {
            configs[0] = (param_config_t) {AMOUNT, 0};
            configs[1] = (param_config_t) {TO, 2};
            configs[2] = (param_config_t) {FROM, 1};
        }
        method.configs = configs;
        method.config_count = 3;
    } else if (is_specific_method(&tx->method.name, METHOD_TRANSFER_V2)) {
        method.title = TRANSFER_TITLE;
        method.finish_title = TRANSFER_CONTENT;
        configs[0] = (param_config_t) {FROM, 1};
        configs[1] = (param_config_t) {TO, 2};
        configs[2] = (param_config_t) {AMOUNT, 0};
        method.configs = configs;
        method.config_count = 3;
    } else if (is_specific_method(&tx->method.name, METHOD_TRANSFER_FROM)) {
        method.title = TRANSFER_FROM_TITLE;
        method.finish_title = TRANSFER_FROM_CONTENT;
        if (tx->contract.type != NEOVM_CONTRACT) {
            configs[0] = (param_config_t) {SENDER, 1};
            configs[1] = (param_config_t) {FROM, 2};
            configs[2] = (param_config_t) {TO, 3};
            configs[3] = (param_config_t) {AMOUNT, 0};
        } else {
            configs[0] = (param_config_t) {AMOUNT, 0};
            configs[1] = (param_config_t) {TO, 3};
            configs[2] = (param_config_t) {FROM, 2};
            configs[3] = (param_config_t) {SENDER, 1};
        }
        method.configs = configs;
        method.config_count = 4;
    } else if (is_specific_method(&tx->method.name, METHOD_TRANSFER_FROM_V2)) {
        method.title = TRANSFER_FROM_TITLE;
        method.finish_title = TRANSFER_FROM_CONTENT;
        configs[0] = (param_config_t) {SENDER, 1};
        configs[1] = (param_config_t) {FROM, 2};
        configs[2] = (param_config_t) {TO, 3};
        configs[3] = (param_config_t) {AMOUNT, 0};
        method.configs = configs;
        method.config_count = 4;
    } else if (is_specific_method(&tx->method.name, METHOD_APPROVE)) {
        method.title = APPROVE_TITLE;
        method.finish_title = APPROVE_CONTENT;
        if (tx->contract.type != NEOVM_CONTRACT) {
            configs[0] = (param_config_t) {FROM, 1};
            configs[1] = (param_config_t) {TO, 2};
            configs[2] = (param_config_t) {AMOUNT, 0};
        } else {
            configs[0] = (param_config_t) {AMOUNT, 0};
            configs[1] = (param_config_t) {TO, 2};
            configs[2] = (param_config_t) {FROM, 1};
        }
        method.configs = configs;
        method.config_count = 3;
    } else if (is_specific_method(&tx->method.name, METHOD_APPROVE_V2)) {
        method.title = APPROVE_TITLE;
        method.finish_title = APPROVE_CONTENT;
        configs[0] = (param_config_t) {FROM, 0};
        configs[1] = (param_config_t) {TO, 1};
        configs[2] = (param_config_t) {AMOUNT, 2};
        method.configs = configs;
        method.config_count = 3;
    } else if (is_specific_method(&tx->method.name, METHOD_REGISTER_CANDIDATE)) {
        method.title = REGISTER_CANDIDATE_TITLE;
        method.finish_title = REGISTER_CANDIDATE_CONTENT;
        configs[0] = (param_config_t) {NBGL_PEER_PUBKEY, 1};
        configs[1] = (param_config_t) {ADDRESS, 0};
        method.configs = configs;
        method.config_count = 2;
    } else if (is_specific_method(&tx->method.name, METHOD_QUIT_NODE)) {
        method.title = QUIT_NODE_TITLE;
        method.finish_title = QUIT_NODE_CONTENT;
        configs[0] = (param_config_t) {NBGL_PEER_PUBKEY, 1};
        configs[1] = (param_config_t) {ADDRESS, 0};
        method.configs = configs;
        method.config_count = 2;
    } else if (is_specific_method(&tx->method.name, METHOD_ADD_INIT_POS)) {
        method.title = ADD_INIT_POS_TITLE;
        method.finish_title = ADD_INIT_POS_CONTENT;
        configs[0] = (param_config_t) {NBGL_PEER_PUBKEY, 1};
        configs[1] = (param_config_t) {ADDRESS, 0};
        configs[2] = (param_config_t) {POS, 2};
        method.configs = configs;
        method.config_count = 3;
    } else if (is_specific_method(&tx->method.name, METHOD_REDUCE_INIT_POS)) {
        method.title = REDUCE_INIT_POS_TITLE;
        method.finish_title = REDUCE_INIT_POS_CONTENT;
        configs[0] = (param_config_t) {NBGL_PEER_PUBKEY, 1};
        configs[1] = (param_config_t) {ADDRESS, 0};
        configs[2] = (param_config_t) {AMOUNT, 2};
        method.configs = configs;
        method.config_count = 3;
    } else if (is_specific_method(&tx->method.name, METHOD_CHANGE_MAX_AUTH)) {
        method.title = CHANGE_MAX_AUTHORIZATION_TITLE;
        method.finish_title = CHANGE_MAX_AUTHORIZATION_CONTENT;
        configs[0] = (param_config_t) {NBGL_PEER_PUBKEY, 1};
        configs[1] = (param_config_t) {ADDRESS, 0};
        configs[2] = (param_config_t) {MAX_AUTHORIZE, 2};
        method.configs = configs;
        method.config_count = 3;
    } else if (is_specific_method(&tx->method.name, METHOD_SET_FEE_PERCENTAGE)) {
        method.title = SET_FEE_PERCENTAGE_TITLE;
        method.finish_title = SET_FEE_PERCENTAGE_CONTENT;
        configs[0] = (param_config_t) {NBGL_PEER_PUBKEY, 1};
        configs[1] = (param_config_t) {ADDRESS, 0};
        configs[2] = (param_config_t) {PEER_COST, 2};
        configs[3] = (param_config_t) {STAKE_COST, 3};
        method.configs = configs;
        method.config_count = 4;
    } else if (is_specific_method(&tx->method.name, METHOD_AUTHORIZE_FOR_PEER)) {
        method.title = AUTHORIZE_FOR_PEER_TITLE;
        method.finish_title = AUTHORIZE_FOR_PEER_CONTENT;
        configs[0] = (param_config_t) {ADDRESS, 0};
        method.configs = configs;
        method.config_count = 1;
    } else if (is_specific_method(&tx->method.name, METHOD_UNAUTHORIZE_FOR_PEER)) {
        method.title = UN_AUTHORIZE_FOR_PEER_TITLE;
        method.finish_title = UN_AUTHORIZE_FOR_PEER_CONTENT;
        configs[0] = (param_config_t) {ADDRESS, 0};
        method.configs = configs;
        method.config_count = 1;
    } else if (is_specific_method(&tx->method.name, METHOD_WITHDRAW)) {
        method.title = WITHDRAW_TITLE;
        method.finish_title = WITHDRAW_CONTENT;
        configs[0] = (param_config_t) {ADDRESS, 0};
        method.configs = configs;
        method.config_count = 1;
    } else if (is_specific_method(&tx->method.name, METHOD_WITHDRAW_FEE)) {
        method.title = WITHDRAW_FEE_TITLE;
        method.finish_title = WITHDRAW_FEE_CONTENT;
        configs[0] = (param_config_t) {ADDRESS, 0};
        method.configs = configs;
        method.config_count = 1;
    } else {
        PRINTF("No matching method found\n");
        return NULL;
    }

    return &method;
}

static void review_choice(bool confirm) {
    validate_transaction(confirm);
    nbgl_useCaseReviewStatus(
        confirm ? STATUS_TYPE_TRANSACTION_SIGNED : STATUS_TYPE_TRANSACTION_REJECTED,
        ui_menu_main);
}

static int ui_display_bs_transaction() {
    pairs[0].item = BLIND_SIGN_TX;
    pairs[0].value = BLIND_SIGNING;
    pairs[1].item = SIGNER;
    pairs[1].value = G_context.display_data.signer;
    pairList.nbPairs = 2;
    nbgl_useCaseReviewBlindSigning(TYPE_TRANSACTION,
                                   &pairList,
                                   &ICON_APP_ONTOLOGY,
                                   BLIND_SIGNING_TITLE,
                                   NULL,
                                   BLIND_SIGNING_CONTENT,
                                   NULL,
                                   review_choice);
    return 0;
}

static int ui_display_normal_transaction() {
    const method_display_t *method = get_method_display(&G_context.tx_info.transaction);
    if (!method) {
        return io_send_sw(SW_INVALID_TRANSACTION);
    }
    pairList.nbPairs = 0;
    handle_params(&G_context.tx_info.transaction,
                  pairs,
                  &pairList.nbPairs,
                  method->configs,
                  method->config_count);

    const char *fee_tag =
        (G_context.tx_info.transaction.method.name.len == strlen(METHOD_REGISTER_CANDIDATE) &&
         memcmp(G_context.tx_info.transaction.method.name.data,
                METHOD_REGISTER_CANDIDATE,
                G_context.tx_info.transaction.method.name.len) == 0)
            ? GAS_FEE
            : FEE_ONG;

    if (!format_fpu64_trimmed(gas_fee,
                              sizeof(gas_fee),
                              G_context.tx_info.transaction.header.gas_price *
                                  G_context.tx_info.transaction.header.gas_limit,
                              9)) {
        return io_send_sw(SW_DISPLAY_AMOUNT_FAIL); 
    }
    strlcat(gas_fee, ONG_VIEW, sizeof(gas_fee));

    pairs[pairList.nbPairs].item = fee_tag;
    pairs[pairList.nbPairs].value = gas_fee;
    pairList.nbPairs++;

    if (!derive_address_from_bip32_path(signer, sizeof(signer))) {
        return io_send_sw(SW_DISPLAY_ADDRESS_FAIL);
    }
    pairs[pairList.nbPairs].item = SIGNER;
    pairs[pairList.nbPairs].value = signer;
    pairList.nbPairs++;

    nbgl_useCaseReview(TYPE_TRANSACTION,
                       &pairList,
                       &ICON_APP_ONTOLOGY,
                       method->title,
                       NULL,
                       method->finish_title,
                       review_choice);
    return 0;
}

int ui_display_transaction(bool is_blind_signed) {
    if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    clear_buffers();
    explicit_bzero(&pairList, sizeof(pairList));
    pairList.pairs = pairs;

    if (is_blind_signed) {
        return ui_display_bs_transaction();
    } else {
        return ui_display_normal_transaction();
    }
    return 0;
}

#endif