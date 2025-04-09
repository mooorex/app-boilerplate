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
#include <string.h>   // memset

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
// Buffer where the transaction amount string is written
static char g_amount[40];
// Buffer where the transaction address string is written
static char g_address[40];
static char g_peer_pubkey[66];
static char g_from[40];
static char g_to[40];
static char g_pubkey_number[20];
static char g_title[60];
static char g_title_two[60];
static char g_title_three[60];
static char g_peer_pubkey_1[68];
static char g_peer_pubkey_2[68];

static nbgl_contentTagValue_t pairs[10];
static nbgl_contentTagValueList_t pairList;

static const char *review_title;
static const char *review_content;

static inline bool is_method(const char *data, size_t len, const char *method) {
    size_t method_len = strlen(method);
    return len == method_len && memcmp(data, method, len) == 0;
}

static void set_display_title_content(void) {
    review_title = TRANSFER_FROM_TITLE;
    review_content = TRANSFER_FROM_CONTENT;

    const char *method_data = G_context.tx_info.transaction.method.name.data;
    size_t method_len = G_context.tx_info.transaction.method.name.len;
    if (is_method(method_data, method_len, METHOD_ADD_INIT_POS)) {
        review_title = ADD_INIT_POS_TITLE;
        review_content = ADD_INIT_POS_CONTENT;
    } else if (is_method(method_data, method_len, METHOD_APPROVE)) {
        review_title = SIGN_APPROVE_TX_TITLE;
        review_content = SIGN_APPROVE_TX_CONTENT;
    } else if (is_method(method_data, method_len, METHOD_APPROVE_V2)) {
        review_title = SIGN_APPROVE_TX_TITLE;
        review_content = SIGN_APPROVE_TX_CONTENT;
    } else if (is_method(method_data, method_len, METHOD_AUTHORIZE_FOR_PEER)) {
        review_title = AUTHORIZE_FOR_PEER_TITLE;
        review_content = AUTHORIZE_FOR_PEER_CONTENT;
    } else if (is_method(method_data, method_len, METHOD_CHANGE_MAX_AUTH)) {
        review_title = CHANGE_MAX_AUTHORIZATION_TITLE;
        review_content = CHANGE_MAX_AUTHORIZATION_CONTENT;
    } else if (is_method(method_data, method_len, METHOD_TRANSFER)) {
        review_title = OEP4_TX_TITLE;
        review_content = OEP4_TX_CONTENT;
    } else if (is_method(method_data, method_len, METHOD_QUIT_NODE)) {
        review_title = QUIT_NODE_TITLE;
        review_content = QUIT_NODE_CONTENT;
    } else if (is_method(method_data, method_len, METHOD_REDUCE_INIT_POS)) {
        review_title = REDUCE_INIT_POS_TITLE;
        review_content = REDUCE_INIT_POS_CONTENT;
    } else if (is_method(method_data, method_len, METHOD_REGISTER_CANDIDATE)) {
        review_title = REGISTER_CANDIDATE_TITLE;
        review_content = REGISTER_CANDIDATE_CONTENT;
    } else if (is_method(method_data, method_len, METHOD_SET_FEE_PERCENTAGE)) {
        review_title = SET_FEE_PERCENTAGE_TITLE;
        review_content = SET_FEE_PERCENTAGE_CONTENT;
    } else if (is_method(method_data, method_len, METHOD_TRANSFER_V2)) {
        review_title = NATIVE_ONG_OR_ONT_TRANSFER_TITLE;
        review_content = NATIVE_ONG_OR_ONT_TRANSFER_CONTENT;
    } else if (is_method(method_data, method_len, METHOD_TRANSFER_FROM_V2)) {
        review_title = TRANSFER_FROM_TITLE;
        review_content = TRANSFER_FROM_CONTENT;
    } else if (is_method(method_data, method_len, METHOD_UNAUTHORIZE_FOR_PEER)) {
        review_title = UN_AUTHORIZE_FOR_PEER_TITLE;
        review_content = UN_AUTHORIZE_FOR_PEER_CONTENT;
    } else if (is_method(method_data, method_len, METHOD_WITHDRAW_FEE)) {
        review_title = WITHDRAW_FEE_TITLE;
        review_content = WITHDRAW_FEE_CONTENT;
    } else if (is_method(method_data, method_len, METHOD_WITHDRAW)) {
        review_title = WITHDRAW_TITLE;
        review_content = WITHDRAW_CONTENT;
    } else {
        PRINTF("No match found for method_data\n");
    }
}

// called when long press button on 3rd page is long-touched or when reject footer is touched
static void review_choice(bool confirm) {
    // Answer, display a status page and go back to main
    validate_transaction(confirm);
    if (confirm) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_SIGNED, ui_menu_main);
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_TRANSACTION_REJECTED, ui_menu_main);
    }
}

static uint8_t setTagValuePairs(void) {
    uint8_t nbPairs = 0;
    explicit_bzero(pairs, sizeof(pairs));

#define ADD_PAIR(tagName, valueName)      \
    do {                                  \
        pairs[nbPairs].item = tagName;    \
        pairs[nbPairs].value = valueName; \
        nbPairs++;                        \
    } while (0)

    const char *method_data = G_context.tx_info.transaction.method.name.data;
    size_t method_len = G_context.tx_info.transaction.method.name.len;

    bool isCommonTx = is_method(method_data, method_len, METHOD_REGISTER_CANDIDATE) ||
                      is_method(method_data, method_len, METHOD_QUIT_NODE) ||
                      is_method(method_data, method_len, METHOD_ADD_INIT_POS) ||
                      is_method(method_data, method_len, METHOD_REDUCE_INIT_POS) ||
                      is_method(method_data, method_len, METHOD_CHANGE_MAX_AUTH) ||
                      is_method(method_data, method_len, METHOD_SET_FEE_PERCENTAGE);

    bool isCommonTx1 = is_method(method_data, method_len, METHOD_AUTHORIZE_FOR_PEER) ||
                       is_method(method_data, method_len, METHOD_UNAUTHORIZE_FOR_PEER) ||
                       is_method(method_data, method_len, METHOD_WITHDRAW) ||
                       is_method(method_data, method_len, METHOD_WITHDRAW_FEE);

    if (isCommonTx) {
        script_hash_to_address(g_address,
                               sizeof(g_address),
                               G_context.tx_info.transaction.method.parameters[1].data);
        ADD_PAIR(ADDRESS, g_address);
        memcpy(g_peer_pubkey,
               G_context.tx_info.transaction.method.parameters[0].data,
               G_context.tx_info.transaction.method.parameters[0].len);
        ADD_PAIR(NBGL_PEER_PUBKEY, g_peer_pubkey);
    }
    if (isCommonTx1) {
        script_hash_to_address(g_address,
                               sizeof(g_address),
                               G_context.tx_info.transaction.method.parameters[0].data);
        ADD_PAIR(ADDRESS, g_address);
    }

    if (is_method(method_data, method_len, METHOD_WITHDRAW) ||
        is_method(method_data, method_len, METHOD_AUTHORIZE_FOR_PEER) ||
        is_method(method_data, method_len, METHOD_UNAUTHORIZE_FOR_PEER)) {
        uint8_t pubkey_number =
            getValueByLen(G_context.tx_info.transaction.method.parameters[1].data,
                          G_context.tx_info.transaction.method.parameters[1].len);
        for (uint8_t i = 0; i < pubkey_number; i++) {
            if (i > 2) {
                break;
            }
            if (i == 0) {
                memset(g_title, 0, sizeof(g_title));
                memcpy(g_title, NBGL_PEER_PUBKEY, sizeof(NBGL_PEER_PUBKEY));
                if (pubkey_number > 1) {
                    strlcat(g_title, ONE, sizeof(g_title));
                }
                memcpy(g_peer_pubkey,
                       G_context.tx_info.transaction.method.parameters[2].data,
                       G_context.tx_info.transaction.method.parameters[2].len);
                ADD_PAIR(g_title, g_peer_pubkey);
            }
            if (i == 1) {
                memset(g_title_two, 0, sizeof(g_title_two));
                memcpy(g_title_two, NBGL_PEER_PUBKEY, sizeof(NBGL_PEER_PUBKEY));
                strlcat(g_title_two, TWO, sizeof(g_title_two));
                memcpy(g_peer_pubkey_1,
                       G_context.tx_info.transaction.method.parameters[3].data,
                       G_context.tx_info.transaction.method.parameters[3].len);
                ADD_PAIR(g_title_two, g_peer_pubkey_1);
            }
            if (i == 2) {
                memset(g_title_three, 0, sizeof(g_title_three));
                memcpy(g_title_three, NBGL_PEER_PUBKEY, sizeof(NBGL_PEER_PUBKEY));
                strlcat(g_title_three, THREE, sizeof(g_title_three));
                memcpy(g_peer_pubkey_2,
                       G_context.tx_info.transaction.method.parameters[4].data,
                       G_context.tx_info.transaction.method.parameters[4].len);
                ADD_PAIR(g_title_three, g_peer_pubkey_2);
            }
        }
        if (pubkey_number > 1) {
            memset(g_pubkey_number, 0, sizeof(g_pubkey_number));
            if (!format_u64(g_pubkey_number, sizeof(g_pubkey_number), pubkey_number)) {
                return io_send_sw(SW_DISPLAY_AMOUNT_FAIL);
            }
            ADD_PAIR(NODE_AMOUNT, g_pubkey_number);
        }
    }

    if ((isCommonTx || isCommonTx1) && (!is_method(method_data, method_len, METHOD_QUIT_NODE) &&
                                        !is_method(method_data, method_len, METHOD_WITHDRAW_FEE))) {
        const char *item = NULL;
        if (is_method(method_data, method_len, METHOD_CHANGE_MAX_AUTH)) {
            item = MAX_AUTHORIZE;
        } else if (is_method(method_data, method_len, METHOD_SET_FEE_PERCENTAGE)) {
            item = PEER_COST;
        } else if ((is_method(method_data, method_len, METHOD_UNAUTHORIZE_FOR_PEER)) ||
                   (is_method(method_data, method_len, METHOD_REDUCE_INIT_POS))) {
            item = AMOUNT;
        } else if (is_method(method_data, method_len, METHOD_WITHDRAW_FEE)) {
            item = TOTAL_POS;
        } else if (is_method(method_data, method_len, METHOD_WITHDRAW)) {
            item = TOTAL_WITHDRAW;
        } else {
            item = POS;
        }
        script_hash_to_address(g_amount,
                               sizeof(g_amount),
                               G_context.tx_info.transaction.method.parameters[2].data);
        ADD_PAIR(item, g_amount);
        ADD_PAIR(ADDRESS, g_address);
    }
    /*
    if (isCommonTx && G_context.tx_type != QUIT_NODE && G_context.tx_type != WITHDRAW_FEE) {
        const char* item = NULL;
        switch (G_context.tx_type) {
            case CHANGE_MAX_AUTHORIZATION: item = MAX_AUTHORIZE; break;
            case SET_FEE_PERCENTAGE: item = PEER_COST; break;
            case WITHDRAW: item = (G_context.tx_info.pubkey_number == 1) ? AMOUNT :
    TOTAL_WITHDRAW; break; case UN_AUTHORIZE_FOR_PEER: case REDUCE_INIT_POS: item = AMOUNT; break;
            default: item = POS; break;
        }
        ADD_PAIR(item, G_context.tx_info.amount);
    }
    */
    /*
    if (G_context.tx_type == SET_FEE_PERCENTAGE) {
        ADD_PAIR(STAKE_COST, G_context.tx_info.content_two);
    }
        */
    if (is_method(method_data, method_len, METHOD_REGISTER_CANDIDATE)) {
        ADD_PAIR(STAKE_FEE, STAKE_FEE_ONG);
    }
    /*
    if (G_context.tx_type == REGISTER_CANDIDATE) {
        ADD_PAIR(STAKE_FEE, STAKE_FEE_ONG);
    }
    */
    // OEP4 and related transactions
    /*
    if (G_context.tx_type == OEP4_TRANSACTION ||
        G_context.tx_type == NEO_VM_OEP4_APPROVE ||
        G_context.tx_type == WASM_VM_OEP4_APPROVE ||
        G_context.tx_type == NEO_VM_OEP4_TRANSFER_FROM ||
        G_context.tx_type == WASM_VM_OEP4_TRANSFER_FROM) {
        if (G_context.tx_info.decimals == 0) {
            ADD_PAIR(DECIMALS, DECIMALS_UNKNOWN);
        }
    }
    */
    // Transfer and Approve transactions
    bool is_transfer_or_approve =
        is_method(method_data, method_len, METHOD_TRANSFER) ||
        is_method(method_data, method_len, METHOD_TRANSFER_FROM) ||
        is_method(method_data, method_len, METHOD_TRANSFER_V2) ||
        is_method(method_data, method_len, METHOD_TRANSFER_FROM_V2) ||
        is_method(method_data, method_len, METHOD_APPROVE) ||
        is_method(method_data, method_len, METHOD_APPROVE_V2);  // OEP4 methods simplified to base methods
    if (is_transfer_or_approve) {
        get_token_value(G_context.tx_info.transaction.method.parameters[2].len,
                        G_context.tx_info.transaction.method.parameters[2].data,
                        G_context.tx_info.transaction.contract.token_decimals,
                        g_amount,
                        sizeof(g_amount));
        bool is_ont = memcmp(G_context.tx_info.transaction.contract.addr.data, ONT_ADDR, ADDRESS_LEN) == 0;
        bool is_ong = memcmp(G_context.tx_info.transaction.contract.addr.data, ONG_ADDR, ADDRESS_LEN) == 0;
        if(is_ont) {
            strlcat(g_amount, ONT_VIEW, sizeof(g_amount));
        } else if(is_ong) {
            strlcat(g_amount, ONG_VIEW, sizeof(g_amount));
        }         
        ADD_PAIR(AMOUNT, g_amount);

        // List of methods corresponding to the second if block (transferFrom variants)
        bool is_transfer_from = is_method(method_data, method_len, METHOD_TRANSFER_FROM) ||
                                is_method(method_data, method_len, METHOD_TRANSFER_FROM_V2);

        if (is_transfer_from) {
            if (G_context.tx_info.transaction.contract.type == NATIVE_CONTRACT ||
                G_context.tx_info.transaction.contract.type == WASMVM_CONTRACT) {
                script_hash_to_address(g_address,
                                       sizeof(g_address),
                                       G_context.tx_info.transaction.method.parameters[0].data);

            } else if (G_context.tx_info.transaction.contract.type == NEOVM_CONTRACT) {
                script_hash_to_address(g_address,
                                       sizeof(g_address),
                                       G_context.tx_info.transaction.method.parameters[1].data);
            }
            ADD_PAIR(SENDER, g_address);
        }
        if (is_method(method_data, method_len, METHOD_TRANSFER) ||
            is_method(method_data, method_len, METHOD_TRANSFER_V2)) {
            if (G_context.tx_info.transaction.contract.type == NATIVE_CONTRACT ||
                G_context.tx_info.transaction.contract.type == WASMVM_CONTRACT) {
                script_hash_to_address(g_from,
                                       sizeof(g_from),
                                       G_context.tx_info.transaction.method.parameters[0].data);

                script_hash_to_address(g_to,
                                       sizeof(g_to),
                                       G_context.tx_info.transaction.method.parameters[1].data);

            } else if (G_context.tx_info.transaction.contract.type == NEOVM_CONTRACT) {
                script_hash_to_address(g_from,
                                       sizeof(g_from),
                                       G_context.tx_info.transaction.method.parameters[1].data);

                script_hash_to_address(g_to,
                                       sizeof(g_to),
                                       G_context.tx_info.transaction.method.parameters[2].data);
            }
        } else if (is_method(method_data, method_len, METHOD_TRANSFER_FROM)) {
            if (G_context.tx_info.transaction.contract.type == NATIVE_CONTRACT ||
                G_context.tx_info.transaction.contract.type == WASMVM_CONTRACT) {
                script_hash_to_address(g_from,
                                       sizeof(g_from),
                                       G_context.tx_info.transaction.method.parameters[1].data);

                script_hash_to_address(g_to,
                                       sizeof(g_to),
                                       G_context.tx_info.transaction.method.parameters[2].data);

            } else if (G_context.tx_info.transaction.contract.type == NEOVM_CONTRACT) {
                script_hash_to_address(g_from,
                                       sizeof(g_from),
                                       G_context.tx_info.transaction.method.parameters[2].data);

                script_hash_to_address(g_to,
                                       sizeof(g_to),
                                       G_context.tx_info.transaction.method.parameters[3].data);
            }
        }
        ADD_PAIR(FROM, g_from);
        ADD_PAIR(TO, g_to);
    }
    // Fee
    if (is_method(method_data, method_len, METHOD_REGISTER_CANDIDATE)) {
        ADD_PAIR(GAS_FEE, G_context.display_data.gas_fee);
    } else {
        ADD_PAIR(FEE_ONG, G_context.display_data.gas_fee);
    }
    // Signer
    ADD_PAIR(SIGNER, G_context.display_data.signer);
    return nbPairs;
}

// Public function to start the transaction review
// - Check if the app is in the right state for transaction review
// - Format the amount and address strings in g_amount and g_address buffers
// - Display the first screen of the transaction review
// - Display a warning if the transaction is blind-signed
int ui_display_transaction_bs_choice(bool is_blind_signed) {
    if (G_context.req_type != CONFIRM_TRANSACTION || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }
    if (is_blind_signed) {
        explicit_bzero(&pairList, sizeof(pairList));
        pairs[0].item = BLIND_SIGN_TX;
        pairs[0].value = BLIND_SIGNING;

        pairs[1].item = SIGNER;
        pairs[1].value = G_context.display_data.signer;

        pairList.pairs = pairs;
        pairList.nbPairs = 2;
        review_title = BLIND_SIGNING_TITLE;
        review_content = BLIND_SIGNING_CONTENT;
        nbgl_useCaseReviewBlindSigning(TYPE_TRANSACTION,
                                       &pairList,
                                       &ICON_APP_BOILERPLATE,
                                       BLIND_SIGNING_TITLE,
                                       NULL,
                                       BLIND_SIGNING_CONTENT,
                                       NULL,
                                       review_choice);
    } else {
        set_display_title_content();
        explicit_bzero(&pairList, sizeof(pairList));
        pairList.nbPairs = setTagValuePairs();
        pairList.pairs = pairs;
        nbgl_useCaseReview(TYPE_TRANSACTION,
                           &pairList,
                           &ICON_APP_BOILERPLATE,
                           review_title,
                           NULL,
                           review_content,
                           review_choice);
    }

    return 0;
}

// Flow used to display a blind-signed transaction
int ui_display_blind_signed_transaction(void) {
    return ui_display_transaction_bs_choice(true);
}

// Flow used to display a clear-signed transaction
int ui_display_transaction() {
    return ui_display_transaction_bs_choice(false);
}

#endif
