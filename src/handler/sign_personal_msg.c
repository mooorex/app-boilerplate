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

#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool
#include <stddef.h>   // size_t
#include <string.h>   // memset, explicit_bzero

#include "os.h"
#include "cx.h"
#include "../sw.h"
#include "../globals.h"
#include "../ui/display.h"
#include "sign_personal_msg.h"
#include "../personal-msg/deserialize.h"
#include "../personal-msg/types.h"
#include "../transaction/utils.h"


#ifdef TARGET_NANOS
#define SHARED_CTX_FIELD_1_SIZE 100
#else
#ifdef SCREEN_SIZE_WALLET
#define SHARED_CTX_FIELD_1_SIZE 380
#else
#define SHARED_CTX_FIELD_1_SIZE 256
#endif
#endif
#define SHARED_CTX_FIELD_2_SIZE 4

typedef struct strDataTmp_s {
    char tmp[SHARED_CTX_FIELD_1_SIZE];
    char tmp2[SHARED_CTX_FIELD_2_SIZE];
} strDataTmp_t;

typedef union {
    strDataTmp_t tmp;
} strings_t;

cx_sha256_t global_sha256;
strings_t strings;

int handler_sign_personal_msg(buffer_t *cdata, uint8_t chunk, bool more) {
    if (chunk == 0) {  // first APDU, parse BIP32 path
        explicit_bzero(&G_context, sizeof(G_context));
        G_context.req_type = CONFIRM_MESSAGE;
        G_context.state = STATE_NONE;

        if (!buffer_read_u8(cdata, &G_context.bip32_path_len) ||
            !buffer_read_bip32_path(cdata,
                                    G_context.bip32_path,
                                    (size_t) G_context.bip32_path_len)) {
            return io_send_sw(SW_WRONG_DATA_LENGTH);
        }
        if (!ont_address_from_pubkey(G_context.display_data.signer,sizeof(G_context.display_data.signer))) {
            return io_send_sw(SW_DISPLAY_ADDRESS_FAIL);
        }
        return io_send_sw(SW_OK);
    } else {
        if (G_context.req_type != CONFIRM_MESSAGE) {
            return io_send_sw(SW_BAD_STATE);
        }
        if (G_context.personal_msg_info.raw_msg_len + cdata->size > sizeof(G_context.personal_msg_info.raw_msg)) {
            return io_send_sw(SW_WRONG_PERSONAL_MSG_LENGTH);
        }
        if (!buffer_move(cdata,
                         G_context.personal_msg_info.raw_msg + G_context.personal_msg_info.raw_msg_len,
                         cdata->size)) {
            return io_send_sw(SW_PERSONAL_MSG_PARSING_FAIL);
        }
        G_context.personal_msg_info.raw_msg_len += cdata->size;
        if (more) {
            // more APDUs with transaction part are expected.
            // Send a SW_OK to signal that we have received the chunk
            return io_send_sw(SW_OK);

        } else {
            // last APDU for this transaction, let's parse, display and request a sign confirmation

            buffer_t buf = {.ptr = G_context.personal_msg_info.raw_msg,
                .size = G_context.personal_msg_info.raw_msg_len,
                .offset = 0};

            parser_status_e status = personal_msg_deserialize(&buf, &G_context.personal_msg_info.msg_info);
            PRINTF("Parsing status: %d.\n", status);
            if (status != PARSING_OK) {
                return io_send_sw(SW_PERSONAL_MSG_PARSING_FAIL);
            }

            G_context.state = STATE_PARSED;
            cx_err_t error = CX_INTERNAL_ERROR;

            // Initialize message header + length
            cx_sha256_init(&global_sha256);

            CX_CHECK(cx_hash_no_throw((cx_hash_t *) &global_sha256,
                                      0,
                                      (uint8_t *) SIGN_MAGIC,
                                      sizeof(SIGN_MAGIC) - 1,
                                      NULL,
                                      0));

            snprintf(strings.tmp.tmp2,
                     sizeof(strings.tmp.tmp2),
                     "%u",
                     G_context.personal_msg_info.raw_msg_len);

            CX_CHECK(cx_hash_no_throw((cx_hash_t *) &global_sha256,
                                      0,
                                      (uint8_t *) strings.tmp.tmp2,
                                      strlen(strings.tmp.tmp2),
                                      NULL,
                                      0));
            CX_CHECK(cx_hash_no_throw((cx_hash_t *) &global_sha256,
                                      0,
                                      G_context.personal_msg_info.raw_msg,
                                      G_context.personal_msg_info.raw_msg_len,
                                      NULL,
                                      0));

            CX_CHECK(cx_hash_no_throw((cx_hash_t *) &global_sha256,
                                      CX_LAST,
                                      NULL,
                                      0,
                                      G_context.personal_msg_info.m_hash,
                                      32));

            PRINTF("Hash: %.*H\n", sizeof(G_context.personal_msg_info.m_hash), G_context.personal_msg_info.m_hash);
            return ui_display_personal_msg();
        end:
            return io_send_sw(error);
        }
    }
    return 0;
}