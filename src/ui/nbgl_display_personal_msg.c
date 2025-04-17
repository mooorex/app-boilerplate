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
#include <ctype.h>
#include <string.h>  // memset

#include "os.h"
#include "glyphs.h"
#include "nbgl_use_case.h"
#include "io.h"
#include "bip32.h"
#include "format.h"

#include "display.h"
#include "../globals.h"
#include "../sw.h"
#include "action/validate.h"
#include "../menu.h"
#include "utils.h"
#include "types.h"

static char g_msg[1060];

static nbgl_layoutTagValue_t pairs[1];
static nbgl_layoutTagValueList_t pairList;

static void personal_msg_review_choice(bool confirm) {
    // Answer, display a status page and go back to main
    validate_personal_msg(confirm);
    if (confirm) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_SIGNED, ui_menu_main);
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_MESSAGE_REJECTED, ui_menu_main);
    }
}

// Public function to start the personal msg review
// - Check if the app is in the right state for personal msg review
// - Display the first screen of the personal msg review
int ui_display_personal_msg_choice() {
    if (G_context.req_type != CONFIRM_MESSAGE || G_context.state != STATE_PARSED) {
        G_context.state = STATE_NONE;
        return io_send_sw(SW_BAD_STATE);
    }

    explicit_bzero(pairs, sizeof(pairs));
    explicit_bzero(g_msg, sizeof(g_msg));

    const size_t max_copy_len = sizeof(g_msg) - 1;
    const size_t msg_len = G_context.personal_msg_info.raw_msg_len;
    const uint8_t *msg = G_context.personal_msg_info.msg_info.personal_msg;
    size_t g_msg_pos = 0;
    size_t msg_pos = 0;

    if (msg == NULL || msg_len == 0) {
        snprintf(g_msg, sizeof(g_msg), "Invalid message");
        goto display;
    }

    if (msg_len > MAX_PERSONAL_MSG_LEN) {
        snprintf(g_msg, sizeof(g_msg), "Message too long");
        goto display;
    }

    while (msg_pos < msg_len && g_msg_pos < max_copy_len) {
        int c = msg[msg_pos];
        if (isspace(c)) {
            c = ' ';
        }
        if (isprint(c)) {
            g_msg[g_msg_pos] = (char) c;
            g_msg_pos += 1;
            msg_pos += 1;
        } else {
            if (g_msg_pos + 4 <= max_copy_len) {
                static const char hex[] = "0123456789abcdef";
                g_msg[g_msg_pos + 0] = '\\';
                g_msg[g_msg_pos + 1] = 'x';
                g_msg[g_msg_pos + 2] = hex[(c >> 4) & 0xF];
                g_msg[g_msg_pos + 3] = hex[c & 0xF];
                g_msg_pos += 4;
                msg_pos += 1;
            } else {
                break;
            }
        }
    }
    g_msg[g_msg_pos] = '\0';

display:

    pairs[0].item = NBGL_MSG;
    pairs[0].value = g_msg;

    pairList.nbMaxLinesForValue = 0;
    pairList.nbPairs = 1;
    pairList.pairs = pairs;

    nbgl_useCaseReview(TYPE_MESSAGE,
                       &pairList,
                       &ICON_APP_BOILERPLATE,
                       PERSONAL_MSG_TITLE,
                       NULL,
                       PERSONAL_MSG_CONTENT,
                       personal_msg_review_choice);

    return 0;
}
// Flow used to display a clear-signed personal msg
int ui_display_personal_msg() {
    return ui_display_personal_msg_choice();
}

#endif
