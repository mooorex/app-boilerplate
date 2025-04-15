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
#include "../transaction/utils.h"

static char g_address[40];

static void review_choice(bool confirm) {
    // Answer, display a status page and go back to main
    validate_pubkey(confirm);
    if (confirm) {
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_VERIFIED, ui_menu_main);
    } else {
        nbgl_useCaseReviewStatus(STATUS_TYPE_ADDRESS_REJECTED, ui_menu_main);
    }
}

int ui_display_address() {
        if (G_context.req_type != CONFIRM_ADDRESS || G_context.state != STATE_NONE) {
            G_context.state = STATE_NONE;
            return io_send_sw(SW_BAD_STATE);
        }
    
        memset(g_address, 0, sizeof(g_address));
        if (!convert_uncompressed_pubkey_to_address(G_context.pk_info.raw_public_key, g_address, sizeof(g_address))) {
            return io_send_sw(SW_DISPLAY_ADDRESS_FAIL);
        }
        nbgl_useCaseAddressReview(g_address,
                                  NULL,
                                  &ICON_APP_BOILERPLATE,
                                  VERIFY_ONT_ADDRESS,
                                  NULL,
                                  review_choice);
        return 0;
}

#endif
