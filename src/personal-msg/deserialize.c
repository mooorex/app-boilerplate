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
#include "buffer.h"

#include "deserialize.h"
#include "constants.h"
#include "types.h"
#include "../globals.h"
#include "../transaction/utils.h"

#if defined(TEST) || defined(FUZZ)
#include "assert.h"
#define LEDGER_ASSERT(x, y) assert(x)
#else
#include "ledger_assert.h"
#endif

parser_status_e personal_msg_deserialize(buffer_t *buf, personal_msg_info *info) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(info != NULL, "NULL personal msg");
    if (buf->size > MAX_PERSONAL_MSG_LEN) {
        return WRONG_LENGTH_ERROR;
    }
    // personal msg
    info->personal_msg = (uint8_t *) (buf->ptr + buf->offset);

    if (!buffer_seek_cur(buf, buf->size)) {
        return PERSONAL_MESSAGE_PARSING_ERROR;
    }

    return (buf->offset == buf->size) ? PARSING_OK : WRONG_LENGTH_ERROR;
}
