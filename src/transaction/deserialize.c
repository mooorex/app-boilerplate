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

/* the Ontology transaction format is as follows:
tx:
| Header     | payload size| payload code|   \x00   |
|--42 bytes--|--any bytes--|--any bytes--|-- 1byte--|

A. tx header:
|  Version |  tx-type |    nonce  |  gasprice |  gaslimit |    payer   |
|--1 byte--|--1 byte--|--4 bytes--|--8 bytes--|--8 bytes--|--20 bytes--|

B. payload size
If the first byte is less than 0xfd, it indicates the length of the payload.

If the first byte equals 0xfd, the next two bytes are interpreted as a uint16_t in little-endian
order to represent the payload length.

If the first byte equals 0xfe, the next four bytes are interpreted as a uint32_t in little-endian
order to represent the payload length.

If the first byte equals 0xff, the next eight bytes are interpreted as a uint64_t in little-endian
order to represent the payload length.

C. tx payload code:
Native contract
|    Params   |Method-w-Length|Contract-w-Length|\x00 + SYSCALL|len + "Ontology.Native.Invoke"|
|--any bytes--| --any bytes-- |  --21 byte--    |  --2 byte--  |         --23 byte--          |

NEOVM contract
|    Params   | Params-Count |    0xC1  |Method-w-Length|  APPCALL | Contract-wo-Length |
|--any bytes--| --any bytes--|--1 byte--| --any byte--  |--1 byte--|     --20 byte--    |

WASM contract
| Contract-wo-Length | Remaining-Length |Method-w-Length|    Params  |
|    --20 bytes--    |   --any bytes--  |--any byte--   |--any byte--|

1. The parameters of the Native Token（ONG/ONT）'s `transfer` and `TransferV2` functions

consist of multiple `transferstate` structures, followed by the count of `transferstate` structures
and a single byte `opcode_pack`. Specifically:
`transferstate transferstate ... transferstate amount c1`

2. The bytecode for parameters in other functions of the Native contract is as follows:
`00c66b param1 6a7cc8 param2 6a7cc8 param3 6a7cc8 ... 6a7cc8 6c`
Here, `param` could be an `addr`, an `amount`, a `transferstate`, a `pk`, a `pk_list`, a `num_list`,
etc.

3. The bytecode for each `transferstate` is as follows:
`00c66b addr-w-length 6a7cc8 addr-w-length 6a7cc8 amount 6c`
Here, `6a7cc8` indicates the end of each parameter.

4. Address
address in params in Native and Neovm contracts has a length as prefix.
address in params in Wasm contract has NO length as prefix.
The length of an address is 20 bytes (excluding the byte that indicates the length).

5. Amount
The amount in params in Native and Neovm contracts has an one-byte prefix.
If the first byte of the amount is between 0x51 and 0x60, i.e., the opcode is PUSHN, it indicates
that the value of this number is N. For example, if the first byte is 0x51, the amount is 1.

When the value N of the first byte of the amount is less than or equal to 8, it means the next N
bytes are interpreted as a uint64_t integer in little-endian order as the value of the amount.

Other cases are considered invalid bytecode.

In WASM contracts, the amount is 16 bytes, which is parsed as a uint128_t in little-endian order.
Similarly, there is no prefix indicating the length.




*/

#include <stdio.h>
#include <stdint.h>  // uint*_t
#include <string.h>

#include "buffer.h"

#include "deserialize.h"
#include "utils.h"
#include "types.h"
#include "macros.h"

#include "parse.h"
#include "contract.h"
#include "../globals.h"

#if defined(TEST) || defined(FUZZ)
#include "assert.h"
#define LEDGER_ASSERT(x, y) assert(x)
#else
#include "ledger_assert.h"
#endif

parser_status_e transaction_deserialize(buffer_t *buf, transaction_t *tx) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(tx != NULL, "NULL tx");

    parser_status_e status = transaction_deserialize_header(buf, tx);
    if (status != PARSING_OK) {
        return status;
    }

    status = transaction_deserialize_payload_size(buf, tx);
    if (status != PARSING_OK) {
        return status;
    }

    status = transaction_deserialize_contract(buf, tx);
    if (status != PARSING_OK) {
        return status;
    }

    status = transaction_deserialize_method(buf, tx);
    if (status != PARSING_OK) {
        return status;
    }

    status = transaction_deserialize_params(buf, tx);
    if (status != PARSING_OK) {
        return status;
    }

    size_t len = 0;
    switch (tx->contract.type) {
        case NATIVE_CONTRACT:
            len = tx->method.name.len + 1 + NATIVE_CONTRACT_CONSTANT_LENGTH;
            break;
        case NEOVM_CONTRACT:
            len = tx->method.name.len + 1 + NEOVM_CONTRACT_CONSTANT_LENGTH;
            break;
        case WASMVM_CONTRACT:
            len = 0;
            break;
        default:
            return BYTECODE_PARSING_ERROR;
    }

    return (buf->offset + len == buf->size) ? PARSING_OK : WRONG_LENGTH_ERROR;
}

parser_status_e transaction_deserialize_header(buffer_t *buf, transaction_t *tx) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(tx != NULL, "NULL tx");

    if (buf->size > MAX_TRANSACTION_LEN) {
        return WRONG_LENGTH_ERROR;
    }
    // version
    if (!buffer_read_u8(buf, &tx->header.version) || tx->header.version != 0x00) {
        return BYTECODE_PARSING_ERROR;
    }

    // tx_type
    if (!buffer_read_u8(buf, &tx->header.tx_type)) {
        return BYTECODE_PARSING_ERROR;
    }

    // nonce
    if (!buffer_read_u32(buf, &tx->header.nonce, LE)) {
        return BYTECODE_PARSING_ERROR;
    }

    // gasPrice
    if (!buffer_read_u64(buf, &tx->header.gas_price, LE) || tx->header.gas_price < GAS_PRICE_MIN) {
        return BYTECODE_PARSING_ERROR;
    }

    // gasLimit
    if (!buffer_read_u64(buf, &tx->header.gas_limit, LE) || tx->header.gas_limit < GAS_LIMIT_MIN) {
        return BYTECODE_PARSING_ERROR;
    }
    get_ong_fee(tx->header.gas_price,
                tx->header.gas_limit,
                G_context.display_data.gas_fee,
                sizeof(G_context.display_data.gas_fee));
    // payer
    tx->header.payer = (uint8_t *) (buf->ptr + buf->offset);
    if (!buffer_seek_cur(buf, ADDRESS_LEN)) {
        return BYTECODE_PARSING_ERROR;
    }

    return PARSING_OK;
}

parser_status_e transaction_deserialize_payload_size(buffer_t *buf, transaction_t *tx) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(tx != NULL, "NULL tx");

    uint8_t first_byte;
    size_t payload_size;
    if (!buffer_read_u8(buf, &first_byte)) {
        return BYTECODE_PARSING_ERROR;
    }

    switch (first_byte) {
        case 0xfd: {
            uint16_t payload_size_16;
            if (!buffer_read_u16(buf, &payload_size_16, LE)) {
                return BYTECODE_PARSING_ERROR;
            }
            payload_size = payload_size_16;
            break;
        }
        case 0xfe: {
            uint32_t payload_size_32;
            if (!buffer_read_u32(buf, &payload_size_32, LE)) {
                return BYTECODE_PARSING_ERROR;
            }
            payload_size = payload_size_32;
            break;
        }
        case 0xff: {
            uint64_t payload_size_64;
            if (!buffer_read_u64(buf, &payload_size_64, LE)) {
                return BYTECODE_PARSING_ERROR;
            }
            payload_size = payload_size_64;
            break;
        }
        default:
            payload_size = first_byte;
            break;
    }

    if (buf->offset + payload_size + ARRAY_LENGTH(OPCODE_END) != buf->size) {
        return WRONG_LENGTH_ERROR;
    }

    return PARSING_OK;
}

parser_status_e transaction_deserialize_contract(buffer_t *buf, transaction_t *tx) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(tx != NULL, "NULL tx");

    size_t os = buf->offset;
    switch (tx->header.tx_type) {
        case 0xd1:
            if (buf->ptr[buf->size - ARRAY_LENGTH(OPCODE_END) - ADDRESS_LEN - 1] !=
                OPCODE_APPCALL[0]) {  // 'n'
                tx->contract.type = NATIVE_CONTRACT;
                if ((!buffer_seek_set(buf, buf->size - NATIVE_CONTRACT_CONSTANT_LENGTH) ||
                     !parse_address(buf, true, &(tx->contract.addr)) ||
                     !parse_constant(buf, OPCODE_SYSCALL, ARRAY_LENGTH(OPCODE_SYSCALL)) ||
                     !parse_constant(buf, NATIVE_INVOKE, ARRAY_LENGTH(NATIVE_INVOKE)) ||
                     !parse_constant(buf, OPCODE_END, ARRAY_LENGTH(OPCODE_END))) ||
                    buf->offset != buf->size || !buffer_seek_set(buf, os)) {
                    return BYTECODE_PARSING_ERROR;
                }
            } else {  // OPCODE_APPCALL
                tx->contract.type = NEOVM_CONTRACT;
                if (!buffer_seek_set(buf, buf->size - NEOVM_CONTRACT_CONSTANT_LENGTH) ||
                    !parse_constant(buf, OPCODE_APPCALL, ARRAY_LENGTH(OPCODE_APPCALL)) ||
                    !parse_address(buf, false, &(tx->contract.addr)) ||
                    !parse_constant(buf, OPCODE_END, ARRAY_LENGTH(OPCODE_END)) ||
                    buf->offset != buf->size || !buffer_seek_set(buf, os)) {
                    return BYTECODE_PARSING_ERROR;
                }
            }
            break;

        case 0xd2:
            tx->contract.type = WASMVM_CONTRACT;
            if (!parse_address(buf, false, &(tx->contract.addr))) {
                return BYTECODE_PARSING_ERROR;
            }
            break;

        default:
            return BYTECODE_PARSING_ERROR;
    }
    return PARSING_OK;
}

parser_status_e transaction_deserialize_method(buffer_t *buf, transaction_t *tx) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(tx != NULL, "NULL tx");

    size_t sBegin = buf->offset;
    size_t sEnd = buf->size;
    switch (tx->contract.type) {
        case NATIVE_CONTRACT:
            sEnd = buf->size - NATIVE_CONTRACT_CONSTANT_LENGTH;
            break;
        case NEOVM_CONTRACT:
            sEnd = buf->size - NEOVM_CONTRACT_CONSTANT_LENGTH;
            break;
        case WASMVM_CONTRACT: {
            uint8_t remaining_size = 0;
            if (!buffer_read_u8(buf, &remaining_size) || remaining_size == 0 ||
                remaining_size != buf->size - buf->offset - ARRAY_LENGTH(OPCODE_END) ||
                !parse_method(buf, &(tx->method.name))) {
                return BYTECODE_PARSING_ERROR;
            }
            return PARSING_OK;
        }
        default:
            return BYTECODE_PARSING_ERROR;
    }

    // Search backward, looking for the first byte 0xc1 (for native token transfer and neo
    // contract), or the first four bytes OPCODE_PARAM_END + OPCODE_END (only for native contract)
    size_t method_intent_length = 0;
    size_t cur = 0;
    for (size_t i = sEnd - (ARRAY_LENGTH(OPCODE_PACK) - 2); i >= sBegin; i--) {  // at least 2 bytes

        // native contract, except native token transfer
        if (tx->contract.type == NATIVE_CONTRACT &&
            i <= sEnd - (ARRAY_LENGTH(OPCODE_PARAM_ST_END) - 2) &&
            memcmp(buf->ptr + i, OPCODE_PARAM_ST_END, ARRAY_LENGTH(OPCODE_PARAM_ST_END)) ==
                0) {  // 0x6a7cc86c
            cur = i + ARRAY_LENGTH(OPCODE_PARAM_ST_END);
            break;
        }

        // native token transfer, neovm contract
        if (memcmp(buf->ptr + i, OPCODE_PACK, ARRAY_LENGTH(OPCODE_PACK)) == 0) {  // 0xc1
            cur = i + ARRAY_LENGTH(OPCODE_PACK);
            break;
        }
    }

    method_intent_length = sEnd - 1 - cur;

    if (!buffer_seek_set(buf, cur) || method_intent_length == 0 ||
        !parse_method(buf, &(tx->method.name)) || tx->method.name.len != method_intent_length ||
        !buffer_seek_set(buf, sBegin)) {
        return BYTECODE_PARSING_ERROR;
    }

    return PARSING_OK;
}

parser_status_e native_transfer_deserialize_params(buffer_t *buf, transaction_t *tx) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(tx != NULL, "NULL tx");

    size_t num = 0;
    size_t cur = 0;
    while (buf->ptr[buf->offset] == OPCODE_ST_BEGIN[0]) {
        if (!parse_trasfer_state(buf, &(tx->method.parameters[cur]), &cur)) {
            return BYTECODE_PARSING_ERROR;
        }
        num++;
    }

    tx_parameter_t tmp_num;
    uint64_t out;

    if (!parse_amount(buf, &tmp_num) || !convert_bytes_to_uint64_le(&tmp_num, &out) || out != num ||
        !parse_constant(buf, OPCODE_PACK, ARRAY_LENGTH(OPCODE_PACK))) {
        return BYTECODE_PARSING_ERROR;
    }

    return PARSING_OK;
}

parser_status_e transaction_deserialize_params(buffer_t *buf, transaction_t *tx) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(tx != NULL, "NULL tx");
    // If the method is transfer or transferV2 for ONG or ONT, call
    // native_transfer_deserialize_params
    if (tx->contract.type == NATIVE_CONTRACT) {
        bool is_ont = memcmp(tx->contract.addr.data, ONT_ADDR, ADDRESS_LEN) == 0;
        bool is_ong = memcmp(tx->contract.addr.data, ONG_ADDR, ADDRESS_LEN) == 0;
        if (is_ont || is_ong) {
            bool is_transfer =
                (tx->method.name.len == strlen(METHOD_TRANSFER) &&
                 memcmp(tx->method.name.data, METHOD_TRANSFER, tx->method.name.len) == 0);
            bool is_transfer_v2 =
                (tx->method.name.len == strlen(METHOD_TRANSFER_V2) &&
                 memcmp(tx->method.name.data, METHOD_TRANSFER_V2, tx->method.name.len) == 0);
            bool is_transfer_from_v2 =
                (tx->method.name.len == strlen(METHOD_TRANSFER_FROM_V2) &&
                 memcmp(tx->method.name.data, METHOD_TRANSFER_FROM_V2, tx->method.name.len) == 0);
            bool is_approve_v2 =
                (tx->method.name.len == strlen(METHOD_APPROVE_V2) &&
                 memcmp(tx->method.name.data, METHOD_APPROVE_V2, tx->method.name.len) == 0);
            tx->contract.token_decimals = is_ont ? 0 : 9;
            if (is_transfer_v2 || is_transfer_from_v2 || is_approve_v2) {
                tx->contract.token_decimals += 9;
            }
            if (is_transfer || is_transfer_v2) {
                return native_transfer_deserialize_params(buf, tx);
            }
        }
        if (!parse_constant(buf, OPCODE_ST_BEGIN, ARRAY_LENGTH(OPCODE_ST_BEGIN))) {
            return BYTECODE_PARSING_ERROR;
        }
    }
    size_t params_num = 0;
    for (size_t i = 0; i < ARRAY_LENGTH(txPayload); i++) {
        if (memcmp(tx->contract.addr.data, txPayload[i].contract_addr, ADDRESS_LEN) == 0) {
            if (tx->contract.type != NATIVE_CONTRACT) {
                tx->contract.token_decimals = txPayload[i].token_decimals;
            }
            for (const tx_method_signature_t *methods = txPayload[i].methods; methods->name != NULL;
                 ++methods) {
                if (tx->method.name.len == strlen(methods->name) &&
                    memcmp(methods->name, (tx->method.name.data), tx->method.name.len) == 0) {
                    if (!parse_method_params(buf, tx, methods->parameters, &params_num)) {
                        return BYTECODE_PARSING_ERROR;
                    }
                    break;
                }
            }
            break;
        }
    }
    if (tx->contract.type == NATIVE_CONTRACT &&
        !parse_constant(buf, OPCODE_ST_END, ARRAY_LENGTH(OPCODE_ST_END))) {
        return BYTECODE_PARSING_ERROR;
    }
    tx_parameter_t params_num_t;
    uint64_t params_num_out;
    if (tx->contract.type == NEOVM_CONTRACT &&
        (!parse_amount(buf, &params_num_t) ||
         !convert_bytes_to_uint64_le(&params_num_t, &params_num_out) ||
         params_num != params_num_out ||
         !parse_constant(buf, OPCODE_PACK, ARRAY_LENGTH(OPCODE_PACK)))) {
        return BYTECODE_PARSING_ERROR;
    }
    if (tx->contract.type == WASMVM_CONTRACT &&
        !parse_constant(buf, OPCODE_END, ARRAY_LENGTH(OPCODE_END))) {
        return BYTECODE_PARSING_ERROR;
    }
    return PARSING_OK;
}
