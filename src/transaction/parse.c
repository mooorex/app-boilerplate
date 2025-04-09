#include "parse.h"
#include "tx_types.h"
#include "utils.h"
#include "types.h"
#include "string.h"
#include "macros.h"
#include "contract.h"

#if defined(TEST) || defined(FUZZ)
#include "assert.h"
#define LEDGER_ASSERT(x, y) assert(x)
#else
#include "ledger_assert.h"
#endif

bool parse_constant(buffer_t *buf, const uint8_t *str, size_t len) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(str != NULL, "NULL str");
    LEDGER_ASSERT(len > 0, "len is 0");

    return buffer_can_read(buf, len) && memcmp(buf->ptr + buf->offset, str, len) == 0 &&
           buffer_seek_cur(buf, len);
}

bool parse_method(buffer_t *buf, tx_parameter_t *out) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(out != NULL, "NULL out");

    uint8_t size = 0;
    if (!buffer_read_u8(buf, &size) || size == 0 || !buffer_can_read(buf, size)) {
        return false;
    }

    out->len = size;
    out->data = (uint8_t*)(buf->ptr + buf->offset);

    return buffer_seek_cur(buf, size);
}

bool parse_address(buffer_t *buf, bool has_length, tx_parameter_t *out) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(out != NULL, "NULL out");

    size_t prefix_len = has_length ? 1 : 0;
    uint8_t size = 0;

    if (!buffer_can_read(buf, ADDRESS_LEN + prefix_len) ||
        (has_length && (!buffer_read_u8(buf, &size) || size != ADDRESS_LEN))) {
        return false;
    }

    out->len = ADDRESS_LEN;
    out->data = (uint8_t*)(buf->ptr + buf->offset);
    out->type = PARAM_ADDR;

    return buffer_seek_cur(buf, ADDRESS_LEN);
}

bool parse_amount(buffer_t *buf, tx_parameter_t *out) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(out != NULL, "NULL out");

    uint8_t amt = 0;
    bool stepping = true;
    if (!buffer_read_u8(buf, &amt) || amt == 0) {
        return false;
    }

    if (amt > OPCODE_PUSH_NUMBER && amt <= OPCODE_PUSH_NUMBER + 16) {
        amt = 1;
        stepping = false;
    } else if (amt > 2 * sizeof(uint64_t)) {
        return false;
    }

    out->len = amt;
    PRINTF("parse_amount: amt=%d\n", amt);
    out->data = (uint8_t*)(buf->ptr + buf->offset - 1);
    out->type = PARAM_AMOUNT;

    return !stepping || buffer_seek_cur(buf, out->len);
}

bool parse_uint128(buffer_t *buf, tx_parameter_t *out) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(out != NULL, "NULL out");

    const uint8_t size = 16;
    if (!buffer_can_read(buf, size)) {
        return false;
    }

    out->len = size;
    out->data = (uint8_t*)(buf->ptr + buf->offset);
    out->type = PARAM_UINT128;

    return buffer_seek_cur(buf, size);
}

bool parse_pk(buffer_t *buf, tx_parameter_t *out) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(out != NULL, "NULL out");

    uint8_t size = 0;
    if (!buffer_read_u8(buf, &size) || size != PK_LEN || !buffer_can_read(buf, PK_LEN)) {
        return false;
    }

    out->len = size;
    out->data = (uint8_t*)(buf->ptr + buf->offset);
    out->type = PARAM_PUBKEY;

    return buffer_seek_cur(buf, size);
}

bool parse_ont_id(buffer_t *buf) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");

    uint8_t size = 0;
    return buffer_read_u8(buf, &size) && size != 0 && !buffer_seek_cur(buf, size);
}

bool parse_pk_amount_pairs(buffer_t *buf, tx_parameter_t *pairs, size_t *cur) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(pairs != NULL, "NULL pairs");
    LEDGER_ASSERT(cur != NULL, "NULL cur");

    uint64_t pks_num = 0;
    uint64_t amts_num = 0;

    if (!parse_amount(buf, &pairs[0]) || !convert_bytes_to_uint64_le(&pairs[0], &pks_num) ||
        pks_num == 0 || !parse_constant(buf, OPCODE_PARAM_END, ARRAY_LENGTH(OPCODE_PARAM_END))) {
        return false;
    }

    for (size_t i = 1; i <= pks_num; i++) {
        if (!parse_pk(buf, &pairs[i]) ||
            !parse_constant(buf, OPCODE_PARAM_END, ARRAY_LENGTH(OPCODE_PARAM_END))) {
            return false;
        }
    }

    if (!parse_amount(buf, &pairs[pks_num + 1]) ||
        !convert_bytes_to_uint64_le(&pairs[pks_num + 1], &amts_num) || pks_num != amts_num ||
        !parse_constant(buf, OPCODE_PARAM_END, ARRAY_LENGTH(OPCODE_PARAM_END))) {
        return false;
    }

    for (size_t i = 1; i <= amts_num; i++) {
        if (!parse_amount(buf, &pairs[pks_num + 1 + i]) ||
            (i != amts_num &&
             !parse_constant(buf, OPCODE_PARAM_END, ARRAY_LENGTH(OPCODE_PARAM_END)))) {
            return false;
        }
    }

    *cur += (pks_num * 2 + 2);
    return true;
}

bool parse_trasfer_state(buffer_t *buf, tx_parameter_t *transfer_state, size_t *cur) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(transfer_state != NULL, "NULL transfer_state");
    LEDGER_ASSERT(cur != NULL, "NULL cur");

    if (!parse_constant(buf, OPCODE_ST_BEGIN, ARRAY_LENGTH(OPCODE_ST_BEGIN)) ||
        !parse_address(buf, true, &transfer_state[0]) ||
        !parse_constant(buf, OPCODE_PARAM_END, ARRAY_LENGTH(OPCODE_PARAM_END)) ||
        !parse_address(buf, true, &transfer_state[1]) ||
        !parse_constant(buf, OPCODE_PARAM_END, ARRAY_LENGTH(OPCODE_PARAM_END)) ||
        !parse_amount(buf, &transfer_state[2]) ||
        !parse_constant(buf, OPCODE_PARAM_END, ARRAY_LENGTH(OPCODE_PARAM_END)) ||
        !parse_constant(buf, OPCODE_ST_END, ARRAY_LENGTH(OPCODE_ST_END))) {
        return false;
    }

    *cur += 3;
    return true;
}

bool parse_method_params(buffer_t *buf,
                        transaction_t *tx,
                        const tx_parameter_type_e *params,
                        size_t *params_num) {
    LEDGER_ASSERT(buf != NULL, "NULL buf");
    LEDGER_ASSERT(tx != NULL, "NULL tx");
    LEDGER_ASSERT(params != NULL, "NULL params");
    LEDGER_ASSERT(params_num != NULL, "NULL params_num");

    size_t cur = 0;
    *params_num = 0;

    for (; *params != PARAM_END; ++params) {
        (*params_num)++;
        switch (*params) {
            case PARAM_ADDR:
                if (!parse_address(buf,
                                   tx->contract.type != WASMVM_CONTRACT,
                                   &(tx->method.parameters[cur++]))) {
                    return false;
                }
                break;
            case PARAM_AMOUNT:
                if (!parse_amount(buf, &(tx->method.parameters[cur++]))) {
                    return false;
                }
                break;
            case PARAM_UINT128:
                if (!parse_uint128(buf, &(tx->method.parameters[cur++]))) {
                    return false;
                }
                break;
            case PARAM_PUBKEY:
                if (!parse_pk(buf, &(tx->method.parameters[cur++]))) {
                    return false;
                }
                break;
            case PARAM_PK_AMOUNT_PAIRS:
                if (!parse_pk_amount_pairs(buf, &(tx->method.parameters[cur]), &cur)) {
                    return false;
                }
                break;
            case PARAM_TRANSFER_STATE:
                if (!parse_trasfer_state(buf, &(tx->method.parameters[cur]), &cur)) {
                    return false;
                }
                break;
            case PARAM_ONTID:
                if (!parse_ont_id(buf)) {
                    return false;
                }
                break;
            default:
                return false;
        }

        if (tx->contract.type == NATIVE_CONTRACT &&
            !parse_constant(buf, OPCODE_PARAM_END, ARRAY_LENGTH(OPCODE_PARAM_END))) {
            return false;
        }
    }

    return true;
}

bool convert_bytes_to_uint64_le(tx_parameter_t *amount, uint64_t *out) {
    LEDGER_ASSERT(amount != NULL, "NULL amount");
    LEDGER_ASSERT(out != NULL, "NULL out");

    if (amount->len > sizeof(uint64_t) || amount->len == 0) {
        return false;
    }

    *out = 0;
    uint8_t amt = amount->data[0];

    if (amt > OPCODE_PUSH_NUMBER && amt <= OPCODE_PUSH_NUMBER + 16) {
        *out = amt - OPCODE_PUSH_NUMBER;
        return true;
    }

    for (size_t i = 1; i <= amount->len; i++) {
        *out |= ((uint64_t)amount->data[i] << (8 * i));
    }

    return true;
}