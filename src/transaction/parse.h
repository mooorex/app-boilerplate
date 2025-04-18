#pragma once

#include <stddef.h>  // size_t
#include "buffer.h"

#include "types.h"
#include "tx_types.h"

/**
 * Parse the parameters of a method according to the parameter types.
 *
 * @param[in] buf
 *   Pointer to buffer with serialized parameters.
 * @param[out] tx
 *   Pointer to transaction structure.
 * @param[in] params
 *   Array of parameter types, terminated by PARAM_END.
 * @param[out] params_num
 *   Number of parameters parsed.
 *   It is only used to check when the transaction is a neovm contract transaction.
 *   It is NOT right to use it to get the number of parameters for other types of transactions.
 *   The parameters of a neovm contract transaction are simple types, not composite types.
 * @return true if success, false otherwise.
 */
bool parse_method_params(buffer_t *buf,
                         transaction_t *tx,
                         const tx_parameter_type_e *params,
                         size_t *params_num);

/**
 * Check if the next bytes in the buffer match a constant string.
 *
 * @param[in] buf
 *   Pointer to buffer to check.
 * @param[in] str
 *   Constant string to match against.
 * @param[in] len
 *   Length of the constant string.
 * @return true if match found and buffer advanced, false otherwise.
 */
bool parse_check_constant(buffer_t *buf, const uint8_t *str, size_t len);

/**
 * Check if the next bytes in the buffer contain a specific amount.
 *
 * @param[in] buf
 *   Pointer to buffer to check.
 * @param[in] num
 *   Expected amount to match.
 * @return true if amount matches and buffer advanced, false otherwise.
 */
bool parse_check_amount(buffer_t *buf, uint64_t num);

/**
 * Parse a transfer state from the buffer.
 * A transfer state consists of a from address, to address and amount.
 *
 * @param[in] buf
 *   Pointer to buffer with serialized transfer state.
 * @param[out] transfer_state
 *   Array to store the parsed transfer state parameters.
 * @param[out] cur
 *   Current index in the parameters array, will be incremented by 3 after parsing.
 * @return true if success, false otherwise.
 */

bool parse_trasfer_state(buffer_t *buf, tx_parameter_t *transfer_state, size_t *cur);
/**
 * Parse a method name from the buffer.
 *
 * @param[in] buf
 *   Pointer to buffer with serialized method name.
 * @param[out] method_name
 *   Parameter structure to store the parsed method name.
 * @return true if success, false otherwise.
 */
bool parse_method_name(buffer_t *buf, tx_parameter_t *method_name);

/**
 * Parse an address from the buffer.
 *
 * @param[in] buf
 *   Pointer to buffer with serialized address.
 * @param[in] has_length
 *   Whether the address is prefixed with a length byte.
 * @param[out] out
 *   Parameter structure to store the parsed address.
 * @return true if success, false otherwise.
 */
bool parse_address(buffer_t *buf, bool has_length, tx_parameter_t *out);
