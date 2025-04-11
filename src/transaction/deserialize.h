#pragma once

#include "buffer.h"

#include "types.h"
#include "tx_types.h"

/**
 * Deserialize raw transaction in structure.
 *
 * @param[in, out] buf
 *   Pointer to buffer with serialized transaction.
 * @param[out]     tx
 *   Pointer to transaction structure.
 *
 * @return PARSING_OK if success, error status otherwise.
 *
 */
parser_status_e transaction_deserialize(buffer_t *buf, transaction_t *tx);
/**
 * Deserialize transaction header.
 *
 * @param[in, out] buf
 *   Pointer to buffer with serialized transaction.
 * @param[out]     tx
 *   Pointer to transaction structure.
 *
 * @return PARSING_OK if success, error status otherwise.
 *
 */
parser_status_e transaction_deserialize_header(buffer_t *buf, transaction_t *tx);
/**
 * Deserialize transaction payload size.
 *
 * @param[in, out] buf
 *   Pointer to buffer with serialized transaction.
 * @param[out]     tx
 *   Pointer to transaction structure.
 *
 * @return PARSING_OK if success, error status otherwise.
 *
 */
parser_status_e transaction_deserialize_payload_size(buffer_t *buf, transaction_t *tx);
/**
 * Deserialize transaction contract name and type.
 *
 * @param[in, out] buf
 *   Pointer to buffer with serialized transaction.
 * @param[out]     tx
 *   Pointer to transaction structure.
 *
 * @return PARSING_OK if success, error status otherwise.
 *
 */
parser_status_e transaction_deserialize_contract(buffer_t *buf,
                                                               transaction_t *tx);
/**
 * Deserialize transaction method.
 *
 * @param[in, out] buf
 *   Pointer to buffer with serialized transaction.
 * @param[out]     tx
 *   Pointer to transaction structure.
 *
 * @return PARSING_OK if success, error status otherwise.
 *
 */
parser_status_e transaction_deserialize_method(buffer_t *buf,
                                                      transaction_t *tx);

parser_status_e native_transfer_deserialize_params(buffer_t *buf,
                                                   transaction_t *tx);

parser_status_e transaction_deserialize_params(buffer_t *buf,
                                                      transaction_t *tx);

parser_status_e wasmvm_transaction_deserialize_method(buffer_t *buf,
                                          transaction_t *tx);