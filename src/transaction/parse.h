#pragma once


#include <stddef.h>  // size_t
#include "buffer.h"

#include "types.h"


bool convert_bytes_to_uint64_le(tx_parameter_t *amount, uint64_t *out);
bool parse_method_params(buffer_t *buf, transaction_t *tx, const tx_parameter_type_e *params, size_t *params_num);

bool parse_constant(buffer_t *buf, const uint8_t *str, size_t len);
bool parse_method(buffer_t *buf, tx_parameter_t *out); 
bool parse_address(buffer_t *buf, bool has_length, tx_parameter_t *out);
bool parse_amount(buffer_t *buf, tx_parameter_t *out) ;
bool parse_uint128(buffer_t *buf, tx_parameter_t *out) ;
bool parse_pk(buffer_t *buf, tx_parameter_t *out);
bool parse_pk_amount_pairs(buffer_t *buf, tx_parameter_t *out, size_t *cur);
bool parse_trasfer_state(buffer_t *buf, tx_parameter_t *out, size_t *cur) ;
bool parse_ont_id(buffer_t *buf, tx_parameter_t *out);


