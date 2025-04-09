#pragma once


#include <stdint.h>   // uint*_t
#include <stdbool.h>  // bool

#include "buffer.h"

int handler_sign_personal_msg(buffer_t *cdata, uint8_t chunk, bool more);
