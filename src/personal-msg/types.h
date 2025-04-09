#pragma once

#include <stddef.h>  // size_t
#include <stdint.h>  // uint*_t

static const char SIGN_MAGIC[] =
    "\x19"
    "Ontology Signed Message:\n";

typedef struct {
    uint8_t  *personal_msg;       /// personal_msg (variable length)
} personal_msg_info;