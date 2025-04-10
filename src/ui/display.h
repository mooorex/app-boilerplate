#pragma once

#include <stdbool.h>  // bool
#include "../transaction/tx_types.h"
#include "nbgl_use_case.h"

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
#define ICON_APP_BOILERPLATE C_nanos_app_ont14px
#define ICON_APP_WARNING     C_icon_warning
#elif defined(TARGET_STAX) || defined(TARGET_FLEX)
#define ICON_APP_BOILERPLATE C_stax_app_ont32px
#define ICON_APP_WARNING     C_Warning_64px
#endif

typedef struct {
    const char *method_name;           
    const char *title;                 
    const char *content;              
    void (*param_handler)(transaction_t *tx, nbgl_contentTagValue_t *pairs, uint8_t *nbPairs);
} method_display_t;

// 通用参数解析函数
void parse_param_to_pair(transaction_t *tx, nbgl_contentTagValue_t *pair, const char *tag, 
                         tx_parameter_type_e type, uint8_t param_idx, char *buffer, size_t buffer_len);

/**
 * Callback to reuse action with approve/reject in step FLOW.
 */
typedef void (*action_validate_cb)(bool);

/**
 * Display address on the device and ask confirmation to export.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */
int ui_display_address(void);

/**
 * Display transaction information on the device and ask confirmation to sign.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */
int ui_display_transaction(void);
/**
 * Display personal msg information on the device and ask confirmation to sign.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */
int ui_display_personal_msg(void);
/**
 * Display blind-sign transaction information on the device and ask confirmation to sign.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */
int ui_display_blind_signed_transaction(void);
