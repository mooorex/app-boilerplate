#pragma once

#include <stdbool.h>  // bool
#include "../transaction/tx_types.h"

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
#define ICON_APP_BOILERPLATE C_app_ont14px
#define ICON_APP_WARNING     C_icon_warning
#elif defined(TARGET_NANOS)
#define ICON_APP_BOILERPLATE C_app_ont16px
#define ICON_APP_WARNING     C_icon_warning
#elif defined(TARGET_STAX)
#define ICON_APP_BOILERPLATE C_app_ont32px
#define ICON_APP_WARNING     C_Warning_64px
#elif defined(TARGET_FLEX)
#define ICON_APP_BOILERPLATE C_app_ont40px
#define ICON_APP_WARNING     C_Warning_64px
#endif

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
