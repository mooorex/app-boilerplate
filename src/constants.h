#pragma once

/**
 * Instruction class of the Boilerplate application.
 */
#define CLA 0x80

/**
 * Length of APPNAME variable in the Makefile.
 */
#define APPNAME_LEN (sizeof(APPNAME) - 1)

/**
 * Maximum length of MAJOR_VERSION || MINOR_VERSION || PATCH_VERSION.
 */
#define APPVERSION_LEN 3

/**
 * Maximum length of application name.
 */
#define MAX_APPNAME_LEN 64

/**
 * Maximum transaction length (bytes).
 */
#if defined(TARGET_STAX) || defined(TARGET_FLEX)
#define MAX_TRANSACTION_LEN 1024 * 6
#elif defined(TARGET_NANOX) || defined(TARGET_NANOS2)
#define MAX_TRANSACTION_LEN 1024 * 4
#else
#error "No target device defined (TARGET_STAX, TARGET_FLEX, TARGET_NANOX, TARGET_NANOS2)"
#endif
/**
 * Maximum personal message length (bytes).
 */
#define MAX_PERSONAL_MSG_LEN 1024
/**
 * Maximum signature length (bytes).
 */
#define MAX_DER_SIG_LEN 72
