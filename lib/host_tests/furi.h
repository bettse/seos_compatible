/* Host stand-in for the Flipper furi API.
 *
 * Covers only what the app's protocol and crypto files touch. Logging is
 * discarded; assertions abort, the way furi_check does on device.
 */
#pragma once

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef COUNT_OF
#define COUNT_OF(x) (sizeof(x) / sizeof((x)[0]))
#endif

#ifndef UNUSED
#define UNUSED(x) ((void)(x))
#endif

#ifndef MIN
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#endif

#define FURI_LOG_T(...) \
    do {                \
    } while(0)
#define FURI_LOG_D(...) \
    do {                \
    } while(0)
#define FURI_LOG_I(...) \
    do {                \
    } while(0)
#define FURI_LOG_W(...) \
    do {                \
    } while(0)
#define FURI_LOG_E(...) \
    do {                \
    } while(0)

#define furi_assert(expr) assert(expr)
#define furi_check(expr)  assert(expr)
#define furi_crash(msg)   abort()

typedef enum {
    FuriLogLevelDefault = 0,
    FuriLogLevelNone = 1,
    FuriLogLevelError = 2,
    FuriLogLevelWarn = 3,
    FuriLogLevelInfo = 4,
    FuriLogLevelDebug = 5,
    FuriLogLevelTrace = 6,
} FuriLogLevel;

/* Tests run with logging off, so the log helpers take their early exit. */
static inline FuriLogLevel furi_log_get_level(void) {
    return FuriLogLevelNone;
}
