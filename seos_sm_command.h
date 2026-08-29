#pragma once

#include "seos_credential.h"
#include "secure_messaging.h"

/* Handling for commands that arrive inside a secure messaging session.
 *
 * Every transport carried its own copy of this, so a fix had to be made four
 * times and the copies had already drifted. There is one copy now, and it
 * reports what happened through a callback rather than reaching into the UI.
 */

/* The command header a secure message carries. */
extern const uint8_t SEOS_SM_HEADER[4];

typedef enum {
    SeosSmEventSioRequested,
} SeosSmEvent;

typedef void (*SeosSmEventCallback)(void* context, SeosSmEvent event);

/* Handles one wrapped command.
 *
 * `apdu` points at the command with any transport framing already stripped.
 * The wrapped response is appended to `tx`, status word included. Nothing is
 * Returns false when the session is finished -- a secure messaging error is
 * answered in the clear and the counters are no longer in step, so the caller
 * should drop the session.
 */
bool seos_sm_command_handle(
    SecureMessaging* secure_messaging,
    SeosCredential* credential,
    const uint8_t* apdu,
    size_t apdu_len,
    BitBuffer* tx,
    SeosSmEventCallback on_event,
    void* event_context);
