#pragma once

#include "seos_ble_plugin.h"

/* Loading and unloading a BLE stack.
 *
 * Acquire when a scene needs one, release when it leaves. Both are idempotent,
 * and the app carries on without complaint when a plugin is missing: the
 * scene reports it and nothing asserts.
 */

/* Loads the stack for `stack`, or returns false if it is not there. */
bool seos_ble_acquire(Seos* seos, SeosBleStack stack);

/* Loads a stack able to act as a peripheral.
 *
 * The dongle is preferred when it is present, since it is the one the user
 * went to the trouble of attaching; the Flipper's own radio is the fallback.
 * Records which was taken in has_external_ble. */
bool seos_ble_acquire_peripheral(Seos* seos);

/* Starts the loaded stack in `mode`. Does nothing if none is loaded. */
void seos_ble_start(Seos* seos, FlowMode mode);

/* Stops and unloads whatever is loaded, in that order. */
void seos_ble_release(Seos* seos);

/* Whether a stack is loaded and running. */
bool seos_ble_is_loaded(Seos* seos);
