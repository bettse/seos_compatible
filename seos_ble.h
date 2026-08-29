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

/* Starts the loaded stack in `mode`. Does nothing if none is loaded. */
void seos_ble_start(Seos* seos, FlowMode mode);

/* Stops and unloads whatever is loaded, in that order. */
void seos_ble_release(Seos* seos);

/* Whether a stack is loaded and running. */
bool seos_ble_is_loaded(Seos* seos);
