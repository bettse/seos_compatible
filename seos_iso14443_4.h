#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Block framing, as ISO 14443-4 lays it out.
 *
 * A block begins with a protocol control byte. An I-block may carry a node
 * address after it, one byte, flagged in that PCB. The command follows.
 *
 * Kept apart from the listener so the arithmetic can be checked against short
 * and malformed frames without a card in a field.
 */

/* The node address bit of a PCB. */
#define SEOS_ISO14443_4_PCB_NAD 0x08

/* Where the command starts in a received block, and how much of it there is.
 *
 * False if the frame is too short to carry the header its own PCB describes,
 * or carries a header and nothing after it. Both cases would otherwise run
 * the length backwards past zero, and a count that wrapped would be read as
 * an enormous one. */
bool seos_iso14443_4_apdu_bounds(
    const uint8_t* data,
    size_t len,
    size_t* offset,
    size_t* apdu_len);

#ifdef __cplusplus
}
#endif
