#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Block framing per ISO 14443-4.
 *
 * A block begins with a protocol control byte. An I-block may carry a one byte
 * node address after it, flagged in the PCB. The command follows.
 *
 * Separate from the listener so the arithmetic can be tested against short and
 * malformed frames.
 */

/* The node address bit of a PCB. */
#define SEOS_ISO14443_4_PCB_NAD 0x08

/* Reports where the command starts in a received block and how long it is.
 *
 * False if the frame is shorter than the header its PCB describes, or holds a
 * header and nothing else. Either case would underflow the remaining
 * length. */
bool seos_iso14443_4_apdu_bounds(
    const uint8_t* data,
    size_t len,
    size_t* offset,
    size_t* apdu_len);

/* Bytes of payload a frame of `frame_size_max` can carry.
 *
 * A block spends one byte on its PCB, up to one more on a node address, and
 * two on the checksum at the end. Returns 0 for a frame with no room for a
 * payload, which the caller should treat as no information. */
size_t seos_iso14443_4_payload_budget(uint16_t frame_size_max);

#ifdef __cplusplus
}
#endif
