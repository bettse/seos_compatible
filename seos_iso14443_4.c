#include "seos_iso14443_4.h"

bool seos_iso14443_4_apdu_bounds(
    const uint8_t* data,
    size_t len,
    size_t* offset,
    size_t* apdu_len) {
    /* The PCB must be present before the rest can be interpreted. */
    if(len < 1) return false;

    size_t header_len = (data[0] & SEOS_ISO14443_4_PCB_NAD) ? 2 : 1;

    /* Compared rather than subtracted: len - header_len would underflow for a
     * frame shorter than its header. */
    if(len <= header_len) return false;

    *offset = header_len;
    *apdu_len = len - header_len;
    return true;
}

/* PCB, an optional node address, and the two checksum bytes. */
#define FRAME_OVERHEAD 4

size_t seos_iso14443_4_payload_budget(uint16_t frame_size_max) {
    if(frame_size_max <= FRAME_OVERHEAD) return 0;
    return (size_t)frame_size_max - FRAME_OVERHEAD;
}
