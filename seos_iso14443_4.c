#include "seos_iso14443_4.h"

bool seos_iso14443_4_apdu_bounds(
    const uint8_t* data,
    size_t len,
    size_t* offset,
    size_t* apdu_len) {
    /* The PCB has to be there before anything can be said about the rest. */
    if(len < 1) return false;

    size_t header_len = (data[0] & SEOS_ISO14443_4_PCB_NAD) ? 2 : 1;

    /* Compared rather than subtracted: a frame shorter than its header would
     * turn the remainder into a very large count. */
    if(len <= header_len) return false;

    *offset = header_len;
    *apdu_len = len - header_len;
    return true;
}
