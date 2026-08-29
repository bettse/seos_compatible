#include <furi_hal.h>

#define SEOS_HOST_RANDOM_MAX 256

static uint8_t queue[SEOS_HOST_RANDOM_MAX];
static size_t queue_len;
static size_t queue_offset;

void seos_host_clear_random(void) {
    queue_len = 0;
    queue_offset = 0;
}

void seos_host_set_random(const uint8_t* data, size_t len) {
    /* Injections accumulate: a test may queue the octets for one exchange while
     * those for an earlier one are still unread. */
    size_t remaining = queue_len - queue_offset;
    if(queue_offset > 0 && remaining > 0) {
        memmove(queue, queue + queue_offset, remaining);
    }
    queue_offset = 0;
    queue_len = remaining;

    size_t room = sizeof(queue) - remaining;
    if(len > room) len = room;
    memcpy(queue + remaining, data, len);
    queue_len += len;
}

size_t seos_host_random_remaining(void) {
    return queue_len - queue_offset;
}

void furi_hal_random_fill_buf(uint8_t* buf, uint32_t len) {
    size_t remaining = queue_len - queue_offset;
    size_t taken = len < remaining ? len : remaining;
    memcpy(buf, queue + queue_offset, taken);
    queue_offset += taken;

    /* Short of queued octets, fall back to a counting ramp so an unscripted
     * session is still reproducible. */
    for(size_t i = taken; i < len; i++) {
        buf[i] = (uint8_t)i;
    }
}
