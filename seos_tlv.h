#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <lib/toolbox/bit_buffer.h>

#ifdef __cplusplus
extern "C" {
#endif

/* BER-TLV data objects, encoded as ITU-T X.690 describes.
 *
 * Reading works from a buffer and a length rather than a BitBuffer, so a
 * caller can walk a message header by header without copying, and so the
 * parsing can be tested away from any transport.
 *
 * Only what this protocol uses is served: tags of one or two octets, and
 * definite lengths of up to two length octets. Anything longer is refused
 * rather than guessed at.
 */

/* Two tag octets, a length form octet, and two length octets. */
#define SEOS_TLV_HEADER_MAX 5

/* Largest value a length can describe here. */
#define SEOS_TLV_LENGTH_MAX 0xffff

typedef struct {
    uint16_t tag;
    const uint8_t* value;
    size_t value_len;
    /* Where the object sat in the buffer it was read from. A caller that
     * works in offsets -- a checksum covering everything ahead of an object,
     * say -- needs these rather than the pointer. */
    size_t header_offset;
    size_t value_offset;
} SeosTlvObject;

typedef struct {
    const uint8_t* data;
    size_t len;
    size_t offset;
} SeosTlvCursor;

void seos_tlv_cursor_init(SeosTlvCursor* cursor, const uint8_t* data, size_t len);

/* Whether the cursor has reached the end of its buffer. */
bool seos_tlv_cursor_done(const SeosTlvCursor* cursor);

/* Reads the object at the cursor and steps past its value.
 *
 * Returns false, leaving the cursor alone, if the object is malformed or runs
 * past the end of the buffer. */
bool seos_tlv_read(SeosTlvCursor* cursor, SeosTlvObject* out);

/* Reads the object at `offset` without a cursor. */
bool seos_tlv_read_at(const uint8_t* data, size_t len, size_t offset, SeosTlvObject* out);

/* Reads a bare tag, stepping `offset` past it. A tag list carries tags with
 * no lengths between them, so it needs this rather than a whole object. */
bool seos_tlv_read_tag(const uint8_t* data, size_t len, size_t* offset, uint16_t* tag);

/* Octets a length takes in its shortest form. */
size_t seos_tlv_length_size(size_t value_len);

/* Writes a tag and length into `out`, which needs SEOS_TLV_HEADER_MAX bytes,
 * and returns how much was written. Always the shortest legal form. */
size_t seos_tlv_write_header(uint8_t* out, uint16_t tag, size_t value_len);

/* Appends a whole object to a buffer. */
void seos_tlv_append(BitBuffer* out, uint16_t tag, const uint8_t* value, size_t value_len);

#ifdef __cplusplus
}
#endif
