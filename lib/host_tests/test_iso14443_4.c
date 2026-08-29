/* Block framing, as ISO 14443-4 lays it out.
 *
 * A block starts with a PCB. An I-block may carry a CID and a NAD after it,
 * each one byte, flagged in the PCB. What follows is the command.
 */
#include "munit.h"
#include "test_helpers.h"

#include <seos_iso14443_4.h>

/* PCB values: an I-block, and the same with the CID and NAD bits set. */
#define I_BLOCK         0x02
#define I_BLOCK_NAD     0x0a
#define I_BLOCK_CID     0x0a /* same bit position as NAD in this encoding */
#define R_BLOCK_ACK     0xa2
#define S_BLOCK_DESELCT 0xc2

static MunitResult test_plain_i_block(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    const uint8_t frame[] = {I_BLOCK, 0x00, 0xa4, 0x04, 0x00};
    size_t offset = 0;
    size_t apdu_len = 0;

    munit_assert_true(seos_iso14443_4_apdu_bounds(frame, sizeof(frame), &offset, &apdu_len));
    munit_assert_size(offset, ==, 1);
    munit_assert_size(apdu_len, ==, 4);

    return MUNIT_OK;
}

/* A NAD puts one more byte of header ahead of the command. */
static MunitResult test_i_block_with_nad(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    const uint8_t frame[] = {I_BLOCK_NAD, 0x00, 0x00, 0xa4, 0x04, 0x00};
    size_t offset = 0;
    size_t apdu_len = 0;

    munit_assert_true(seos_iso14443_4_apdu_bounds(frame, sizeof(frame), &offset, &apdu_len));
    munit_assert_size(offset, ==, 2);
    munit_assert_size(apdu_len, ==, 4);

    return MUNIT_OK;
}

/* A frame carrying only its header carries no command. Subtracting the header
 * from the length would run the count backwards past zero. */
static MunitResult test_header_only(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    size_t offset = 0;
    size_t apdu_len = 0;

    const uint8_t plain[] = {I_BLOCK};
    munit_assert_false(seos_iso14443_4_apdu_bounds(plain, sizeof(plain), &offset, &apdu_len));

    const uint8_t with_nad[] = {I_BLOCK_NAD, 0x00};
    munit_assert_false(seos_iso14443_4_apdu_bounds(with_nad, sizeof(with_nad), &offset, &apdu_len));

    return MUNIT_OK;
}

/* A frame shorter than the header its own PCB claims. A single byte naming a
 * NAD is the case that reads past the end. */
static MunitResult test_shorter_than_its_header(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    const uint8_t frame[] = {I_BLOCK_NAD};
    size_t offset = 0;
    size_t apdu_len = 0;

    munit_assert_false(seos_iso14443_4_apdu_bounds(frame, sizeof(frame), &offset, &apdu_len));

    return MUNIT_OK;
}

/* No frame at all. The PCB itself cannot be read. */
static MunitResult test_empty_frame(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    const uint8_t frame[] = {0x00};
    size_t offset = 0;
    size_t apdu_len = 0;

    munit_assert_false(seos_iso14443_4_apdu_bounds(frame, 0, &offset, &apdu_len));

    return MUNIT_OK;
}

/* Every prefix of a well-formed frame either reports bounds that stay inside
 * it, or is refused. Nothing may describe more than it was given. */
static MunitResult test_never_reports_past_the_end(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    static const uint8_t pcbs[] = {I_BLOCK, I_BLOCK_NAD, R_BLOCK_ACK, S_BLOCK_DESELCT, 0x00, 0xff};

    for(size_t i = 0; i < sizeof(pcbs); i++) {
        uint8_t frame[8];
        frame[0] = pcbs[i];
        for(size_t b = 1; b < sizeof(frame); b++) {
            frame[b] = (uint8_t)b;
        }

        for(size_t len = 0; len <= sizeof(frame); len++) {
            size_t offset = 0;
            size_t apdu_len = 0;
            if(seos_iso14443_4_apdu_bounds(frame, len, &offset, &apdu_len)) {
                munit_assert_size(offset, <=, len);
                munit_assert_size(apdu_len, <=, len - offset);
                munit_assert_size(apdu_len, >, 0);
            }
        }
    }

    return MUNIT_OK;
}

/* The advertised frame size covers the whole block, so the payload is what is
 * left after the header and the checksum. */
static MunitResult test_payload_budget(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    /* The sizes the shortest and longest useful frames work out to. */
    munit_assert_size(seos_iso14443_4_payload_budget(256), ==, 252);
    munit_assert_size(seos_iso14443_4_payload_budget(128), ==, 124);
    munit_assert_size(seos_iso14443_4_payload_budget(64), ==, 60);

    /* A frame with no room for a payload reports none. */
    munit_assert_size(seos_iso14443_4_payload_budget(4), ==, 0);
    munit_assert_size(seos_iso14443_4_payload_budget(0), ==, 0);

    return MUNIT_OK;
}

static MunitTest test_iso14443_4_cases[] = {
    {(char*)"/bounds/i-block", test_plain_i_block, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/bounds/nad", test_i_block_with_nad, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/bounds/header-only", test_header_only, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/bounds/short-header",
     test_shorter_than_its_header,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {(char*)"/bounds/empty", test_empty_frame, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/payload-budget", test_payload_budget, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/bounds/never-past-end",
     test_never_reports_past_the_end,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

MunitSuite test_iso14443_4_suite = {
    (char*)"/iso14443-4",
    test_iso14443_4_cases,
    NULL,
    1,
    MUNIT_SUITE_OPTION_NONE,
};
