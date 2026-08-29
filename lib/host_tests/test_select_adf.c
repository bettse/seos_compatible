/* Selecting an application, from both ends.
 *
 * The card builds the answer and the reader takes it apart again, so the two
 * are checked against each other rather than against a recorded blob. The
 * refusals matter as much as the round trip: everything here is parsed out of
 * bytes a reader was handed.
 */
#include "munit.h"
#include "test_helpers.h"

#include <keys.h>
#include <seos_protocol.h>

#define BUFFER_CAPACITY 256

static SeosCredential credential_for_select(void) {
    SeosCredential credential;
    memset(&credential, 0, sizeof(credential));
    /* No saved answer, so the card builds one. */
    credential.diversifier_len = 7;
    for(size_t i = 0; i < credential.diversifier_len; i++)
        credential.diversifier[i] = (uint8_t)(0x40 + i);
    return credential;
}

/* The application list a reader offers, naming the one the keys describe. */
static size_t offer_known_application(uint8_t* out) {
    size_t len = 0;
    out[len++] = 0x06;
    out[len++] = (uint8_t)SEOS_ADF_OID_LEN;
    memcpy(out + len, SEOS_ADF_OID, SEOS_ADF_OID_LEN);
    return len + SEOS_ADF_OID_LEN;
}

/* What the card sends, with the status word a reader would see after it. */
static void card_answer(uint8_t cipher, uint8_t hash, SeosCredential* credential, BitBuffer* out) {
    AuthParameters params;
    memset(&params, 0, sizeof(params));
    params.cipher = cipher;
    params.hash = hash;

    uint8_t offer[64];
    size_t offer_len = offer_known_application(offer);

    munit_assert_true(seos_emulator_select_adf(offer, offer_len, &params, credential, out));
    bit_buffer_append_bytes(out, SEOS_SW_SUCCESS, sizeof(SEOS_SW_SUCCESS));
}

static void round_trip(uint8_t cipher, uint8_t hash) {
    SeosCredential card = credential_for_select();
    BitBuffer* answer = bit_buffer_alloc(BUFFER_CAPACITY);
    card_answer(cipher, hash, &card, answer);

    /* The answer names the cipher and digest, and carries the diversifier the
     * reader needs to work out the card's keys. */
    SeosCredential reader;
    memset(&reader, 0, sizeof(reader));
    AuthParameters params;
    memset(&params, 0, sizeof(params));

    munit_assert_true(seos_reader_select_adf_response(answer, 0, &reader, &params));
    munit_assert_uint8(params.cipher, ==, cipher);
    munit_assert_uint8(params.hash, ==, hash);
    munit_assert_size(reader.diversifier_len, ==, card.diversifier_len);
    munit_assert_memory_equal(card.diversifier_len, reader.diversifier, card.diversifier);

    bit_buffer_free(answer);
}

static MunitResult test_round_trip_aes(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    round_trip(AES_128_CBC, SHA256);
    return MUNIT_OK;
}

static MunitResult test_round_trip_des(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    round_trip(TWO_KEY_3DES_CBC_MODE, SHA1);
    return MUNIT_OK;
}

/* Two answers for the same card must differ, or the card is recognisable. */
static MunitResult test_answer_varies_des(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    SeosCredential card = credential_for_select();
    BitBuffer* first = bit_buffer_alloc(BUFFER_CAPACITY);
    BitBuffer* second = bit_buffer_alloc(BUFFER_CAPACITY);
    card_answer(TWO_KEY_3DES_CBC_MODE, SHA1, &card, first);
    card_answer(TWO_KEY_3DES_CBC_MODE, SHA1, &card, second);

    munit_assert_memory_not_equal(
        bit_buffer_get_size_bytes(first), bit_buffer_get_data(first), bit_buffer_get_data(second));

    bit_buffer_free(first);
    bit_buffer_free(second);
    return MUNIT_OK;
}

/* An application the card does not carry is not selected. */
static MunitResult test_unknown_application(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    SeosCredential card = credential_for_select();
    AuthParameters params;
    memset(&params, 0, sizeof(params));
    params.cipher = AES_128_CBC;
    params.hash = SHA256;

    uint8_t offer[] = {0x06, 0x04, 0x2b, 0x06, 0x01, 0x99};
    BitBuffer* out = bit_buffer_alloc(BUFFER_CAPACITY);
    munit_assert_false(seos_emulator_select_adf(offer, sizeof(offer), &params, &card, out));

    bit_buffer_free(out);
    return MUNIT_OK;
}

/* Answers a reader must refuse rather than parse. */
static void assert_reader_refuses(const uint8_t* raw, size_t len) {
    SeosCredential credential;
    memset(&credential, 0, sizeof(credential));
    AuthParameters params;
    memset(&params, 0, sizeof(params));

    BitBuffer* answer = bit_buffer_alloc(BUFFER_CAPACITY);
    bit_buffer_copy_bytes(answer, raw, len);
    munit_assert_false(seos_reader_select_adf_response(answer, 0, &credential, &params));
    bit_buffer_free(answer);
}

static MunitResult test_reader_refuses_malformed(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    uint8_t too_short[] = {0xcd};
    assert_reader_refuses(too_short, sizeof(too_short));

    uint8_t wrong_header[] = {0xaa, 0xbb, 0x09, 0x07, 0x85, 0x40, 0x00, 0x90, 0x00};
    assert_reader_refuses(wrong_header, sizeof(wrong_header));
    return MUNIT_OK;
}

/* An answer that decrypts to something without the expected shape is refused
 * rather than read as though it had it. */
static MunitResult test_reader_refuses_bad_contents(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    SeosCredential card = credential_for_select();
    BitBuffer* answer = bit_buffer_alloc(BUFFER_CAPACITY);
    card_answer(AES_128_CBC, SHA256, &card, answer);

    /* Disturb the initialisation vector, which changes the first block of the
     * recovered bytes, so they no longer describe an application. */
    uint8_t raw[BUFFER_CAPACITY];
    size_t len = bit_buffer_get_size_bytes(answer);
    memcpy(raw, bit_buffer_get_data(answer), len);
    raw[6] ^= 0xff;

    assert_reader_refuses(raw, len);
    bit_buffer_free(answer);
    return MUNIT_OK;
}

/* The card's answer is longer than the field a reader keeps it in only if
 * something is wrong; it must be clamped, not overrun. */
static MunitResult test_reader_clamps_long_answer(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    SeosCredential card = credential_for_select();
    BitBuffer* answer = bit_buffer_alloc(BUFFER_CAPACITY);
    card_answer(AES_128_CBC, SHA256, &card, answer);

    uint8_t raw[BUFFER_CAPACITY];
    size_t len = bit_buffer_get_size_bytes(answer);
    memcpy(raw, bit_buffer_get_data(answer), len);
    /* Pad it out well past the field that holds it. */
    memset(raw + len, 0x00, 120);
    len += 120;

    SeosCredential reader;
    memset(&reader, 0, sizeof(reader));
    AuthParameters params;
    memset(&params, 0, sizeof(params));

    BitBuffer* padded = bit_buffer_alloc(BUFFER_CAPACITY);
    bit_buffer_copy_bytes(padded, raw, len);
    /* Whatever it decides, it must not have written past the field. */
    seos_reader_select_adf_response(padded, 0, &reader, &params);

    bit_buffer_free(padded);
    bit_buffer_free(answer);
    return MUNIT_OK;
}

static MunitTest test_select_adf_cases[] = {
    {(char*)"/round-trip/aes", test_round_trip_aes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/round-trip/des", test_round_trip_des, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/varies/des", test_answer_varies_des, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/unknown-application",
     test_unknown_application,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {(char*)"/reader/malformed",
     test_reader_refuses_malformed,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {(char*)"/reader/bad-contents",
     test_reader_refuses_bad_contents,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {(char*)"/reader/long-answer",
     test_reader_clamps_long_answer,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

MunitSuite test_select_adf_suite = {
    (char*)"/select-adf",
    test_select_adf_cases,
    NULL,
    1,
    MUNIT_SUITE_OPTION_NONE,
};
