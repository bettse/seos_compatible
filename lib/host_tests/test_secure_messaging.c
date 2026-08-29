/* Secure messaging wrap and unwrap.
 *
 * The wrap and unwrap pairs are meant to be exact inverses, so most cases run
 * a message through both. The rest feed malformed messages to unwrap and check
 * it refuses them rather than reading past the buffer.
 */
#include "munit.h"
#include "test_helpers.h"

#include <secure_messaging.h>

#define RX_CAPACITY 256

static AuthParameters test_params(uint8_t cipher, uint8_t hash) {
    AuthParameters params;
    memset(&params, 0, sizeof(params));
    params.cipher = cipher;
    params.hash = hash;
    for(size_t i = 0; i < sizeof(params.rndICC); i++)
        params.rndICC[i] = (uint8_t)(0x10 + i);
    for(size_t i = 0; i < sizeof(params.UID); i++)
        params.UID[i] = (uint8_t)(0x20 + i);
    for(size_t i = 0; i < sizeof(params.cNonce); i++)
        params.cNonce[i] = (uint8_t)(0x30 + i);
    for(size_t i = 0; i < sizeof(params.rNonce); i++)
        params.rNonce[i] = (uint8_t)(0x40 + i);
    return params;
}

static SecureMessaging* session(uint8_t cipher, uint8_t hash) {
    AuthParameters params = test_params(cipher, hash);
    SecureMessaging* sm = secure_messaging_alloc(&params);
    munit_assert_not_null(sm);
    return sm;
}

/* A command wrapped by one side must unwrap to the same plaintext on the
 * other. Both sides start from the same counter, so both advance in step. */
static void round_trip_command(uint8_t cipher, uint8_t hash, size_t message_len) {
    SecureMessaging* sender = session(cipher, hash);
    SecureMessaging* receiver = session(cipher, hash);

    uint8_t header[] = {0x0c, 0xcb, 0x3f, 0xff};
    uint8_t message[SECURE_MESSAGING_MAX_SIZE];
    for(size_t i = 0; i < message_len; i++)
        message[i] = (uint8_t)(i * 7 + 1);

    BitBuffer* buffer = bit_buffer_alloc(RX_CAPACITY);
    munit_assert_true(
        secure_messaging_wrap_apdu(sender, message, message_len, header, sizeof(header), buffer));

    /* The transmitted APDU carries a trailing Le the receiver does not see as
     * part of the body, but unwrap must tolerate it. */
    munit_assert_size(bit_buffer_get_size_bytes(buffer), >, message_len);

    munit_assert_true(secure_messaging_unwrap_apdu(receiver, buffer));
    munit_assert_size(bit_buffer_get_size_bytes(buffer), ==, message_len);
    munit_assert_memory_equal(message_len, bit_buffer_get_data(buffer), message);

    bit_buffer_free(buffer);
    secure_messaging_free(sender);
    secure_messaging_free(receiver);
}

static void round_trip_response(uint8_t cipher, uint8_t hash, size_t message_len) {
    SecureMessaging* sender = session(cipher, hash);
    SecureMessaging* receiver = session(cipher, hash);

    uint8_t message[SECURE_MESSAGING_MAX_SIZE];
    for(size_t i = 0; i < message_len; i++)
        message[i] = (uint8_t)(i * 3 + 9);

    BitBuffer* buffer = bit_buffer_alloc(RX_CAPACITY);
    munit_assert_true(secure_messaging_wrap_rapdu(sender, message, message_len, buffer));
    munit_assert_true(secure_messaging_unwrap_rapdu(receiver, buffer));
    munit_assert_size(bit_buffer_get_size_bytes(buffer), ==, message_len);
    munit_assert_memory_equal(message_len, bit_buffer_get_data(buffer), message);

    bit_buffer_free(buffer);
    secure_messaging_free(sender);
    secure_messaging_free(receiver);
}

static MunitResult test_round_trip_aes(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    round_trip_command(AES_128_CBC, SHA256, 4);
    round_trip_response(AES_128_CBC, SHA256, 4);
    return MUNIT_OK;
}

static MunitResult test_round_trip_des(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    round_trip_command(TWO_KEY_3DES_CBC_MODE, SHA1, 4);
    round_trip_response(TWO_KEY_3DES_CBC_MODE, SHA1, 4);
    return MUNIT_OK;
}

/* A message that is already a whole number of blocks still needs a pad byte,
 * so it must grow by a full block rather than losing the 0x80. */
static MunitResult test_exact_block_multiple(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    for(size_t len = 8; len <= 64; len += 8) {
        round_trip_command(TWO_KEY_3DES_CBC_MODE, SHA1, len);
        round_trip_response(TWO_KEY_3DES_CBC_MODE, SHA1, len);
    }
    for(size_t len = 16; len <= 64; len += 16) {
        round_trip_command(AES_128_CBC, SHA256, len);
        round_trip_response(AES_128_CBC, SHA256, len);
    }
    return MUNIT_OK;
}

/* Every length up to the limit, to catch off-by-one padding. */
static MunitResult test_all_lengths(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    for(size_t len = 0; len < SECURE_MESSAGING_MAX_SIZE; len++) {
        round_trip_response(AES_128_CBC, SHA256, len);
    }
    return MUNIT_OK;
}

/* Above 127 the cryptogram length needs the long form. */
static MunitResult test_long_form_length(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    SecureMessaging* sender = session(AES_128_CBC, SHA256);
    uint8_t message[120];
    memset(message, 0xa5, sizeof(message));

    BitBuffer* buffer = bit_buffer_alloc(RX_CAPACITY);
    munit_assert_true(secure_messaging_wrap_rapdu(sender, message, sizeof(message), buffer));

    /* 120 bytes plus a pad block is 128, which must be written as 81 80. */
    munit_assert_uint8(bit_buffer_get_byte(buffer, 0), ==, 0x85);
    munit_assert_uint8(bit_buffer_get_byte(buffer, 1), ==, 0x81);
    munit_assert_uint8(bit_buffer_get_byte(buffer, 2), ==, 0x80);

    SecureMessaging* receiver = session(AES_128_CBC, SHA256);
    munit_assert_true(secure_messaging_unwrap_rapdu(receiver, buffer));
    munit_assert_size(bit_buffer_get_size_bytes(buffer), ==, sizeof(message));
    munit_assert_memory_equal(sizeof(message), bit_buffer_get_data(buffer), message);

    bit_buffer_free(buffer);
    secure_messaging_free(sender);
    secure_messaging_free(receiver);
    return MUNIT_OK;
}

/* A message with no room for the pad byte must be refused, not written one
 * past the plaintext buffer. */
static MunitResult test_rejects_oversized_message(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    SecureMessaging* sm = session(AES_128_CBC, SHA256);
    uint8_t message[SECURE_MESSAGING_MAX_SIZE];
    memset(message, 0x11, sizeof(message));

    BitBuffer* buffer = bit_buffer_alloc(RX_CAPACITY);
    munit_assert_false(secure_messaging_wrap_rapdu(sm, message, sizeof(message), buffer));
    munit_assert_size(bit_buffer_get_size_bytes(buffer), ==, 0);

    bit_buffer_free(buffer);
    secure_messaging_free(sm);
    return MUNIT_OK;
}

/* Feeds unwrap a message built from hex and checks it is refused. */
static void assert_rejected(const char* hex, size_t offset) {
    SecureMessaging* sm = session(AES_128_CBC, SHA256);
    uint8_t raw[RX_CAPACITY];
    size_t len = hex_to_bytes(hex, raw, sizeof(raw));

    BitBuffer* buffer = bit_buffer_alloc(RX_CAPACITY);
    bit_buffer_copy_bytes(buffer, raw, len);

    bool accepted = offset == SECURE_MESSAGING_CAPDU_BODY_OFFSET ?
                        secure_messaging_unwrap_apdu(sm, buffer) :
                        secure_messaging_unwrap_rapdu(sm, buffer);
    munit_assert_false(accepted);

    /* Refusal must leave the buffer as it was, so a caller cannot mistake the
     * still-wrapped bytes for plaintext of the length it expected. */
    munit_assert_size(bit_buffer_get_size_bytes(buffer), ==, len);

    bit_buffer_free(buffer);
    secure_messaging_free(sm);
}

static MunitResult test_rejects_malformed(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    /* Empty, and shorter than a tag plus length. */
    assert_rejected("85", SECURE_MESSAGING_RAPDU_BODY_OFFSET);
    /* Wrong tag where the cryptogram should be. */
    assert_rejected("87100102030405060708090a0b0c0d0e0f10", SECURE_MESSAGING_RAPDU_BODY_OFFSET);
    /* Zero length. */
    assert_rejected("8500", SECURE_MESSAGING_RAPDU_BODY_OFFSET);
    /* Length not a whole number of blocks. */
    assert_rejected("85080102030405060708", SECURE_MESSAGING_RAPDU_BODY_OFFSET);
    /* Length runs past the end of the message. */
    assert_rejected("85400102030405060708", SECURE_MESSAGING_RAPDU_BODY_OFFSET);
    /* Long form with no length octet. */
    assert_rejected("8581", SECURE_MESSAGING_RAPDU_BODY_OFFSET);
    /* Indefinite and multi-octet forms are not used here. */
    assert_rejected("8582010001020304", SECURE_MESSAGING_RAPDU_BODY_OFFSET);
    /* A command too short to hold a cryptogram after its header. */
    assert_rejected("0ccb3fff00", SECURE_MESSAGING_CAPDU_BODY_OFFSET);
    return MUNIT_OK;
}

/* Ciphertext that decrypts to something without valid padding is a wrong key
 * or a tampered message, and must not be handed back as plaintext. */
static MunitResult test_rejects_bad_padding(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    SecureMessaging* sender = session(AES_128_CBC, SHA256);
    SecureMessaging* wrong_key = session(TWO_KEY_3DES_CBC_MODE, SHA1);
    wrong_key->cipher = AES_128_CBC;

    uint8_t message[] = {0x5c, 0x02, 0xff, 0x00};
    BitBuffer* buffer = bit_buffer_alloc(RX_CAPACITY);
    munit_assert_true(secure_messaging_wrap_rapdu(sender, message, sizeof(message), buffer));
    munit_assert_false(secure_messaging_unwrap_rapdu(wrong_key, buffer));

    bit_buffer_free(buffer);
    secure_messaging_free(sender);
    secure_messaging_free(wrong_key);
    return MUNIT_OK;
}

/* The sequence counter is big endian and must carry across byte boundaries. */
static MunitResult test_counter_carries(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    SecureMessaging* sm = session(AES_128_CBC, SHA256);
    memset(sm->aesContext, 0, sizeof(sm->aesContext));
    sm->aesContext[sizeof(sm->aesContext) - 1] = 0xff;

    secure_messaging_increment_context(sm);
    munit_assert_uint8(sm->aesContext[sizeof(sm->aesContext) - 1], ==, 0x00);
    munit_assert_uint8(sm->aesContext[sizeof(sm->aesContext) - 2], ==, 0x01);

    secure_messaging_free(sm);
    return MUNIT_OK;
}

/* The extension macro builds paths, so it must name exactly one extension.
 * The browser filter is the one allowed to list several. */
static MunitResult test_path_extension_is_single(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    munit_assert_null(strchr(SEOS_APP_EXTENSION, '|'));
    munit_assert_not_null(strstr(SEOS_APP_BROWSER_EXTENSIONS, SEOS_APP_EXTENSION));
    return MUNIT_OK;
}

static MunitTest test_secure_messaging_cases[] = {
    {(char*)"/round-trip/aes", test_round_trip_aes, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/round-trip/des", test_round_trip_des, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/padding/exact-block",
     test_exact_block_multiple,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {(char*)"/padding/all-lengths", test_all_lengths, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/length/long-form", test_long_form_length, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/wrap/oversized",
     test_rejects_oversized_message,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {(char*)"/unwrap/malformed", test_rejects_malformed, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/unwrap/bad-padding",
     test_rejects_bad_padding,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {(char*)"/counter/carry", test_counter_carries, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/credential/path-extension",
     test_path_extension_is_single,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

MunitSuite test_secure_messaging_suite = {
    (char*)"/secure-messaging",
    test_secure_messaging_cases,
    NULL,
    1,
    MUNIT_SUITE_OPTION_NONE,
};
