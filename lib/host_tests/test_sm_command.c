/* The shared handler for commands inside a secure messaging session.
 *
 * Each transport used to carry its own copy of this. Testing the one copy is
 * what makes the four agree.
 */
#include "munit.h"
#include "test_helpers.h"

#include <seos_protocol.h>
#include <seos_sm_command.h>

#define BUFFER_CAPACITY 512

typedef struct {
    unsigned sio_requested;
} EventLog;

static void record_event(void* context, SeosSmEvent event) {
    EventLog* log = context;
    if(event == SeosSmEventSioRequested) log->sio_requested++;
}

static AuthParameters command_params(void) {
    AuthParameters params;
    memset(&params, 0, sizeof(params));
    params.cipher = AES_128_CBC;
    params.hash = SHA256;
    for(size_t i = 0; i < sizeof(params.rndICC); i++)
        params.rndICC[i] = (uint8_t)(0x10 + i);
    for(size_t i = 0; i < sizeof(params.UID); i++)
        params.UID[i] = (uint8_t)(0x20 + i);
    return params;
}

static SeosCredential credential_with_sio(size_t sio_len) {
    SeosCredential credential;
    memset(&credential, 0, sizeof(credential));
    credential.sio_len = sio_len;
    for(size_t i = 0; i < sio_len; i++)
        credential.sio[i] = (uint8_t)(0xc0 + i);
    return credential;
}

/* Runs one command through the handler as a reader would send it, and hands
 * back the plaintext the reader recovers from the answer. */
static uint16_t last_status_word;
static uint16_t last_protected_status_word;

static size_t exchange(
    SeosCredential* credential,
    const uint8_t* plain_command,
    size_t plain_command_len,
    uint8_t* recovered,
    size_t recovered_cap,
    EventLog* log) {
    AuthParameters params = command_params();
    SecureMessaging* reader = secure_messaging_alloc(&params);
    SecureMessaging* card = secure_messaging_alloc(&params);
    munit_assert_not_null(reader);
    munit_assert_not_null(card);

    BitBuffer* wire = bit_buffer_alloc(BUFFER_CAPACITY);
    munit_assert_true(secure_messaging_wrap_apdu(
        reader,
        (uint8_t*)plain_command,
        plain_command_len,
        (uint8_t*)SEOS_SM_HEADER,
        sizeof(SEOS_SM_HEADER),
        wire));

    BitBuffer* answer = bit_buffer_alloc(BUFFER_CAPACITY);
    seos_sm_command_handle(
        card,
        credential,
        bit_buffer_get_data(wire),
        bit_buffer_get_size_bytes(wire),
        answer,
        record_event,
        log);

    size_t recovered_len = 0;
    last_status_word = 0;
    last_protected_status_word = 0;

    size_t answer_len = bit_buffer_get_size_bytes(answer);
    munit_assert_size(answer_len, >=, 2);

    /* Every answer ends with a status word in the clear. */
    last_status_word = (uint16_t)((bit_buffer_get_byte(answer, answer_len - 2) << 8) |
                                  bit_buffer_get_byte(answer, answer_len - 1));

    if(answer_len > 2) {
        BitBuffer* body = bit_buffer_alloc(BUFFER_CAPACITY);
        bit_buffer_copy_bytes(body, bit_buffer_get_data(answer), answer_len - 2);

        munit_assert_true(secure_messaging_unwrap_rapdu(reader, body));
        last_protected_status_word = reader->last_response_sw;
        recovered_len = bit_buffer_get_size_bytes(body);
        munit_assert_size(recovered_len, <=, recovered_cap);
        memcpy(recovered, bit_buffer_get_data(body), recovered_len);
        bit_buffer_free(body);
    }

    bit_buffer_free(wire);
    bit_buffer_free(answer);
    secure_messaging_free(reader);
    secure_messaging_free(card);
    return recovered_len;
}

/* The tag list naming the SIO file gets the file back. */
static MunitResult test_returns_sio(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    SeosCredential credential = credential_with_sio(20);
    uint8_t request[] = {0x5c, 0x02, 0xff, 0x00};
    uint8_t recovered[BUFFER_CAPACITY];
    EventLog log = {0};

    size_t len =
        exchange(&credential, request, sizeof(request), recovered, sizeof(recovered), &log);

    /* fileId(2), length(1), then the file. */
    munit_assert_size(len, ==, 3 + credential.sio_len);
    munit_assert_uint8(recovered[0], ==, 0xff);
    munit_assert_uint8(recovered[1], ==, 0x00);
    munit_assert_uint8(recovered[2], ==, (uint8_t)credential.sio_len);
    munit_assert_memory_equal(credential.sio_len, recovered + 3, credential.sio);
    munit_assert_uint(log.sio_requested, ==, 1);
    munit_assert_uint16(last_status_word, ==, SEOS_SW_SUCCESS_VALUE);
    munit_assert_uint16(last_protected_status_word, ==, last_status_word);
    return MUNIT_OK;
}

/* A command that is not the SIO tag list must not report one was requested. */
static MunitResult test_ignores_other_tags(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    SeosCredential credential = credential_with_sio(8);
    uint8_t request[] = {0x5c, 0x02, 0xff, 0x42};
    uint8_t recovered[BUFFER_CAPACITY];
    EventLog log = {0};

    size_t len =
        exchange(&credential, request, sizeof(request), recovered, sizeof(recovered), &log);

    /* An object the card does not hold is answered with success and no data. */
    munit_assert_size(len, ==, 0);
    munit_assert_uint16(last_status_word, ==, SEOS_SW_SUCCESS_VALUE);
    munit_assert_uint16(last_protected_status_word, ==, SEOS_SW_SUCCESS_VALUE);
    munit_assert_uint(log.sio_requested, ==, 0);
    return MUNIT_OK;
}

/* A plaintext shorter than the tag list must not be compared against it. */
static MunitResult test_short_plaintext(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    SeosCredential credential = credential_with_sio(8);
    uint8_t request[] = {0x5c};
    uint8_t recovered[BUFFER_CAPACITY];
    EventLog log = {0};

    exchange(&credential, request, sizeof(request), recovered, sizeof(recovered), &log);

    /* A data field that is not a well formed tag list is a wrong-data error. */
    munit_assert_uint16(last_status_word, ==, SEOS_SW_WRONG_DATA);
    munit_assert_uint(log.sio_requested, ==, 0);
    return MUNIT_OK;
}

/* An extended header list is refused rather than answered wrongly. */
static MunitResult test_extended_header_list(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    SeosCredential credential = credential_with_sio(8);
    uint8_t request[] = {0x4d, 0x02, 0xff, 0x00};
    uint8_t recovered[BUFFER_CAPACITY];
    EventLog log = {0};

    exchange(&credential, request, sizeof(request), recovered, sizeof(recovered), &log);
    munit_assert_uint16(last_status_word, ==, SEOS_SW_WRONG_DATA);
    munit_assert_uint(log.sio_requested, ==, 0);
    return MUNIT_OK;
}

/* A tag list naming more than one object is not a tag list we can serve. */
static MunitResult test_multiple_tags(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    SeosCredential credential = credential_with_sio(8);
    uint8_t request[] = {0x5c, 0x04, 0xff, 0x00, 0xff, 0x01};
    uint8_t recovered[BUFFER_CAPACITY];
    EventLog log = {0};

    exchange(&credential, request, sizeof(request), recovered, sizeof(recovered), &log);
    munit_assert_uint16(last_status_word, ==, SEOS_SW_WRONG_DATA);
    return MUNIT_OK;
}

/* A command that does not unwrap ends the session, answered in the clear. */
static MunitResult test_unwrappable_command(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    SeosCredential credential = credential_with_sio(8);
    AuthParameters params = command_params();
    SecureMessaging* card = secure_messaging_alloc(&params);
    EventLog log = {0};

    uint8_t garbage[] = {0x0c, 0xcb, 0x3f, 0xff, 0x04, 0x85, 0x02, 0x00, 0x00};
    BitBuffer* answer = bit_buffer_alloc(BUFFER_CAPACITY);
    munit_assert_false(seos_sm_command_handle(
        card, &credential, garbage, sizeof(garbage), answer, record_event, &log));

    /* The error is answered unprotected, and nothing else is sent. */
    munit_assert_size(bit_buffer_get_size_bytes(answer), ==, 2);
    munit_assert_uint8(bit_buffer_get_byte(answer, 0), ==, 0x69);
    munit_assert_uint(log.sio_requested, ==, 0);

    bit_buffer_free(answer);
    secure_messaging_free(card);
    return MUNIT_OK;
}

/* An empty command is not a command. */
static MunitResult test_empty_command(const MunitParameter p[], void* d) {
    (void)p;
    (void)d;
    SeosCredential credential = credential_with_sio(8);
    AuthParameters params = command_params();
    SecureMessaging* card = secure_messaging_alloc(&params);
    EventLog log = {0};

    BitBuffer* answer = bit_buffer_alloc(BUFFER_CAPACITY);
    munit_assert_true(
        seos_sm_command_handle(card, &credential, NULL, 0, answer, record_event, &log));
    munit_assert_size(bit_buffer_get_size_bytes(answer), ==, 0);

    bit_buffer_free(answer);
    secure_messaging_free(card);
    return MUNIT_OK;
}

static MunitTest test_sm_command_cases[] = {
    {(char*)"/sio/returned", test_returns_sio, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/sio/other-tag", test_ignores_other_tags, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/sio/short-plaintext", test_short_plaintext, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/sio/extended-header-list",
     test_extended_header_list,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {(char*)"/sio/multiple-tags", test_multiple_tags, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {(char*)"/reject/unwrappable",
     test_unwrappable_command,
     NULL,
     NULL,
     MUNIT_TEST_OPTION_NONE,
     NULL},
    {(char*)"/reject/empty", test_empty_command, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
    {NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL},
};

MunitSuite test_sm_command_suite = {
    (char*)"/sm-command",
    test_sm_command_cases,
    NULL,
    1,
    MUNIT_SUITE_OPTION_NONE,
};
