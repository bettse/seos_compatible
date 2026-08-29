#pragma once

#include <stdint.h>
#include <stdlib.h>

#include <mbedtls/des.h>
#include <mbedtls/aes.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>

#include "seos_common.h"
#include "aes_cmac.h"
#include "des_cmac.h"

#define SECURE_MESSAGING_MAX_SIZE 128

/* Room for the sequence counter, a padded command header, the largest
 * cryptogram and its objects, each group padded to a block boundary. */
#define SECURE_MESSAGING_CMAC_INPUT_SIZE 192

/* Largest span of protected objects: a cryptogram header, the cryptogram, and
 * the protected status word. */
#define SECURE_MESSAGING_OBJECTS_SIZE 144

/* The command header covered by the checksum. */
#define SECURE_MESSAGING_APDU_HEADER_LEN 4

/* Secure messaging errors are answered unprotected, and end the session. */
#define SECURE_MESSAGING_SW_MISSING_DO   0x6987
#define SECURE_MESSAGING_SW_INCORRECT_DO 0x6988

/* Where the cryptogram starts. A command carries a four byte header and a
 * length byte ahead of it; a response body starts with the cryptogram. */
#define SECURE_MESSAGING_CAPDU_BODY_OFFSET 5
#define SECURE_MESSAGING_RAPDU_BODY_OFFSET 0

typedef struct {
    uint8_t cipher;
    uint8_t PrivacyKey[16];
    uint8_t CMACKey[16];
    uint8_t aesContext[16];
    uint8_t desContext[8];
    /* Status word for the last message that failed to unwrap, or 0. */
    uint16_t last_error_sw;
    /* Protected status word of the last response unwrapped, or 0. */
    uint16_t last_response_sw;
} SecureMessaging;

SecureMessaging* secure_messaging_alloc(AuthParameters* params);

void secure_messaging_free(SecureMessaging* secure_messaging);

void secure_messaging_increment_context(SecureMessaging* secure_messaging);

/* The wrap calls return false if the message will not fit or the cipher
 * refuses it, leaving the output buffer alone.
 *
 * The unwrap calls replace the buffer contents with the recovered plaintext
 * and return true. They return false, leaving the buffer untouched, if the
 * message is malformed or the padding is wrong -- a caller must check before
 * reading what it thinks is plaintext. */
bool secure_messaging_wrap_apdu(
    SecureMessaging* secure_messaging,
    uint8_t* message,
    size_t message_len,
    uint8_t* apdu_header,
    size_t apdu_header_len,
    BitBuffer* tx_buffer);

bool secure_messaging_unwrap_apdu(SecureMessaging* secure_messaging, BitBuffer* rx_buffer);

bool secure_messaging_unwrap_rapdu(SecureMessaging* secure_messaging, BitBuffer* rx_buffer);
/* Wraps a response. `status_word` is carried in the protected status object
 * and must match the one the caller sends in the clear. A response with no
 * data omits the cryptogram rather than encrypting nothing. */
bool secure_messaging_wrap_rapdu(
    SecureMessaging* secure_messaging,
    uint8_t* message,
    size_t message_len,
    uint16_t status_word,
    BitBuffer* tx_buffer);
