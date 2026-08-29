#include "secure_messaging.h"

#define TAG "SecureMessaging"

static uint8_t padding[16] =
    {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

/* Secure messaging data object tags. */
#define DO_CRYPTOGRAM 0x85
#define DO_CHECKSUM   0x8e
#define DO_LE         0x97
#define DO_STATUS     0x99

/* Longest cryptogram header: tag, long-form marker, length. */
#define CRYPTOGRAM_HEADER_MAX 3

static size_t block_size_for(uint8_t cipher) {
    return cipher == AES_128_CBC ? 16 : 8;
}

/* Pads a checksum input up to the next cipher block boundary. */
static void append_padding(BitBuffer* buffer, size_t block_size) {
    size_t remainder = bit_buffer_get_size_bytes(buffer) % block_size;
    bit_buffer_append_bytes(buffer, padding, block_size - remainder);
}

/* Writes the cryptogram tag and length, returning the header length.
 *
 * A length of 128 or more needs the long form; written as a bare byte it would
 * be read back as a length header with no length octets. */
static size_t encode_cryptogram_header(uint8_t* out, size_t value_len) {
    out[0] = DO_CRYPTOGRAM;
    if(value_len < 0x80) {
        out[1] = (uint8_t)value_len;
        return 2;
    }
    out[1] = 0x81;
    out[2] = (uint8_t)value_len;
    return 3;
}

/* Encrypts a padded plaintext block in place of the caller choosing a cipher. */
static bool encrypt_blocks(
    SecureMessaging* secure_messaging,
    const uint8_t* clear,
    size_t clear_len,
    uint8_t* encrypted) {
    if(secure_messaging->cipher == AES_128_CBC) {
        return seos_worker_aes_encrypt(secure_messaging->PrivacyKey, clear_len, clear, encrypted);
    }
    if(secure_messaging->cipher == TWO_KEY_3DES_CBC_MODE) {
        return seos_worker_des_encrypt(secure_messaging->PrivacyKey, clear_len, clear, encrypted);
    }
    FURI_LOG_W(TAG, "Cipher not matched");
    return false;
}

/* Computes the checksum over the sequence counter, the command header if there
 * is one, and the protected data objects, each group padded to a block
 * boundary. Both directions use the same scope, so both use this. */
static bool checksum_objects(
    SecureMessaging* secure_messaging,
    const uint8_t* header,
    size_t header_len,
    const uint8_t* objects,
    size_t objects_len,
    uint8_t* cmac) {
    uint8_t cipher = secure_messaging->cipher;
    size_t block_size = block_size_for(cipher);
    uint8_t* context = cipher == AES_128_CBC ? secure_messaging->aesContext :
                                               secure_messaging->desContext;

    BitBuffer* input = bit_buffer_alloc(SECURE_MESSAGING_CMAC_INPUT_SIZE);
    bit_buffer_append_bytes(input, context, block_size);
    if(header_len > 0) {
        bit_buffer_append_bytes(input, header, header_len);
        append_padding(input, block_size);
    }
    bit_buffer_append_bytes(input, objects, objects_len);
    append_padding(input, block_size);

    bool ok = false;
    if(cipher == AES_128_CBC) {
        ok = aes_cmac(
            secure_messaging->CMACKey,
            sizeof(secure_messaging->CMACKey),
            (uint8_t*)bit_buffer_get_data(input),
            bit_buffer_get_size_bytes(input),
            cmac);
    } else if(cipher == TWO_KEY_3DES_CBC_MODE) {
        ok = des_cmac(
            secure_messaging->CMACKey,
            sizeof(secure_messaging->CMACKey),
            (uint8_t*)bit_buffer_get_data(input),
            bit_buffer_get_size_bytes(input),
            cmac);
    } else {
        FURI_LOG_W(TAG, "Cipher not matched");
    }

    bit_buffer_free(input);
    return ok;
}

/* Reads a data object header at `offset`, reporting where its value starts and
 * how long it is. */
static bool read_object_header(
    const uint8_t* data,
    size_t data_len,
    size_t offset,
    uint8_t* tag,
    size_t* value_offset,
    size_t* value_len) {
    if(offset + 2 > data_len) return false;

    *tag = data[offset];
    uint8_t length_byte = data[offset + 1];
    if(length_byte < 0x80) {
        *value_len = length_byte;
        *value_offset = offset + 2;
    } else if(length_byte == 0x81 && offset + 3 <= data_len) {
        *value_len = data[offset + 2];
        *value_offset = offset + 3;
    } else {
        return false;
    }
    return *value_offset + *value_len <= data_len;
}

/* Walks the data objects from `body_offset` to the checksum object.
 *
 * The checksum covers everything ahead of it, so its position also gives the
 * length of the protected span. */
static bool find_checksum(
    const uint8_t* data,
    size_t data_len,
    size_t body_offset,
    size_t* objects_len,
    size_t* checksum_offset) {
    size_t offset = body_offset;
    while(offset < data_len) {
        uint8_t tag;
        size_t value_offset;
        size_t value_len;
        if(!read_object_header(data, data_len, offset, &tag, &value_offset, &value_len)) {
            return false;
        }
        if(tag == DO_CHECKSUM) {
            if(value_len != SEOS_WORKER_CMAC_SIZE) return false;
            *objects_len = offset - body_offset;
            *checksum_offset = value_offset;
            return true;
        }
        offset = value_offset + value_len;
    }
    return false;
}

/* Recomputes the checksum of a received message and compares it.
 *
 * Records the status word the caller should answer with: a message with no
 * checksum is missing an object, one that fails to match is incorrect. */
static bool verify_checksum(
    SecureMessaging* secure_messaging,
    const uint8_t* data,
    size_t data_len,
    size_t body_offset,
    const uint8_t* header,
    size_t header_len,
    size_t* objects_len) {
    size_t checksum_offset = 0;
    if(!find_checksum(data, data_len, body_offset, objects_len, &checksum_offset)) {
        FURI_LOG_W(TAG, "No checksum in secure message");
        secure_messaging->last_error_sw = SECURE_MESSAGING_SW_MISSING_DO;
        return false;
    }

    uint8_t expected[16];
    if(!checksum_objects(
           secure_messaging, header, header_len, data + body_offset, *objects_len, expected)) {
        secure_messaging->last_error_sw = SECURE_MESSAGING_SW_INCORRECT_DO;
        return false;
    }

    if(memcmp(expected, data + checksum_offset, SEOS_WORKER_CMAC_SIZE) != 0) {
        FURI_LOG_W(TAG, "Checksum mismatch");
        secure_messaging->last_error_sw = SECURE_MESSAGING_SW_INCORRECT_DO;
        return false;
    }
    return true;
}

/* Copies a message into a padded plaintext block, returning the padded length.
 * Returns 0 if the message does not leave room for the mandatory pad byte. */
static size_t pad_message(
    const uint8_t* message,
    size_t message_len,
    size_t block_size,
    uint8_t* clear,
    size_t clear_cap) {
    /* The pad byte is mandatory, so a message filling the buffer exactly is
     * still too long. */
    if(message_len >= clear_cap) {
        return 0;
    }

    size_t clear_len = ((message_len / block_size) + 1) * block_size;
    if(clear_len > clear_cap) {
        return 0;
    }

    memset(clear, 0, clear_cap);
    memcpy(clear, message, message_len);
    clear[message_len] = 0x80;
    return clear_len;
}

/* Recovers the plaintext from the cryptogram at `offset`.
 *
 * Returns false if the message is not well formed. Every length here comes off
 * the wire, so each is checked against the buffer before it is used. The
 * length is reported separately because an empty plaintext is a valid result.
 */
static bool unwrap_cryptogram(
    SecureMessaging* secure_messaging,
    const uint8_t* data,
    size_t data_len,
    size_t offset,
    uint8_t* clear,
    size_t clear_cap,
    size_t* clear_len_out) {
    uint8_t tag;
    size_t value_offset;
    size_t value_len;
    if(!read_object_header(data, data_len, offset, &tag, &value_offset, &value_len) ||
       tag != DO_CRYPTOGRAM) {
        FURI_LOG_W(TAG, "No cryptogram to unwrap");
        return false;
    }

    size_t block_size = block_size_for(secure_messaging->cipher);
    if(value_len == 0 || value_len > clear_cap || (value_len % block_size) != 0) {
        FURI_LOG_W(TAG, "Invalid cryptogram length (%d)", value_len);
        return false;
    }

    const uint8_t* encrypted = data + value_offset;
    memset(clear, 0, clear_cap);

    bool decrypted = false;
    if(secure_messaging->cipher == AES_128_CBC) {
        decrypted =
            seos_worker_aes_decrypt(secure_messaging->PrivacyKey, value_len, encrypted, clear);
    } else if(secure_messaging->cipher == TWO_KEY_3DES_CBC_MODE) {
        decrypted =
            seos_worker_des_decrypt(secure_messaging->PrivacyKey, value_len, encrypted, clear);
    } else {
        FURI_LOG_W(TAG, "Cipher not matched");
    }
    if(!decrypted) {
        return false;
    }

    /* Strip the pad: trailing zeroes, then the one mandatory 0x80. Its absence
     * means the padding is wrong, which is a decryption failure in disguise. */
    size_t clear_len = value_len;
    while(clear_len > 0 && clear[clear_len - 1] == 0x00) {
        clear_len--;
    }
    if(clear_len == 0 || clear[clear_len - 1] != 0x80) {
        FURI_LOG_W(TAG, "Bad cryptogram padding");
        return false;
    }

    *clear_len_out = clear_len - 1;
    return true;
}

SecureMessaging* secure_messaging_alloc(AuthParameters* params) {
    SecureMessaging* secure_messaging = malloc(sizeof(SecureMessaging));
    memset(secure_messaging, 0, sizeof(SecureMessaging));

    secure_messaging->cipher = params->cipher;
    if(params->cipher == AES_128_CBC) {
        memcpy(secure_messaging->aesContext, params->rndICC, 8);
        memcpy(secure_messaging->aesContext + 8, params->UID, 8);
    } else if(params->cipher == TWO_KEY_3DES_CBC_MODE) {
        memcpy(secure_messaging->desContext, params->rndICC, 4);
        memcpy(secure_messaging->desContext + 4, params->UID, 4);
    } else {
        FURI_LOG_W(TAG, "Cipher not matched");
    }

    size_t index = 0;
    uint8_t buffer[38];
    memset(buffer, 0, sizeof(buffer));
    index += 4; // skip 4 bytes where iteration will be put
    memcpy(buffer + index, params->cNonce, 8);
    index += 8;
    memcpy(buffer + index, params->rNonce, 8);
    index += 8;
    buffer[index++] = params->cipher;
    buffer[index++] = params->cipher;
    memcpy(buffer + index, params->rndICC, 8);
    index += 8;
    memcpy(buffer + index, params->UID, 8);
    index += 8;

    size_t iterations = 1;
    size_t unit = 0;
    if(params->hash == SHA1) {
        unit = 160 / 8;
    } else if(params->hash == SHA256) {
        unit = 256 / 8;
    }
    // FURI_LOG_D(TAG, "secure_messaging_alloc hash %d unit %d", hash, unit);

    // More than enough space for the hash
    uint8_t accumulator[64];
    memset(accumulator, 0, sizeof(accumulator));
    for(size_t i = 0; i < 32; i += unit) {
        buffer[3] = iterations++;
        if(params->hash == SHA1) {
            mbedtls_sha1_context ctx;
            mbedtls_sha1_init(&ctx);
            mbedtls_sha1_starts(&ctx);
            mbedtls_sha1_update(&ctx, buffer, index);
            mbedtls_sha1_finish(&ctx, accumulator + i);
            mbedtls_sha1_free(&ctx);
        } else if(params->hash == SHA256) {
            mbedtls_sha256_context ctx;
            mbedtls_sha256_init(&ctx);
            mbedtls_sha256_starts(&ctx, 0);
            mbedtls_sha256_update(&ctx, buffer, index);
            mbedtls_sha256_finish(&ctx, accumulator + i);
            mbedtls_sha256_free(&ctx);
        } else {
            FURI_LOG_W(TAG, "Could not match hash algorithm");
        }
    }

    memcpy(secure_messaging->PrivacyKey, accumulator, 16);
    memcpy(secure_messaging->CMACKey, accumulator + 16, 16);

    return secure_messaging;
}

void secure_messaging_free(SecureMessaging* secure_messaging) {
    furi_assert(secure_messaging);
    // Nothing to free;
    free(secure_messaging);
}

void secure_messaging_increment_context(SecureMessaging* secure_messaging) {
    uint8_t* context = NULL;
    size_t context_len = 0;
    if(secure_messaging->cipher == AES_128_CBC) {
        context = secure_messaging->aesContext;
        context_len = sizeof(secure_messaging->aesContext);
    } else if(secure_messaging->cipher == TWO_KEY_3DES_CBC_MODE) {
        context = secure_messaging->desContext;
        context_len = sizeof(secure_messaging->desContext);
    } else {
        FURI_LOG_W(TAG, "Cipher not matched");
        return;
    }
    do {
    } while(++context[--context_len] == 0 && context_len > 0);
}

bool secure_messaging_wrap_apdu(
    SecureMessaging* secure_messaging,
    uint8_t* message,
    size_t message_len,
    uint8_t* apdu_header,
    size_t apdu_header_len,
    BitBuffer* tx_buffer) {
    uint8_t cipher = secure_messaging->cipher;
    size_t block_size = block_size_for(cipher);

    uint8_t clear[SECURE_MESSAGING_MAX_SIZE];
    size_t clear_len = pad_message(message, message_len, block_size, clear, sizeof(clear));
    if(clear_len == 0) {
        FURI_LOG_W(TAG, "Message too long to wrap (%d)", message_len);
        return false;
    }

    secure_messaging_increment_context(secure_messaging);

    uint8_t encrypted[SECURE_MESSAGING_MAX_SIZE];
    if(!encrypt_blocks(secure_messaging, clear, clear_len, encrypted)) {
        return false;
    }

    uint8_t cryptogram_header[CRYPTOGRAM_HEADER_MAX];
    size_t cryptogram_header_len = encode_cryptogram_header(cryptogram_header, clear_len);

    uint8_t protected_le[] = {DO_LE, 0x00};
    uint8_t checksum_prefix[] = {DO_CHECKSUM, SEOS_WORKER_CMAC_SIZE};
    uint8_t Le[] = {0x00};

    /* Assemble the protected objects once. They are checksummed and then sent
     * as they stand, so the two cannot disagree. */
    uint8_t objects[SECURE_MESSAGING_OBJECTS_SIZE];
    size_t objects_len = 0;
    memcpy(objects, cryptogram_header, cryptogram_header_len);
    objects_len += cryptogram_header_len;
    memcpy(objects + objects_len, encrypted, clear_len);
    objects_len += clear_len;
    memcpy(objects + objects_len, protected_le, sizeof(protected_le));
    objects_len += sizeof(protected_le);

    uint8_t cmac[16];
    if(!checksum_objects(
           secure_messaging, apdu_header, apdu_header_len, objects, objects_len, cmac)) {
        return false;
    }

    uint8_t apdu_len[] = {
        (uint8_t)(objects_len + sizeof(checksum_prefix) + SEOS_WORKER_CMAC_SIZE)};

    bit_buffer_reset(tx_buffer);
    bit_buffer_append_bytes(tx_buffer, apdu_header, apdu_header_len);
    bit_buffer_append_bytes(tx_buffer, apdu_len, sizeof(apdu_len));
    bit_buffer_append_bytes(tx_buffer, objects, objects_len);
    bit_buffer_append_bytes(tx_buffer, checksum_prefix, sizeof(checksum_prefix));
    bit_buffer_append_bytes(tx_buffer, cmac, SEOS_WORKER_CMAC_SIZE);
    bit_buffer_append_bytes(tx_buffer, Le, sizeof(Le));
    return true;
}

bool secure_messaging_unwrap_rapdu(SecureMessaging* secure_messaging, BitBuffer* rx_buffer) {
    secure_messaging_increment_context(secure_messaging);
    secure_messaging->last_error_sw = 0;

    const uint8_t* data = bit_buffer_get_data(rx_buffer);
    size_t data_len = bit_buffer_get_size_bytes(rx_buffer);

    size_t objects_len = 0;
    if(!verify_checksum(
           secure_messaging,
           data,
           data_len,
           SECURE_MESSAGING_RAPDU_BODY_OFFSET,
           NULL,
           0,
           &objects_len)) {
        return false;
    }

    uint8_t clear[SECURE_MESSAGING_MAX_SIZE];
    size_t clear_len = 0;
    if(!unwrap_cryptogram(
           secure_messaging,
           data,
           data_len,
           SECURE_MESSAGING_RAPDU_BODY_OFFSET,
           clear,
           sizeof(clear),
           &clear_len)) {
        secure_messaging->last_error_sw = SECURE_MESSAGING_SW_INCORRECT_DO;
        return false;
    }

    bit_buffer_reset(rx_buffer);
    bit_buffer_append_bytes(rx_buffer, clear, clear_len);
    return true;
}

// Assumes it is an iso14443a-4 and doesn't have framing bytes
/*
0ccb3fff
16
  8508
    4088b37ca72bc7ae
  9700
  8e08
    85345f0f5c44b980
00
*/
bool secure_messaging_unwrap_apdu(SecureMessaging* secure_messaging, BitBuffer* rx_buffer) {
    secure_messaging_increment_context(secure_messaging);
    secure_messaging->last_error_sw = 0;

    const uint8_t* data = bit_buffer_get_data(rx_buffer);
    size_t data_len = bit_buffer_get_size_bytes(rx_buffer);

    /* The command header is the four bytes ahead of the length byte, and is
     * covered by the checksum. */
    if(data_len < SECURE_MESSAGING_CAPDU_BODY_OFFSET) {
        FURI_LOG_W(TAG, "Command too short to unwrap");
        secure_messaging->last_error_sw = SECURE_MESSAGING_SW_MISSING_DO;
        return false;
    }

    size_t objects_len = 0;
    if(!verify_checksum(
           secure_messaging,
           data,
           data_len,
           SECURE_MESSAGING_CAPDU_BODY_OFFSET,
           data,
           SECURE_MESSAGING_APDU_HEADER_LEN,
           &objects_len)) {
        return false;
    }

    uint8_t clear[SECURE_MESSAGING_MAX_SIZE];
    size_t clear_len = 0;
    if(!unwrap_cryptogram(
           secure_messaging,
           data,
           data_len,
           SECURE_MESSAGING_CAPDU_BODY_OFFSET,
           clear,
           sizeof(clear),
           &clear_len)) {
        secure_messaging->last_error_sw = SECURE_MESSAGING_SW_INCORRECT_DO;
        return false;
    }

    bit_buffer_reset(rx_buffer);
    bit_buffer_append_bytes(rx_buffer, clear, clear_len);
    return true;
}

bool secure_messaging_wrap_rapdu(
    SecureMessaging* secure_messaging,
    uint8_t* message,
    size_t message_len,
    BitBuffer* tx_buffer) {
    size_t block_size = block_size_for(secure_messaging->cipher);

    uint8_t clear[SECURE_MESSAGING_MAX_SIZE];
    size_t clear_len = pad_message(message, message_len, block_size, clear, sizeof(clear));
    if(clear_len == 0) {
        FURI_LOG_W(TAG, "Message too long to wrap (%d)", message_len);
        return false;
    }

    secure_messaging_increment_context(secure_messaging);

    uint8_t encrypted[SECURE_MESSAGING_MAX_SIZE];
    if(!encrypt_blocks(secure_messaging, clear, clear_len, encrypted)) {
        return false;
    }

    uint8_t cryptogram_header[CRYPTOGRAM_HEADER_MAX];
    size_t cryptogram_header_len = encode_cryptogram_header(cryptogram_header, clear_len);

    uint8_t checksum_prefix[] = {DO_CHECKSUM, SEOS_WORKER_CMAC_SIZE};
    uint8_t protected_status[] = {DO_STATUS, 0x02, 0x90, 0x00};

    uint8_t objects[SECURE_MESSAGING_OBJECTS_SIZE];
    size_t objects_len = 0;
    memcpy(objects, cryptogram_header, cryptogram_header_len);
    objects_len += cryptogram_header_len;
    memcpy(objects + objects_len, encrypted, clear_len);
    objects_len += clear_len;
    memcpy(objects + objects_len, protected_status, sizeof(protected_status));
    objects_len += sizeof(protected_status);

    uint8_t cmac[16];
    if(!checksum_objects(secure_messaging, NULL, 0, objects, objects_len, cmac)) {
        return false;
    }

    bit_buffer_append_bytes(tx_buffer, objects, objects_len);
    bit_buffer_append_bytes(tx_buffer, checksum_prefix, sizeof(checksum_prefix));
    bit_buffer_append_bytes(tx_buffer, cmac, SEOS_WORKER_CMAC_SIZE);
    // Success (9000) is appended by common code before transmission
    return true;
}
