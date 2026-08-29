#include "seos_sm_command.h"

#include "seos_protocol.h"

#define TAG "SeosSmCommand"

const uint8_t SEOS_SM_HEADER[4] = {0x0c, 0xcb, 0x3f, 0xff};
const uint8_t SEOS_GET_RESPONSE[4] = {0x00, 0xc0, 0x00, 0x00};

/* Status word telling the reader how much of the response is still to come. */
#define SEOS_SW_MORE_DATA 0x6100

/* Tag of the file holding the SIO. */
#define SIO_FILE_TAG 0xff00

/* Data field forms. Only a tag list is supported; an extended header list is
 * refused rather than answered wrongly. */
#define DO_TAG_LIST             0x5c
#define DO_EXTENDED_HEADER_LIST 0x4d

/* Sends as much of a response as one frame carries.
 *
 * Anything left over is kept for the reader to ask for, and the status word
 * says how much that is. The whole response is protected as one message
 * before being split, so the pieces are not separately meaningful. */
static void send_response(
    SecureMessaging* secure_messaging,
    const uint8_t* response,
    size_t response_len,
    size_t max_frame_len,
    uint16_t status_word,
    BitBuffer* tx) {
    /* Two bytes of every frame are the status word. */
    size_t room = max_frame_len > 2 ? max_frame_len - 2 : 0;

    if(response_len <= room) {
        bit_buffer_append_bytes(tx, response, response_len);
        bit_buffer_append_byte(tx, (uint8_t)(status_word >> 8));
        bit_buffer_append_byte(tx, (uint8_t)(status_word & 0xff));
        return;
    }

    bit_buffer_append_bytes(tx, response, room);
    size_t remaining = response_len - room;
    if(!secure_messaging_set_pending(secure_messaging, response + room, remaining)) {
        FURI_LOG_W(TAG, "No room to hold the rest of the response");
        bit_buffer_reset(tx);
        bit_buffer_append_byte(tx, 0x6a);
        bit_buffer_append_byte(tx, 0x84);
        return;
    }

    bit_buffer_append_byte(tx, (uint8_t)(SEOS_SW_MORE_DATA >> 8));
    bit_buffer_append_byte(tx, remaining > 0xff ? 0x00 : (uint8_t)remaining);
}

void seos_sm_command_get_response(
    SecureMessaging* secure_messaging,
    size_t max_frame_len,
    BitBuffer* tx) {
    furi_assert(secure_messaging);

    if(secure_messaging->pending_len == 0) {
        FURI_LOG_W(TAG, "Nothing pending to continue");
        bit_buffer_append_byte(tx, (uint8_t)(SEOS_SW_WRONG_P1P2 >> 8));
        bit_buffer_append_byte(tx, (uint8_t)(SEOS_SW_WRONG_P1P2 & 0xff));
        return;
    }

    size_t room = max_frame_len > 2 ? max_frame_len - 2 : 0;
    uint8_t chunk[SEOS_SM_RESPONSE_MAX];
    if(room > sizeof(chunk)) room = sizeof(chunk);

    size_t remaining = 0;
    size_t taken = secure_messaging_take_pending(secure_messaging, chunk, room, &remaining);
    bit_buffer_append_bytes(tx, chunk, taken);

    if(remaining > 0) {
        bit_buffer_append_byte(tx, (uint8_t)(SEOS_SW_MORE_DATA >> 8));
        bit_buffer_append_byte(tx, remaining > 0xff ? 0x00 : (uint8_t)remaining);
    } else {
        bit_buffer_append_bytes(tx, SEOS_SW_SUCCESS, sizeof(SEOS_SW_SUCCESS));
    }
}

/* Answers a command with no data, protected and then in the clear. */
static void answer_status(SecureMessaging* secure_messaging, BitBuffer* tx, uint16_t status_word) {
    if(!secure_messaging_wrap_rapdu(secure_messaging, NULL, 0, status_word, tx)) {
        return;
    }
    bit_buffer_append_byte(tx, (uint8_t)(status_word >> 8));
    bit_buffer_append_byte(tx, (uint8_t)(status_word & 0xff));
}

/* Reads the single tag a tag list names.
 *
 * Only one- and two-byte tags are allowed, and the list must name exactly one
 * object and nothing else. */
static bool parse_tag_list(const uint8_t* data, size_t data_len, uint16_t* tag) {
    if(data_len < 3 || data[0] != DO_TAG_LIST) return false;

    size_t tag_len = data[1];
    if(tag_len < 1 || tag_len > 2 || data_len != 2 + tag_len) return false;

    *tag = tag_len == 1 ? data[2] : (uint16_t)((data[2] << 8) | data[3]);
    return true;
}

bool seos_sm_command_handle(
    SecureMessaging* secure_messaging,
    SeosCredential* credential,
    const uint8_t* apdu,
    size_t apdu_len,
    size_t max_frame_len,
    BitBuffer* tx,
    SeosSmEventCallback on_event,
    void* event_context) {
    furi_assert(secure_messaging);
    furi_assert(credential);

    /* A new command supersedes anything the reader never asked for. */
    secure_messaging_clear_pending(secure_messaging);

    if(apdu_len == 0) {
        return true;
    }

    /* Unwrapping replaces the contents, so work on a copy. */
    BitBuffer* message = bit_buffer_alloc(apdu_len);
    bit_buffer_copy_bytes(message, apdu, apdu_len);

    seos_log_bitbuffer(TAG, "received(wrapped)", message);
    if(!secure_messaging_unwrap_apdu(secure_messaging, message)) {
        /* A secure messaging error is answered in the clear, and ends the
         * session: the counters are no longer in step. */
        uint16_t status_word = secure_messaging->last_error_sw;
        if(status_word == 0) status_word = SECURE_MESSAGING_SW_INCORRECT_DO;
        FURI_LOG_W(TAG, "Ending session after %04x", status_word);

        bit_buffer_append_byte(tx, (uint8_t)(status_word >> 8));
        bit_buffer_append_byte(tx, (uint8_t)(status_word & 0xff));
        bit_buffer_free(message);
        return false;
    }
    seos_log_bitbuffer(TAG, "received(clear)", message);

    uint16_t tag = 0;
    if(!parse_tag_list(bit_buffer_get_data(message), bit_buffer_get_size_bytes(message), &tag)) {
        uint8_t first = bit_buffer_get_size_bytes(message) > 0 ? bit_buffer_get_byte(message, 0) :
                                                                 0;
        if(first == DO_EXTENDED_HEADER_LIST) {
            FURI_LOG_W(TAG, "Extended header lists are not supported");
        } else {
            FURI_LOG_W(TAG, "Malformed data field");
        }
        answer_status(secure_messaging, tx, SEOS_SW_WRONG_DATA);
        bit_buffer_free(message);
        return true;
    }

    if(tag != SIO_FILE_TAG) {
        /* An object we do not hold is not an error: the answer simply carries
         * no data. */
        FURI_LOG_D(TAG, "No object with tag %04x", tag);
        answer_status(secure_messaging, tx, SEOS_SW_SUCCESS_VALUE);
        bit_buffer_free(message);
        return true;
    }

    if(on_event) {
        on_event(event_context, SeosSmEventSioRequested);
    }

    BitBuffer* sio_file = bit_buffer_alloc(SEOS_SM_RESPONSE_MAX);
    bit_buffer_append_byte(sio_file, (uint8_t)(tag >> 8));
    bit_buffer_append_byte(sio_file, (uint8_t)(tag & 0xff));
    bit_buffer_append_byte(sio_file, credential->sio_len);
    bit_buffer_append_bytes(sio_file, credential->sio, credential->sio_len);

    seos_log_bitbuffer(TAG, "send(clear)", sio_file);

    BitBuffer* wrapped = bit_buffer_alloc(SEOS_SM_RESPONSE_MAX);
    if(secure_messaging_wrap_rapdu(
           secure_messaging,
           (uint8_t*)bit_buffer_get_data(sio_file),
           bit_buffer_get_size_bytes(sio_file),
           SEOS_SW_SUCCESS_VALUE,
           wrapped)) {
        send_response(
            secure_messaging,
            bit_buffer_get_data(wrapped),
            bit_buffer_get_size_bytes(wrapped),
            max_frame_len,
            SEOS_SW_SUCCESS_VALUE,
            tx);
    } else {
        FURI_LOG_W(TAG, "SIO too long to protect");
        answer_status(secure_messaging, tx, SEOS_SW_NOT_ENOUGH_ROOM);
    }

    bit_buffer_free(wrapped);
    bit_buffer_free(sio_file);
    bit_buffer_free(message);
    return true;
}
