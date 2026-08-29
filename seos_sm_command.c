#include "seos_sm_command.h"

#include "seos_protocol.h"

#define TAG "SeosSmCommand"

const uint8_t SEOS_SM_HEADER[4] = {0x0c, 0xcb, 0x3f, 0xff};

/* The tag list naming the SIO file. */
static const uint8_t request_sio[] = {0x5c, 0x02, 0xff, 0x00};

void seos_sm_command_handle(
    SecureMessaging* secure_messaging,
    SeosCredential* credential,
    const uint8_t* apdu,
    size_t apdu_len,
    BitBuffer* tx,
    SeosSmEventCallback on_event,
    void* event_context) {
    furi_assert(secure_messaging);
    furi_assert(credential);

    if(apdu_len == 0) {
        return;
    }

    /* Unwrapping replaces the contents, so work on a copy. */
    BitBuffer* message = bit_buffer_alloc(apdu_len);
    bit_buffer_copy_bytes(message, apdu, apdu_len);

    seos_log_bitbuffer(TAG, "received(wrapped)", message);
    if(!secure_messaging_unwrap_apdu(secure_messaging, message)) {
        FURI_LOG_W(TAG, "Could not unwrap secure message");
        bit_buffer_free(message);
        return;
    }
    seos_log_bitbuffer(TAG, "received(clear)", message);

    size_t message_len = bit_buffer_get_size_bytes(message);
    if(message_len >= sizeof(request_sio) &&
       memcmp(bit_buffer_get_data(message), request_sio, sizeof(request_sio)) == 0) {
        if(on_event) {
            on_event(event_context, SeosSmEventSioRequested);
        }

        BitBuffer* sio_file = bit_buffer_alloc(SEOS_WORKER_MAX_BUFFER_SIZE);
        bit_buffer_append_bytes(sio_file, bit_buffer_get_data(message) + 2, 2); // fileId
        bit_buffer_append_byte(sio_file, credential->sio_len);
        bit_buffer_append_bytes(sio_file, credential->sio, credential->sio_len);

        seos_log_bitbuffer(TAG, "send(clear)", sio_file);
        if(secure_messaging_wrap_rapdu(
               secure_messaging,
               (uint8_t*)bit_buffer_get_data(sio_file),
               bit_buffer_get_size_bytes(sio_file),
               tx)) {
            bit_buffer_append_bytes(tx, SEOS_SW_SUCCESS, sizeof(SEOS_SW_SUCCESS));
        }

        bit_buffer_free(sio_file);
    }

    bit_buffer_free(message);
}
