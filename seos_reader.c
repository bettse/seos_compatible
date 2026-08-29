#include "seos_reader_i.h"

#include "seos_protocol.h"
#include "seos_sm_command.h"

#define TAG "SeosReader"

static uint8_t select[] =
    {0x00, 0xa4, 0x04, 0x00, 0x0a, 0xa0, 0x00, 0x00, 0x04, 0x40, 0x00, 0x01, 0x01, 0x00, 0x01, 0x00};
static uint8_t SEOS_APPLET_FCI[] =
    {0x6F, 0x0C, 0x84, 0x0A, 0xA0, 0x00, 0x00, 0x04, 0x40, 0x00, 0x01, 0x01, 0x00, 0x01};

SeosReader* seos_reader_alloc(SeosCredential* credential, Iso14443_4aPoller* iso14443_4a_poller) {
    SeosReader* seos_reader = malloc(sizeof(SeosReader));
    memset(seos_reader, 0, sizeof(SeosReader));
    seos_reader->params.key_no = 1;
    seos_reader->secure_messaging = NULL;
    seos_worker_random_nonce(seos_reader->params.cNonce, sizeof(seos_reader->params.cNonce));
    seos_worker_random_nonce(seos_reader->params.UID, sizeof(seos_reader->params.UID));

    seos_reader->credential = credential;
    seos_reader->iso14443_4a_poller = iso14443_4a_poller;

    seos_reader->tx_buffer = bit_buffer_alloc(SEOS_WORKER_MAX_BUFFER_SIZE);
    seos_reader->rx_buffer = bit_buffer_alloc(SEOS_WORKER_MAX_BUFFER_SIZE);

    return seos_reader;
}

void seos_reader_free(SeosReader* seos_reader) {
    furi_assert(seos_reader);
    bit_buffer_free(seos_reader->tx_buffer);
    bit_buffer_free(seos_reader->rx_buffer);
    if(seos_reader->secure_messaging) {
        secure_messaging_free(seos_reader->secure_messaging);
    }
    free(seos_reader);
}

bool seos_reader_request_sio(SeosReader* seos_reader) {
    SecureMessaging* secure_messaging = seos_reader->secure_messaging;
    furi_assert(secure_messaging);
    Iso14443_4aPoller* iso14443_4a_poller = seos_reader->iso14443_4a_poller;
    BitBuffer* tx_buffer = seos_reader->tx_buffer;
    BitBuffer* rx_buffer = seos_reader->rx_buffer;
    Iso14443_4aError error;

    uint8_t message[] = {0x5c, 0x02, 0xff, 0x00};
    secure_messaging_wrap_apdu(
        secure_messaging,
        message,
        sizeof(message),
        (uint8_t*)SEOS_SM_HEADER,
        sizeof(SEOS_SM_HEADER),
        tx_buffer);

    seos_log_bitbuffer(TAG, "NFC transmit", tx_buffer);

    /* A response longer than one frame arrives in pieces, each ending in 61xx
     * to say more is coming. They are collected before being unwrapped: the
     * whole answer is one protected message, so a piece means nothing alone. */
    BitBuffer* assembled = bit_buffer_alloc(SEOS_SM_RESPONSE_MAX);
    bool ok = false;

    for(size_t frame = 0; frame < SEOS_SM_MAX_CHAINED_FRAMES; frame++) {
        error = iso14443_4a_poller_send_block(iso14443_4a_poller, tx_buffer, rx_buffer);
        if(error != Iso14443_4aErrorNone) {
            FURI_LOG_W(TAG, "iso14443_4a_poller_send_block error %d", error);
            break;
        }
        bit_buffer_reset(tx_buffer);
        seos_log_bitbuffer(TAG, "NFC response(wrapped)", rx_buffer);

        size_t rx_len = bit_buffer_get_size_bytes(rx_buffer);
        if(rx_len < 2) {
            FURI_LOG_W(TAG, "Response too short to carry a status word");
            break;
        }

        uint8_t sw1 = bit_buffer_get_byte(rx_buffer, rx_len - 2);
        uint8_t sw2 = bit_buffer_get_byte(rx_buffer, rx_len - 1);
        if(bit_buffer_get_size_bytes(assembled) + rx_len - 2 > SEOS_SM_RESPONSE_MAX) {
            FURI_LOG_W(TAG, "Chained response too long to hold");
            break;
        }
        bit_buffer_append_bytes(assembled, bit_buffer_get_data(rx_buffer), rx_len - 2);

        if(sw1 == 0x61) {
            /* Le is how much the card said is still waiting. */
            uint8_t get_response[SEOS_GET_RESPONSE_LEN];
            memcpy(get_response, SEOS_GET_RESPONSE, sizeof(get_response));
            get_response[SEOS_GET_RESPONSE_LEN - 1] = sw2;
            bit_buffer_append_bytes(tx_buffer, get_response, sizeof(get_response));
            continue;
        }
        if(sw1 == 0x90 && sw2 == 0x00) {
            ok = true;
        } else {
            FURI_LOG_W(TAG, "SIO request answered %02x%02x", sw1, sw2);
        }
        break;
    }

    if(ok) {
        if(!secure_messaging_unwrap_rapdu(secure_messaging, assembled)) {
            FURI_LOG_W(TAG, "Could not unwrap SIO response");
            ok = false;
        }
    }

    if(ok) {
        seos_log_bitbuffer(TAG, "NFC response(clear)", assembled);

        // fileId(2) then the length byte
        size_t len = bit_buffer_get_size_bytes(assembled);
        if(len < 3) {
            FURI_LOG_W(TAG, "SIO response too short");
            ok = false;
        } else {
            size_t sio_len = bit_buffer_get_byte(assembled, 2);
            size_t sio_offset = 3;
            /* A length of 128 or more arrives in the long form. */
            if(sio_len == 0x81 && len > 3) {
                sio_len = bit_buffer_get_byte(assembled, 3);
                sio_offset = 4;
            }
            if(sio_len > sizeof(seos_reader->credential->sio) || len < sio_offset + sio_len) {
                FURI_LOG_W(TAG, "SIO length does not fit the response");
                ok = false;
            } else {
                seos_reader->credential->sio_len = sio_len;
                memcpy(seos_reader->credential->sio, bit_buffer_get_data(assembled) + 3, sio_len);
            }
        }
    }

    bit_buffer_free(assembled);
    return ok;
}

bool seos_reader_write_sio(SeosReader* seos_reader) {
    SecureMessaging* secure_messaging = seos_reader->secure_messaging;
    furi_assert(secure_messaging);
    Iso14443_4aPoller* iso14443_4a_poller = seos_reader->iso14443_4a_poller;
    BitBuffer* tx_buffer = seos_reader->tx_buffer;
    BitBuffer* rx_buffer = seos_reader->rx_buffer;
    Iso14443_4aError error;

    uint8_t apdu_header[] = {0x0c, 0xdb, 0x3f, 0xff};

    uint8_t message_prefix[] = {0xff, 0x00, seos_reader->credential->sio_len};
    uint8_t message[sizeof(message_prefix) + seos_reader->credential->sio_len];
    memcpy(message, message_prefix, sizeof(message_prefix));
    memcpy(
        message + sizeof(message_prefix),
        seos_reader->credential->sio,
        seos_reader->credential->sio_len);
    seos_log_buffer(TAG, "NFC transmit(clear)", message, sizeof(message));
    secure_messaging_wrap_apdu(
        secure_messaging, message, sizeof(message), apdu_header, sizeof(apdu_header), tx_buffer);

    seos_log_bitbuffer(TAG, "NFC transmit(wrapped)", tx_buffer);
    error = iso14443_4a_poller_send_block(iso14443_4a_poller, tx_buffer, rx_buffer);
    if(error != Iso14443_4aErrorNone) {
        FURI_LOG_W(TAG, "iso14443_4a_poller_send_block error %d", error);
        return false;
    }
    bit_buffer_reset(tx_buffer);

    seos_log_bitbuffer(TAG, "NFC response", rx_buffer);
    if(memcmp(
           bit_buffer_get_data(rx_buffer) + bit_buffer_get_size_bytes(rx_buffer) -
               sizeof(SEOS_SW_SUCCESS),
           SEOS_SW_SUCCESS,
           sizeof(SEOS_SW_SUCCESS)) != 0) {
        FURI_LOG_W(TAG, "Non-success response");
        return false;
    }

    return true;
}

NfcCommand seos_reader_select_aid(SeosReader* seos_reader) {
    Iso14443_4aPoller* iso14443_4a_poller = seos_reader->iso14443_4a_poller;
    BitBuffer* tx_buffer = seos_reader->tx_buffer;
    BitBuffer* rx_buffer = seos_reader->rx_buffer;

    NfcCommand ret = NfcCommandContinue;
    Iso14443_4aError error;

    bit_buffer_append_bytes(tx_buffer, select, sizeof(select));
    seos_log_bitbuffer(TAG, "NFC transmit", tx_buffer);
    error = iso14443_4a_poller_send_block(iso14443_4a_poller, tx_buffer, rx_buffer);
    if(error != Iso14443_4aErrorNone) {
        FURI_LOG_W(TAG, "iso14443_4a_poller_send_block error %d", error);
        return NfcCommandStop;
    }
    bit_buffer_reset(tx_buffer);

    seos_log_bitbuffer(TAG, "NFC response", rx_buffer);

    // TODO: validate response

    if(memcmp(
           bit_buffer_get_data(rx_buffer) + bit_buffer_get_size_bytes(rx_buffer) -
               sizeof(SEOS_SW_SUCCESS),
           SEOS_SW_SUCCESS,
           sizeof(SEOS_SW_SUCCESS)) != 0) {
        FURI_LOG_W(TAG, "Non-success response");
        return NfcCommandStop;
    }

    if(memcmp(bit_buffer_get_data(rx_buffer), SEOS_APPLET_FCI, sizeof(SEOS_APPLET_FCI)) != 0) {
        FURI_LOG_W(TAG, "Unexpected select AID response");
        return NfcCommandStop;
    }

    return ret;
}

NfcCommand seos_reader_select_adf(SeosReader* seos_reader) {
    Iso14443_4aPoller* iso14443_4a_poller = seos_reader->iso14443_4a_poller;
    BitBuffer* tx_buffer = seos_reader->tx_buffer;
    BitBuffer* rx_buffer = seos_reader->rx_buffer;

    NfcCommand ret = NfcCommandContinue;
    Iso14443_4aError error;

    uint8_t select_adf_header[] = {
        0x80, 0xa5, 0x04, 0x00, (uint8_t)SEOS_ADF_OID_LEN + 2, 0x06, (uint8_t)SEOS_ADF_OID_LEN};

    bit_buffer_append_bytes(tx_buffer, select_adf_header, sizeof(select_adf_header));
    bit_buffer_append_bytes(tx_buffer, SEOS_ADF_OID, SEOS_ADF_OID_LEN);
    bit_buffer_append_byte(tx_buffer, 0x00); // Le

    seos_log_bitbuffer(TAG, "NFC transmit", tx_buffer);
    error = iso14443_4a_poller_send_block(iso14443_4a_poller, tx_buffer, rx_buffer);
    if(error != Iso14443_4aErrorNone) {
        FURI_LOG_W(TAG, "iso14443_4a_poller_send_block error %d", error);
        return NfcCommandStop;
    }
    seos_log_bitbuffer(TAG, "NFC response", rx_buffer);
    if(memcmp(
           bit_buffer_get_data(rx_buffer) + bit_buffer_get_size_bytes(rx_buffer) -
               sizeof(SEOS_SW_SUCCESS),
           SEOS_SW_SUCCESS,
           sizeof(SEOS_SW_SUCCESS)) != 0) {
        FURI_LOG_W(TAG, "Non-success response");
        return NfcCommandStop;
    }

    bit_buffer_reset(tx_buffer);
    return ret;
}

NfcCommand seos_reader_general_authenticate_1(SeosReader* seos_reader) {
    Iso14443_4aPoller* iso14443_4a_poller = seos_reader->iso14443_4a_poller;
    BitBuffer* tx_buffer = seos_reader->tx_buffer;
    BitBuffer* rx_buffer = seos_reader->rx_buffer;
    FURI_LOG_D(TAG, "General Authenticate 1 with key no %d", seos_reader->params.key_no);

    NfcCommand ret = NfcCommandContinue;
    Iso14443_4aError error;

    uint8_t general_authenticate_1[SEOS_GENERAL_AUTHENTICATE_1_LEN];
    seos_build_general_authenticate_1(seos_reader->params.key_no, general_authenticate_1);
    bit_buffer_append_bytes(tx_buffer, general_authenticate_1, sizeof(general_authenticate_1));
    seos_log_bitbuffer(TAG, "NFC transmit", tx_buffer);

    error = iso14443_4a_poller_send_block(iso14443_4a_poller, tx_buffer, rx_buffer);
    if(error != Iso14443_4aErrorNone) {
        FURI_LOG_W(TAG, "iso14443_4a_poller_send_block error %d", error);
        return NfcCommandStop;
    }
    bit_buffer_reset(tx_buffer);

    seos_log_bitbuffer(TAG, "NFC response", rx_buffer);
    if(memcmp(
           bit_buffer_get_data(rx_buffer) + bit_buffer_get_size_bytes(rx_buffer) -
               sizeof(SEOS_SW_SUCCESS),
           SEOS_SW_SUCCESS,
           sizeof(SEOS_SW_SUCCESS)) != 0) {
        FURI_LOG_W(TAG, "Non-success response");
        return NfcCommandStop;
    }

    // 7c0a8108018cde7d6049edb09000

    uint8_t expected_header[] = {0x7c, 0x0a, 0x81, 0x08};
    const uint8_t* rx_data = bit_buffer_get_data(rx_buffer);
    if(memcmp(rx_data, expected_header, sizeof(expected_header)) != 0) {
        FURI_LOG_W(TAG, "Invalid response");
        return NfcCommandStop;
    }

    memcpy(seos_reader->params.rndICC, rx_data + 4, 8);

    return ret;
}

NfcCommand seos_reader_general_authenticate_2(SeosReader* seos_reader) {
    Iso14443_4aPoller* iso14443_4a_poller = seos_reader->iso14443_4a_poller;
    BitBuffer* tx_buffer = seos_reader->tx_buffer;
    BitBuffer* rx_buffer = seos_reader->rx_buffer;
    FURI_LOG_I(TAG, "General Authenticate 2 with key no %d", seos_reader->params.key_no);

    NfcCommand ret = NfcCommandContinue;
    Iso14443_4aError error;

    uint8_t cryptogram[32 + 8];
    memset(cryptogram, 0, sizeof(cryptogram));
    seos_reader_generate_cryptogram(seos_reader->credential, &seos_reader->params, cryptogram);

    uint8_t ga_header[] = {
        0x00, 0x87, 0x00, seos_reader->params.key_no, 0x2c, 0x7c, 0x2a, 0x82, 0x28};

    bit_buffer_append_bytes(tx_buffer, ga_header, sizeof(ga_header));
    bit_buffer_append_bytes(tx_buffer, cryptogram, sizeof(cryptogram));
    seos_log_bitbuffer(TAG, "NFC transmit", tx_buffer);

    error = iso14443_4a_poller_send_block(iso14443_4a_poller, tx_buffer, rx_buffer);
    if(error != Iso14443_4aErrorNone) {
        FURI_LOG_W(TAG, "iso14443_4a_poller_send_block error %d", error);
        return NfcCommandStop;
    }
    bit_buffer_reset(tx_buffer);

    seos_log_bitbuffer(TAG, "NFC response", rx_buffer);
    if(memcmp(
           bit_buffer_get_data(rx_buffer) + bit_buffer_get_size_bytes(rx_buffer) -
               sizeof(SEOS_SW_SUCCESS),
           SEOS_SW_SUCCESS,
           sizeof(SEOS_SW_SUCCESS)) != 0) {
        FURI_LOG_W(TAG, "Non-success response");
        return NfcCommandStop;
    }

    const uint8_t* rx_data = bit_buffer_get_data(rx_buffer);
    if(rx_data[0] != 0x7C || rx_data[2] != 0x82) {
        FURI_LOG_W(TAG, "Invalid rx_data");
        return NfcCommandStop;
    }

    if(rx_data[3] == 40) {
        if(!seos_reader_verify_cryptogram(&seos_reader->params, rx_data + 4)) {
            FURI_LOG_W(TAG, "Card cryptogram failed verification");
            return NfcCommandStop;
        }
        FURI_LOG_I(TAG, "Authenticated successfully with key no %d", seos_reader->params.key_no);
    } else {
        FURI_LOG_W(TAG, "Unhandled card cryptogram size %d", rx_data[3]);
        ret = NfcCommandStop;
    }

    seos_reader->secure_messaging = secure_messaging_alloc(&seos_reader->params);
    if(!seos_reader->secure_messaging) {
        FURI_LOG_W(TAG, "Could not start secure messaging");
        ret = NfcCommandStop;
    }

    return ret;
}

NfcCommand seos_state_machine(Seos* seos, Iso14443_4aPoller* iso14443_4a_poller) {
    furi_assert(seos);
    NfcCommand ret = NfcCommandContinue;

    SeosReader* seos_reader = seos_reader_alloc(seos->credential, iso14443_4a_poller);
    seos->seos_reader = seos_reader;

    do {
        ret = seos_reader_select_aid(seos_reader);
        if(ret == NfcCommandStop) break;

        ret = seos_reader_select_adf(seos_reader);
        if(ret == NfcCommandStop) break;

        if(!seos_reader_select_adf_response(
               seos_reader->rx_buffer, 0, seos_reader->credential, &seos_reader->params)) {
            ret = NfcCommandStop;
            break;
        }

        if(seos_reader->credential->write) {
            // Use Write keyslot
            seos_reader->params.key_no = 2;
        } else {
            // Use Read keyslot
            seos_reader->params.key_no = 1;
        }

        ret = seos_reader_general_authenticate_1(seos_reader);
        if(ret == NfcCommandStop) break;

        ret = seos_reader_general_authenticate_2(seos_reader);
        if(ret == NfcCommandStop) break;

        if(seos_reader->credential->write) {
            FURI_LOG_D(TAG, "Write SIO");
            if(seos_reader_write_sio(seos_reader)) {
                view_dispatcher_send_custom_event(
                    seos->view_dispatcher, SeosCustomEventPollerSuccess);
            } else {
                view_dispatcher_send_custom_event(
                    seos->view_dispatcher, SeosCustomEventPollerError);
            }
        } else {
            FURI_LOG_D(TAG, "Request SIO");
            if(seos_reader_request_sio(seos_reader)) {
                SeosCredential* credential = seos_reader->credential;
                AuthParameters* params = &seos_reader->params;

                memcpy(credential->priv_key, params->priv_key, sizeof(credential->priv_key));
                memcpy(credential->auth_key, params->auth_key, sizeof(credential->auth_key));
                credential->adf_oid_len = SEOS_ADF_OID_LEN;
                memcpy(credential->adf_oid, SEOS_ADF_OID, sizeof(credential->adf_oid));

                view_dispatcher_send_custom_event(
                    seos->view_dispatcher, SeosCustomEventPollerSuccess);
            } else {
                view_dispatcher_send_custom_event(
                    seos->view_dispatcher, SeosCustomEventPollerError);
            }
        }

    } while(false);

    // An error occurred
    if(ret == NfcCommandStop) {
        view_dispatcher_send_custom_event(seos->view_dispatcher, SeosCustomEventPollerError);
    }
    seos_reader_free(seos_reader);

    return NfcCommandStop;
}

NfcCommand seos_worker_poller_callback(NfcGenericEvent event, void* context) {
    furi_assert(event.protocol == NfcProtocolIso14443_4a);
    NfcCommand ret = NfcCommandContinue;

    Seos* seos = context;

    const Iso14443_4aPollerEvent* iso14443_4a_event = event.event_data;
    Iso14443_4aPoller* iso14443_4a_poller = event.instance;

    if(iso14443_4a_event->type == Iso14443_4aPollerEventTypeReady) {
        // view_dispatcher_send_custom_event(seos->view_dispatcher, SeosCustomEventPollerDetect);

        nfc_device_set_data(
            seos->nfc_device, NfcProtocolIso14443_4a, nfc_poller_get_data(seos->poller));

        ret = seos_state_machine(seos, iso14443_4a_poller);

        // furi_thread_set_current_priority(FuriThreadPriorityLowest);
    } else if(iso14443_4a_event->type == Iso14443_4aPollerEventTypeError) {
        Iso14443_4aPollerEventData* data = iso14443_4a_event->data;
        Iso14443_4aError error = data->error;
        FURI_LOG_W(TAG, "Iso14443_4aError %i", error);
        // I was hoping to catch MFC here, but it seems to be treated the same (None) as no card being present.
        switch(error) {
        case Iso14443_4aErrorNone:
            break;
        case Iso14443_4aErrorNotPresent:
            break;
        case Iso14443_4aErrorProtocol:
            ret = NfcCommandStop;
            break;
        case Iso14443_4aErrorTimeout:
            break;
        default:
            break;
        }
    }

    return ret;
}
