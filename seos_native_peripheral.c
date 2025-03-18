#include "seos_native_peripheral_i.h"

#define TAG "SeosNativePeripheral"

#define MESSAGE_QUEUE_SIZE 10

static uint8_t standard_seos_aid[] = {0xa0, 0x00, 0x00, 0x04, 0x40, 0x00, 0x01, 0x01, 0x00, 0x01};
static uint8_t cd02[] = {0xcd, 0x02};
static uint8_t general_authenticate_1[] =
    {0x00, 0x87, 0x00, 0x01, 0x04, 0x7c, 0x02, 0x81, 0x00, 0x00};
static uint8_t ga1_response[] = {0x7c, 0x0a, 0x81, 0x08};

int32_t seos_native_peripheral_task(void* context);

typedef struct {
    size_t len;
    uint8_t buf[BLE_SVC_SEOS_CHAR_VALUE_LEN_MAX];
} NativePeripheralMessage;

static void seos_ble_connection_status_callback(BtStatus status, void* context) {
    furi_assert(context);
    SeosNativePeripheral* seos_native_peripheral = context;
    FURI_LOG_D(TAG, "seos_ble_connection_status_callback %d", (status == BtStatusConnected));
    if(status == BtStatusConnected) {
        view_dispatcher_send_custom_event(
            seos_native_peripheral->seos->view_dispatcher, SeosCustomEventConnected);
    } else if(status == BtStatusAdvertising) {
        view_dispatcher_send_custom_event(
            seos_native_peripheral->seos->view_dispatcher, SeosCustomEventAdvertising);
    }
}

static uint16_t seos_svc_callback(SeosServiceEvent event, void* context) {
    SeosNativePeripheral* seos_native_peripheral = context;
    uint16_t bytes_available = 0;

    if(event.event == SeosServiceEventTypeDataReceived) {
        uint32_t space = furi_message_queue_get_space(seos_native_peripheral->messages);
        if(space > 0) {
            NativePeripheralMessage message = {.len = event.data.size};
            memcpy(message.buf, event.data.buffer, event.data.size);

            if(furi_mutex_acquire(seos_native_peripheral->mq_mutex, FuriWaitForever) ==
               FuriStatusOk) {
                furi_message_queue_put(
                    seos_native_peripheral->messages, &message, FuriWaitForever);
                furi_mutex_release(seos_native_peripheral->mq_mutex);
            }
            if(space < MESSAGE_QUEUE_SIZE / 2) {
                FURI_LOG_D(TAG, "Queue message.  %ld remaining", space);
            }
            bytes_available = (space - 1) * sizeof(NativePeripheralMessage);
        } else {
            FURI_LOG_E(TAG, "No space in message queue");
        }
    }

    return bytes_available;
}

SeosNativePeripheral* seos_native_peripheral_alloc(Seos* seos) {
    SeosNativePeripheral* seos_native_peripheral = malloc(sizeof(SeosNativePeripheral));
    memset(seos_native_peripheral, 0, sizeof(SeosNativePeripheral));

    seos_native_peripheral->seos = seos;
    seos_native_peripheral->credential = &seos->credential;
    seos_native_peripheral->bt = furi_record_open(RECORD_BT);

    seos_native_peripheral->phase = SELECT_AID;
    seos_native_peripheral->secure_messaging = NULL;
    seos_native_peripheral->params.key_no = 1;
    memset(
        seos_native_peripheral->params.cNonce,
        0x0c,
        sizeof(seos_native_peripheral->params.cNonce));
    memset(seos_native_peripheral->params.UID, 0x0d, sizeof(seos_native_peripheral->params.UID));

    seos_native_peripheral->thread = furi_thread_alloc_ex(
        "SeosNativePeripheralWorker",
        5 * 1024,
        seos_native_peripheral_task,
        seos_native_peripheral);
    seos_native_peripheral->messages =
        furi_message_queue_alloc(MESSAGE_QUEUE_SIZE, sizeof(NativePeripheralMessage));
    seos_native_peripheral->mq_mutex = furi_mutex_alloc(FuriMutexTypeNormal);

    return seos_native_peripheral;
}

void seos_native_peripheral_free(SeosNativePeripheral* seos_native_peripheral) {
    furi_assert(seos_native_peripheral);

    furi_record_close(RECORD_BT);

    furi_message_queue_free(seos_native_peripheral->messages);
    furi_mutex_free(seos_native_peripheral->mq_mutex);
    furi_thread_free(seos_native_peripheral->thread);

    free(seos_native_peripheral);
}

void seos_native_peripheral_start(SeosNativePeripheral* seos_native_peripheral, FlowMode mode) {
    UNUSED(mode);
    bt_disconnect(seos_native_peripheral->bt);

    // Wait 2nd core to update nvm storage
    furi_delay_ms(200);
    seos_native_peripheral->ble_profile =
        bt_profile_start(seos_native_peripheral->bt, ble_profile_seos, NULL);
    furi_check(seos_native_peripheral->ble_profile);
    bt_set_status_changed_callback(
        seos_native_peripheral->bt, seos_ble_connection_status_callback, seos_native_peripheral);
    ble_profile_seos_set_event_callback(
        seos_native_peripheral->ble_profile,
        sizeof(seos_native_peripheral->event_buffer),
        seos_svc_callback,
        seos_native_peripheral);
    furi_hal_bt_start_advertising();
    view_dispatcher_send_custom_event(
        seos_native_peripheral->seos->view_dispatcher, SeosCustomEventAdvertising);

    furi_thread_start(seos_native_peripheral->thread);
}

void seos_native_peripheral_stop(SeosNativePeripheral* seos_native_peripheral) {
    furi_hal_bt_stop_advertising();
    bt_set_status_changed_callback(seos_native_peripheral->bt, NULL, NULL);
    bt_disconnect(seos_native_peripheral->bt);

    // Wait 2nd core to update nvm storage
    furi_delay_ms(200);
    bt_keys_storage_set_default_path(seos_native_peripheral->bt);

    furi_check(bt_profile_restore_default(seos_native_peripheral->bt));

    furi_thread_flags_set(furi_thread_get_id(seos_native_peripheral->thread), WorkerEvtStop);
    furi_thread_join(seos_native_peripheral->thread);
}

void seos_native_peripheral_process_message(
    SeosNativePeripheral* seos_native_peripheral,
    NativePeripheralMessage message) {
    BitBuffer* response = bit_buffer_alloc(128); // TODO: MTU

    uint8_t* data = message.buf;
    uint8_t* rx_data = data + 1; // Match name to nfc version for easier copying
    seos_log_buffer(TAG, "seos_svc_callback", data, message.len);

    if(data[0] != BLE_START && data[0] != 0xe1) {
        FURI_LOG_W(TAG, "Unexpected start of BLE packet");
    }

    if(memcmp(data + 5, standard_seos_aid, sizeof(standard_seos_aid)) == 0) { // response to select
        FURI_LOG_I(TAG, "Select ADF");
        uint8_t select_adf_header[] = {
            0x80, 0xa5, 0x04, 0x00, (uint8_t)SEOS_ADF_OID_LEN + 2, 0x06, (uint8_t)SEOS_ADF_OID_LEN};

        bit_buffer_append_bytes(response, select_adf_header, sizeof(select_adf_header));
        bit_buffer_append_bytes(response, SEOS_ADF_OID, SEOS_ADF_OID_LEN);
        seos_native_peripheral->phase = SELECT_ADF;

    } else if(memcmp(data + 1, cd02, sizeof(cd02)) == 0) {
        BitBuffer* attribute_value = bit_buffer_alloc(message.len);
        bit_buffer_append_bytes(attribute_value, message.buf, message.len);
        if(seos_reader_select_adf_response(
               attribute_value,
               1,
               seos_native_peripheral->credential,
               &seos_native_peripheral->params)) {
            // Craft response
            general_authenticate_1[3] = seos_native_peripheral->params.key_no;
            bit_buffer_append_bytes(
                response, general_authenticate_1, sizeof(general_authenticate_1));
            seos_native_peripheral->phase = GENERAL_AUTHENTICATION_1;
        }
        bit_buffer_free(attribute_value);
    } else if(memcmp(data + 1, ga1_response, sizeof(ga1_response)) == 0) {
        memcpy(seos_native_peripheral->params.rndICC, data + 5, 8);

        // Craft response
        uint8_t cryptogram[32 + 8];
        memset(cryptogram, 0, sizeof(cryptogram));
        seos_reader_generate_cryptogram(
            seos_native_peripheral->credential, &seos_native_peripheral->params, cryptogram);

        uint8_t ga_header[] = {
            0x00,
            0x87,
            0x00,
            seos_native_peripheral->params.key_no,
            sizeof(cryptogram) + 4,
            0x7c,
            sizeof(cryptogram) + 2,
            0x82,
            sizeof(cryptogram)};

        bit_buffer_append_bytes(response, ga_header, sizeof(ga_header));
        bit_buffer_append_bytes(response, cryptogram, sizeof(cryptogram));

        seos_native_peripheral->phase = GENERAL_AUTHENTICATION_2;
    } else if(rx_data[0] == 0x7C && rx_data[2] == 0x82) { // ga2 response
        if(rx_data[3] == 40) {
            if(!seos_reader_verify_cryptogram(&seos_native_peripheral->params, rx_data + 4)) {
                FURI_LOG_W(TAG, "Card cryptogram failed verification");
                bit_buffer_free(response);
                return;
            }
            FURI_LOG_I(TAG, "Authenticated");
            view_dispatcher_send_custom_event(
                seos_native_peripheral->seos->view_dispatcher, SeosCustomEventAuthenticated);
        } else {
            FURI_LOG_W(TAG, "Unhandled card cryptogram size %d", rx_data[3]);
        }

        seos_native_peripheral->secure_messaging =
            secure_messaging_alloc(&seos_native_peripheral->params);

        SecureMessaging* secure_messaging = seos_native_peripheral->secure_messaging;

        uint8_t message[] = {0x5c, 0x02, 0xff, 0x00};
        secure_messaging_wrap_apdu(secure_messaging, message, sizeof(message), response);
        seos_native_peripheral->phase = REQUEST_SIO;
        view_dispatcher_send_custom_event(
            seos_native_peripheral->seos->view_dispatcher, SeosCustomEventSIORequested);
    } else if(seos_native_peripheral->phase == REQUEST_SIO) {
        SecureMessaging* secure_messaging = seos_native_peripheral->secure_messaging;

        BitBuffer* rx_buffer = bit_buffer_alloc(message.len - 1);
        bit_buffer_append_bytes(rx_buffer, rx_data, message.len - 1);
        seos_log_bitbuffer(TAG, "BLE response(wrapped)", rx_buffer);
        secure_messaging_unwrap_rapdu(secure_messaging, rx_buffer);
        seos_log_bitbuffer(TAG, "BLE response(clear)", rx_buffer);

        // Skip fileId
        seos_native_peripheral->credential->sio_len = bit_buffer_get_byte(rx_buffer, 2);
        if(seos_native_peripheral->credential->sio_len >
           sizeof(seos_native_peripheral->credential->sio)) {
            FURI_LOG_W(TAG, "SIO too long to save");
            bit_buffer_free(response);
            return;
        }
        memcpy(
            seos_native_peripheral->credential->sio,
            bit_buffer_get_data(rx_buffer) + 3,
            seos_native_peripheral->credential->sio_len);
        FURI_LOG_I(TAG, "SIO Captured, %d bytes", seos_native_peripheral->credential->sio_len);

        Seos* seos = seos_native_peripheral->seos;
        view_dispatcher_send_custom_event(seos->view_dispatcher, SeosCustomEventReaderSuccess);
        bit_buffer_free(rx_buffer);

        seos_native_peripheral->phase = SELECT_AID;

    } else if(data[0] == 0xe1) {
        //ignore
    } else {
        FURI_LOG_W(TAG, "No match for write request");
    }

    if(bit_buffer_get_size_bytes(response) > 0) {
        BitBuffer* tx = bit_buffer_alloc(1 + 2 + 1 + bit_buffer_get_size_bytes(response));

        bit_buffer_append_byte(tx, BLE_START);
        bit_buffer_append_bytes(
            tx, bit_buffer_get_data(response), bit_buffer_get_size_bytes(response));
        ble_profile_seos_tx(
            seos_native_peripheral->ble_profile,
            (uint8_t*)bit_buffer_get_data(tx),
            bit_buffer_get_size_bytes(tx));
        bit_buffer_free(tx);
    }

    bit_buffer_free(response);
}

int32_t seos_native_peripheral_task(void* context) {
    SeosNativePeripheral* seos_native_peripheral = (SeosNativePeripheral*)context;
    bool running = true;

    while(running) {
        uint32_t events = furi_thread_flags_get();
        if(events & WorkerEvtStop) {
            running = false;
            break;
        }

        if(furi_mutex_acquire(seos_native_peripheral->mq_mutex, 1) == FuriStatusOk) {
            uint32_t count = furi_message_queue_get_count(seos_native_peripheral->messages);
            if(count > 0) {
                if(count > MESSAGE_QUEUE_SIZE / 2) {
                    FURI_LOG_I(TAG, "Dequeue message [%ld messages]", count);
                }

                NativePeripheralMessage message = {};
                FuriStatus status = furi_message_queue_get(
                    seos_native_peripheral->messages, &message, FuriWaitForever);
                if(status != FuriStatusOk) {
                    FURI_LOG_W(TAG, "furi_message_queue_get fail %d", status);
                }

                seos_native_peripheral_process_message(seos_native_peripheral, message);
            }
            furi_mutex_release(seos_native_peripheral->mq_mutex);
        } else {
            FURI_LOG_W(TAG, "Failed to acquire mutex");
        }

        // A beat for event flags
        furi_delay_ms(1);
    }

    return 0;
}
