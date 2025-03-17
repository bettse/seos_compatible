#include "seos_service.h"
#include "app_common.h"
//#include <ble/ble.h>
#include <furi_ble/event_dispatcher.h>
#include <furi_ble/gatt.h>

#include "ble_vs_codes.h"
#include "ble_gatt_aci.h"

#include <furi.h>

#include "seos_service_uuid.inc"
#include <stdint.h>

#define TAG "BtSeosSvc"

typedef enum {
    SeosSvcGattCharacteristicRxTx = 0,
    SeosSvcGattCharacteristicCount,
} SeosSvcGattCharacteristicId;

typedef struct {
    const void* data_ptr;
    uint16_t data_len;
} SeosSvcDataWrapper;

static bool
    ble_svc_seos_data_callback(const void* context, const uint8_t** data, uint16_t* data_len) {
    FURI_LOG_D(TAG, "ble_svc_seos_data_callback");
    const SeosSvcDataWrapper* report_data = context;
    if(data) {
        *data = report_data->data_ptr;
        *data_len = report_data->data_len;
    } else {
        *data_len = BLE_SVC_SEOS_DATA_LEN_MAX;
    }
    return false;
}

static const BleGattCharacteristicParams ble_svc_seos_chars[SeosSvcGattCharacteristicCount] = {
    [SeosSvcGattCharacteristicRxTx] =
        {.name = "SEOS",
         .data_prop_type = FlipperGattCharacteristicDataCallback,
         .data.callback.fn = ble_svc_seos_data_callback,
         .data.callback.context = NULL,
         //.max_length = BLE_SVC_SEOS_DATA_LEN_MAX,
         .uuid.Char_UUID_128 = BLE_SVC_SEOS_CHAR_UUID,
         .uuid_type = UUID_TYPE_128,
         .char_properties = CHAR_PROP_WRITE_WITHOUT_RESP | CHAR_PROP_NOTIFY,
         .security_permissions = ATTR_PERMISSION_NONE,
         .gatt_evt_mask = GATT_NOTIFY_ATTRIBUTE_WRITE,
         .is_variable = CHAR_VALUE_LEN_VARIABLE},
};

struct BleServiceSeos {
    uint16_t svc_handle;
    BleGattCharacteristicInstance chars[SeosSvcGattCharacteristicCount];
    FuriMutex* buff_size_mtx;
    uint32_t buff_size;
    uint16_t bytes_ready_to_receive;
    SeosServiceEventCallback callback;
    void* context;
    GapSvcEventHandler* event_handler;
};

static BleEventAckStatus ble_svc_seos_event_handler(void* event, void* context) {
    FURI_LOG_D(TAG, "ble_svc_seos_event_handler");
    BleServiceSeos* seos_svc = (BleServiceSeos*)context;
    BleEventAckStatus ret = BleEventNotAck;
    hci_event_pckt* event_pckt = (hci_event_pckt*)(((hci_uart_pckt*)event)->data);
    evt_blecore_aci* blecore_evt = (evt_blecore_aci*)event_pckt->data;
    aci_gatt_attribute_modified_event_rp0* attribute_modified;

    if(event_pckt->evt == HCI_LE_META_EVT_CODE) {
        // FURI_LOG_D(TAG, "ble_svc_seos_event_handler HCI_LE_META_EVT_CODE %02x", event_pckt->data[0]);
    } else if(event_pckt->evt == HCI_DISCONNECTION_COMPLETE_EVT_CODE) {
    } else if(event_pckt->evt == HCI_VENDOR_SPECIFIC_DEBUG_EVT_CODE) {
        if(blecore_evt->ecode == ACI_GATT_ATTRIBUTE_MODIFIED_VSEVT_CODE) {
            FURI_LOG_D(TAG, "Process modification events");
            attribute_modified = (aci_gatt_attribute_modified_event_rp0*)blecore_evt->data;
            if(attribute_modified->Attr_Handle ==
               seos_svc->chars[SeosSvcGattCharacteristicRxTx].handle + 2) {
                // Descriptor handle
                ret = BleEventAckFlowEnable;
                if(attribute_modified->Attr_Data_Length == 2) {
                    uint16_t* value = (uint16_t*)attribute_modified->Attr_Data;
                    FURI_LOG_D(TAG, "descriptor event %04x", *value);
                    if(*value == 1) { // ENABLE_NOTIFICATION_VALUE)
                        uint8_t select_header[] = {0xc0, 0x00, 0xa4, 0x04, 0x00};

                        SeosSvcDataWrapper report_data = {
                            .data_ptr = select_header, .data_len = sizeof(select_header)};

                        ble_gatt_characteristic_update(
                            seos_svc->svc_handle,
                            &seos_svc->chars[SeosSvcGattCharacteristicRxTx],
                            &report_data);
                    }
                } else {
                    FURI_LOG_D(
                        TAG, "descriptor event %d bytes", attribute_modified->Attr_Data_Length);
                }

            } else if(
                attribute_modified->Attr_Handle ==
                seos_svc->chars[SeosSvcGattCharacteristicRxTx].handle + 1) {
                FURI_LOG_D(TAG, "Received %d bytes", attribute_modified->Attr_Data_Length);
                if(seos_svc->callback) {
                    furi_check(
                        furi_mutex_acquire(seos_svc->buff_size_mtx, FuriWaitForever) ==
                        FuriStatusOk);
                    if(attribute_modified->Attr_Data_Length > seos_svc->bytes_ready_to_receive) {
                        FURI_LOG_W(
                            TAG,
                            "Received %d, while was ready to receive %d bytes. Can lead to buffer overflow!",
                            attribute_modified->Attr_Data_Length,
                            seos_svc->bytes_ready_to_receive);
                    }
                    seos_svc->bytes_ready_to_receive -= MIN(
                        seos_svc->bytes_ready_to_receive, attribute_modified->Attr_Data_Length);
                    SeosServiceEvent event = {
                        .event = SeosServiceEventTypeDataReceived,
                        .data = {
                            .buffer = attribute_modified->Attr_Data,
                            .size = attribute_modified->Attr_Data_Length,
                        }};
                    uint32_t buff_free_size = seos_svc->callback(event, seos_svc->context);
                    FURI_LOG_D(TAG, "Available buff size: %ld", buff_free_size);
                    furi_check(furi_mutex_release(seos_svc->buff_size_mtx) == FuriStatusOk);
                } else {
                    FURI_LOG_W(TAG, "No seos_cvs->callback defined");
                }
                ret = BleEventAckFlowEnable;
            }
        } else if(blecore_evt->ecode == ACI_GATT_SERVER_CONFIRMATION_VSEVT_CODE) {
            FURI_LOG_T(TAG, "Ack received");
            if(seos_svc->callback) {
                SeosServiceEvent event = {
                    .event = SeosServiceEventTypeDataSent,
                };
                seos_svc->callback(event, seos_svc->context);
            }
            ret = BleEventAckFlowEnable;
        } else {
            FURI_LOG_D(
                TAG,
                "ble_svc_seos_event_handler unhandled blecore_evt->ecode %d",
                blecore_evt->ecode);
        }
    } else {
        FURI_LOG_D(
            TAG, "ble_svc_seos_event_handler unhandled event_pckt->evt %d", event_pckt->evt);
    }
    return ret;
}

BleServiceSeos* ble_svc_seos_start(void) {
    FURI_LOG_D(TAG, "ble_svc_seos_start");
    BleServiceSeos* seos_svc = malloc(sizeof(BleServiceSeos));

    seos_svc->event_handler =
        ble_event_dispatcher_register_svc_handler(ble_svc_seos_event_handler, seos_svc);

    if(!ble_gatt_service_add(
           UUID_TYPE_128, &service_uuid, PRIMARY_SERVICE, 12, &seos_svc->svc_handle)) {
        free(seos_svc);
        return NULL;
    }
    for(uint8_t i = 0; i < SeosSvcGattCharacteristicCount; i++) {
        FURI_LOG_D(TAG, "ble_gatt_characteristic_init %d", i);
        ble_gatt_characteristic_init(
            seos_svc->svc_handle, &ble_svc_seos_chars[i], &seos_svc->chars[i]);
    }

    seos_svc->buff_size_mtx = furi_mutex_alloc(FuriMutexTypeNormal);

    return seos_svc;
}

void ble_svc_seos_set_callbacks(
    BleServiceSeos* seos_svc,
    uint16_t buff_size,
    SeosServiceEventCallback callback,
    void* context) {
    furi_check(seos_svc);
    FURI_LOG_D(TAG, "ble_svc_seos_set_callbacks");
    seos_svc->callback = callback;
    seos_svc->context = context;
    seos_svc->buff_size = buff_size;
    seos_svc->bytes_ready_to_receive = buff_size;

    /*
    uint32_t buff_size_reversed = REVERSE_BYTES_U32(seos_svc->buff_size);
    ble_gatt_characteristic_update(
        seos_svc->svc_handle,
        &seos_svc->chars[SeosSvcGattCharacteristicFlowCtrl],
        &buff_size_reversed);
        */
}

void ble_svc_seos_notify_buffer_is_empty(BleServiceSeos* seos_svc) {
    furi_check(seos_svc);
    furi_check(seos_svc->buff_size_mtx);
    FURI_LOG_D(TAG, "ble_svc_seos_notify_buffer_is_empty");

    furi_check(furi_mutex_acquire(seos_svc->buff_size_mtx, FuriWaitForever) == FuriStatusOk);
    if(seos_svc->bytes_ready_to_receive == 0) {
        FURI_LOG_D(TAG, "Buffer is empty. Notifying client");
        seos_svc->bytes_ready_to_receive = seos_svc->buff_size;

        /*
        uint32_t buff_size_reversed = REVERSE_BYTES_U32(seos_svc->buff_size);
        ble_gatt_characteristic_update(
            seos_svc->svc_handle,
            &seos_svc->chars[SeosSvcGattCharacteristicFlowCtrl],
            &buff_size_reversed);
            */
    }
    furi_check(furi_mutex_release(seos_svc->buff_size_mtx) == FuriStatusOk);
}

void ble_svc_seos_stop(BleServiceSeos* seos_svc) {
    furi_check(seos_svc);

    ble_event_dispatcher_unregister_svc_handler(seos_svc->event_handler);

    for(uint8_t i = 0; i < SeosSvcGattCharacteristicCount; i++) {
        ble_gatt_characteristic_delete(seos_svc->svc_handle, &seos_svc->chars[i]);
    }
    ble_gatt_service_delete(seos_svc->svc_handle);
    furi_mutex_free(seos_svc->buff_size_mtx);
    free(seos_svc);
}

bool ble_svc_seos_update_tx(BleServiceSeos* seos_svc, uint8_t* data, uint16_t data_len) {
    FURI_LOG_D(TAG, "ble_svc_seos_update_tx");
    UNUSED(seos_svc);
    UNUSED(data);
    if(data_len > BLE_SVC_SEOS_DATA_LEN_MAX) {
        return false;
    }

    /*
    for(uint16_t remained = data_len; remained > 0;) {
        uint8_t value_len = MIN(BLE_SVC_SEOS_CHAR_VALUE_LEN_MAX, remained);
        uint16_t value_offset = data_len - remained;
        remained -= value_len;

        tBleStatus result = aci_gatt_update_char_value_ext(
            0,
            seos_svc->svc_handle,
            seos_svc->chars[SeosSvcGattCharacteristicTx].handle,
            remained ? 0x00 : 0x02,
            data_len,
            value_offset,
            value_len,
            data + value_offset);

        if(result) {
            FURI_LOG_E(TAG, "Failed updating TX characteristic: %d", result);
            return false;
        }
    }
    */

    return true;
}
