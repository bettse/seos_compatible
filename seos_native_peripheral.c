#include "seos_native_peripheral_i.h"

#define TAG "SeosNativePeripheral"

static void seos_ble_connection_status_callback(BtStatus status, void* context) {
    furi_assert(context);
    SeosNativePeripheral* seos_native_peripheral = context;
    FURI_LOG_D(TAG, "seos_ble_connection_status_callback %d", (status == BtStatusConnected));
    if(status == BtStatusConnected) {
        view_dispatcher_send_custom_event(
            seos_native_peripheral->seos->view_dispatcher, SeosCustomEventConnected);
    } else if (status == BtStatusAdvertising) {
        view_dispatcher_send_custom_event(
            seos_native_peripheral->seos->view_dispatcher, SeosCustomEventAdvertising);
    }
}

static uint16_t seos_svc_callback(SeosServiceEvent event, void* context) {
    FURI_LOG_D(TAG, "seos_svc_callback");
    SeosNativePeripheral* seos_native_peripheral = context;
    UNUSED(seos_native_peripheral);
    UNUSED(event);
    return 0;
}

SeosNativePeripheral* seos_native_peripheral_alloc(Seos* seos) {
    SeosNativePeripheral* seos_native_peripheral = malloc(sizeof(SeosNativePeripheral));
    memset(seos_native_peripheral, 0, sizeof(SeosNativePeripheral));

    seos_native_peripheral->seos = seos;
    seos_native_peripheral->bt = furi_record_open(RECORD_BT);

    return seos_native_peripheral;
}

void seos_native_peripheral_free(SeosNativePeripheral* seos_native_peripheral) {
    furi_assert(seos_native_peripheral);

    furi_record_close(RECORD_BT);

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
        seos_native_peripheral->ble_profile, 32, seos_svc_callback, seos_native_peripheral);
    furi_hal_bt_start_advertising();
    view_dispatcher_send_custom_event(
        seos_native_peripheral->seos->view_dispatcher, SeosCustomEventAdvertising);
}

void seos_native_peripheral_stop(SeosNativePeripheral* seos_native_peripheral) {
    furi_hal_bt_stop_advertising();
    bt_set_status_changed_callback(seos_native_peripheral->bt, NULL, NULL);
    bt_disconnect(seos_native_peripheral->bt);

    // Wait 2nd core to update nvm storage
    furi_delay_ms(200);
    bt_keys_storage_set_default_path(seos_native_peripheral->bt);

    furi_check(bt_profile_restore_default(seos_native_peripheral->bt));
}
