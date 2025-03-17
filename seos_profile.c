#include "seos_profile.h"

#include <gap.h>
#include <furi_ble/profile_interface.h>
#include "seos_service.h"
#include <furi.h>

typedef struct {
    FuriHalBleProfileBase base;

    BleServiceSeos* seos_svc;
} BleProfileSeos;
_Static_assert(offsetof(BleProfileSeos, base) == 0, "Wrong layout");

static FuriHalBleProfileBase* ble_profile_seos_start(FuriHalBleProfileParams profile_params) {
    UNUSED(profile_params);

    BleProfileSeos* profile = malloc(sizeof(BleProfileSeos));

    profile->base.config = ble_profile_seos;

    profile->seos_svc = ble_svc_seos_start();

    return &profile->base;
}

static void ble_profile_seos_stop(FuriHalBleProfileBase* profile) {
    furi_check(profile);
    furi_check(profile->config == ble_profile_seos);

    BleProfileSeos* seos_profile = (BleProfileSeos*)profile;
    ble_svc_seos_stop(seos_profile->seos_svc);
}

// AN5289: 4.7, in order to use flash controller interval must be at least 25ms + advertisement, which is 30 ms
// Since we don't use flash controller anymore interval can be lowered to 7.5ms
#define CONNECTION_INTERVAL_MIN (0x06)
// Up to 45 ms
#define CONNECTION_INTERVAL_MAX (0x24)

static GapConfig seos_template_config = {
    .adv_service_uuid = 0x3080,
    .appearance_char = 0x8600,
    .bonding_mode = true,
    .pairing_method = GapPairingPinCodeShow,
    .conn_param = {
        .conn_int_min = CONNECTION_INTERVAL_MIN,
        .conn_int_max = CONNECTION_INTERVAL_MAX,
        .slave_latency = 0,
        .supervisor_timeout = 0,
    }};

static void
    ble_profile_seos_get_config(GapConfig* config, FuriHalBleProfileParams profile_params) {
    UNUSED(profile_params);

    furi_check(config);
    memcpy(config, &seos_template_config, sizeof(GapConfig));
    // Set mac address
    memcpy(config->mac_address, furi_hal_version_get_ble_mac(), sizeof(config->mac_address));
    // Set advertise name
    strlcpy(
        config->adv_name,
        furi_hal_version_get_ble_local_device_name_ptr(),
        FURI_HAL_VERSION_DEVICE_NAME_LENGTH);
    config->adv_service_uuid |= furi_hal_version_get_hw_color();
}

static const FuriHalBleProfileTemplate profile_callbacks = {
    .start = ble_profile_seos_start,
    .stop = ble_profile_seos_stop,
    .get_gap_config = ble_profile_seos_get_config,
};

const FuriHalBleProfileTemplate* ble_profile_seos = &profile_callbacks;

void ble_profile_seos_set_event_callback(
    FuriHalBleProfileBase* profile,
    uint16_t buff_size,
    FuriHalBtSeosCallback callback,
    void* context) {
    furi_check(profile && (profile->config == ble_profile_seos));

    BleProfileSeos* seos_profile = (BleProfileSeos*)profile;
    ble_svc_seos_set_callbacks(seos_profile->seos_svc, buff_size, callback, context);
}

void ble_profile_seos_notify_buffer_is_empty(FuriHalBleProfileBase* profile) {
    furi_check(profile && (profile->config == ble_profile_seos));

    BleProfileSeos* seos_profile = (BleProfileSeos*)profile;
    ble_svc_seos_notify_buffer_is_empty(seos_profile->seos_svc);
}

void ble_profile_seos_set_rpc_active(FuriHalBleProfileBase* profile, bool active) {
    furi_check(profile && (profile->config == ble_profile_seos));

    BleProfileSeos* seos_profile = (BleProfileSeos*)profile;
    ble_svc_seos_set_rpc_active(seos_profile->seos_svc, active);
}

bool ble_profile_seos_tx(FuriHalBleProfileBase* profile, uint8_t* data, uint16_t size) {
    furi_check(profile && (profile->config == ble_profile_seos));

    BleProfileSeos* seos_profile = (BleProfileSeos*)profile;

    if(size > BLE_PROFILE_SEOS_PACKET_SIZE_MAX) {
        return false;
    }

    return ble_svc_seos_update_tx(seos_profile->seos_svc, data, size);
}
