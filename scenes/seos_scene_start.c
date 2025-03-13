#include "../seos_i.h"

#define TAG "SceneStart"

enum SubmenuIndex {
    SubmenuIndexSaved,
    SubmenuIndexRead,
    SubmenuIndexBLEReader,
    SubmenuIndexScannerMenu,
    SubmenuIndexBLECredInterrogate,
    SubmenuIndexAbout,
};

static SeosHci* seos_hci = NULL;
static int8_t ble_checks;

void seos_scene_start_submenu_callback(void* context, uint32_t index) {
    Seos* seos = context;
    view_dispatcher_send_custom_event(seos->view_dispatcher, index);
}

void seos_scene_start_on_update(void* context) {
    Seos* seos = context;
    Submenu* submenu = seos->submenu;
    submenu_reset(submenu);

    submenu_add_item(submenu, "Saved", SubmenuIndexSaved, seos_scene_start_submenu_callback, seos);
    submenu_add_item(
        submenu, "Read NFC", SubmenuIndexRead, seos_scene_start_submenu_callback, seos);
    if(seos->has_ble) {
        submenu_add_item(
            submenu,
            "Start BLE Reader",
            SubmenuIndexBLEReader,
            seos_scene_start_submenu_callback,
            seos);
        submenu_add_item(
            submenu,
            "Scanners >",
            SubmenuIndexScannerMenu,
            seos_scene_start_submenu_callback,
            seos);
        submenu_add_item(
            submenu,
            "BLE Cred Interrogate",
            SubmenuIndexBLECredInterrogate,
            seos_scene_start_submenu_callback,
            seos);
    }
    submenu_add_item(submenu, "About", SubmenuIndexAbout, seos_scene_start_submenu_callback, seos);

    submenu_set_selected_item(
        seos->submenu, scene_manager_get_scene_state(seos->scene_manager, SeosSceneStart));

    view_dispatcher_switch_to_view(seos->view_dispatcher, SeosViewMenu);
}

void seos_scene_start_on_enter(void* context) {
    Seos* seos = context;
    // Dont' check if we've checked before
    if(seos->has_ble == false) {
        ble_checks = 3;
        seos_hci = seos_hci_alloc(seos);
        seos_hci_start(seos_hci, BLE_PERIPHERAL, FLOW_TEST);
    }

    seos_scene_start_on_update(context);
}

bool seos_scene_start_on_event(void* context, SceneManagerEvent event) {
    Seos* seos = context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == SubmenuIndexRead) {
            scene_manager_set_scene_state(seos->scene_manager, SeosSceneStart, SubmenuIndexRead);
            scene_manager_next_scene(seos->scene_manager, SeosSceneRead);
            consumed = true;
        } else if(event.event == SubmenuIndexBLEReader) {
            scene_manager_set_scene_state(
                seos->scene_manager, SeosSceneStart, SubmenuIndexBLEReader);
            seos->flow_mode = FLOW_READER;
            scene_manager_next_scene(seos->scene_manager, SeosSceneBlePeripheral);
            consumed = true;
        } else if(event.event == SubmenuIndexScannerMenu) {
            scene_manager_set_scene_state(
                seos->scene_manager, SeosSceneStart, SubmenuIndexScannerMenu);
            scene_manager_next_scene(seos->scene_manager, SeosSceneScannerMenu);
            consumed = true;
        } else if(event.event == SubmenuIndexBLECredInterrogate) {
            scene_manager_set_scene_state(
                seos->scene_manager, SeosSceneStart, SubmenuIndexBLECredInterrogate);
            seos->flow_mode = FLOW_READER;
            scene_manager_next_scene(seos->scene_manager, SeosSceneBleDevice);
            consumed = true;
        } else if(event.event == SubmenuIndexSaved) {
            scene_manager_set_scene_state(seos->scene_manager, SeosSceneStart, SubmenuIndexSaved);
            scene_manager_next_scene(seos->scene_manager, SeosSceneFileSelect);
            consumed = true;
        } else if(event.event == SubmenuIndexAbout) {
            scene_manager_set_scene_state(seos->scene_manager, SeosSceneStart, SubmenuIndexAbout);
            scene_manager_next_scene(seos->scene_manager, SeosSceneAbout);
            consumed = true;
        } else if(event.event == SeosCustomEventHCIInit) {
            seos->has_ble = true;
            FURI_LOG_I(TAG, "HCI Init");
            if(seos_hci) {
                seos_hci_stop(seos_hci);
                seos_hci_free(seos_hci);
                seos_hci = NULL;
            }
        }
    } else if(event.type == SceneManagerEventTypeTick) {
        if(ble_checks > 0) {
            FURI_LOG_D(TAG, "ble check %d has_ble %d", ble_checks, seos->has_ble);
            ble_checks--;
            if(seos->has_ble) {
                ble_checks = 0;
                seos_scene_start_on_update(context);
            }
        }
    }

    return consumed;
}

void seos_scene_start_on_exit(void* context) {
    Seos* seos = context;

    if(seos_hci) {
        seos_hci_stop(seos_hci);
        seos_hci_free(seos_hci);
        seos_hci = NULL;
    }

    submenu_reset(seos->submenu);
}
