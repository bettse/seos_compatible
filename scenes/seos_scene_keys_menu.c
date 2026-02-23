#include "../seos_i.h"

#define TAG "SceneKeysMenu"

#define SEOS_MAX_KEY_FILES 8

enum SubmenuIndex {
    SubmenuIndexZeroKeys = 0,
    SubmenuIndexKeyFileStart = 1,
};

void seos_scene_keys_menu_submenu_callback(void* context, uint32_t index) {
    Seos* seos = context;
    view_dispatcher_send_custom_event(seos->view_dispatcher, index);
}

void seos_scene_keys_menu_on_enter(void* context) {
    Seos* seos = context;
    Submenu* submenu = seos->submenu;
    submenu_reset(submenu);

    bool zero_active = !seos->keys_loaded;
    submenu_add_item(
        submenu,
        zero_active ? "Zero Keys *" : "Zero Keys",
        SubmenuIndexZeroKeys,
        seos_scene_keys_menu_submenu_callback,
        seos);

    // Scan for key files
    seos->key_file_count = 0;
    File* dir = storage_file_alloc(seos->credential->storage);
    if(storage_dir_open(dir, STORAGE_APP_DATA_PATH_PREFIX)) {
        FileInfo info;
        char name[256];
        while(storage_dir_read(dir, &info, name, sizeof(name))) {
            if(seos->key_file_count >= SEOS_MAX_KEY_FILES) break;
            if(info.flags & FSF_DIRECTORY) continue;
            size_t len = strlen(name);
            if(len < 5) continue;
            if(strcmp(name + len - 4, ".txt") != 0) continue;

            bool is_keys = (strcmp(name, "keys.txt") == 0);
            bool is_x_keys = (len > 9 && strcmp(name + len - 9, "_keys.txt") == 0);
            if(!is_keys && !is_x_keys) continue;

            // Store base name (without .txt)
            size_t base_len = len - 4;
            if(base_len > SEOS_FILE_NAME_MAX_LENGTH) base_len = SEOS_FILE_NAME_MAX_LENGTH;
            memcpy(seos->key_files[seos->key_file_count], name, base_len);
            seos->key_files[seos->key_file_count][base_len] = '\0';

            bool is_active = seos->keys_loaded &&
                             furi_string_equal_str(
                                 seos->active_key_file, seos->key_files[seos->key_file_count]);

            char label[SEOS_FILE_NAME_MAX_LENGTH + 4];
            snprintf(
                label,
                sizeof(label),
                is_active ? "%s *" : "%s",
                seos->key_files[seos->key_file_count]);

            submenu_add_item(
                submenu,
                label,
                SubmenuIndexKeyFileStart + seos->key_file_count,
                seos_scene_keys_menu_submenu_callback,
                seos);

            seos->key_file_count++;
        }
        storage_dir_close(dir);
    }
    storage_file_free(dir);

    submenu_set_selected_item(
        seos->submenu, scene_manager_get_scene_state(seos->scene_manager, SeosSceneKeysMenu));

    view_dispatcher_switch_to_view(seos->view_dispatcher, SeosViewMenu);
}

bool seos_scene_keys_menu_on_event(void* context, SceneManagerEvent event) {
    Seos* seos = context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == SubmenuIndexZeroKeys) {
            seos_reset_to_zero_keys(seos);
            scene_manager_search_and_switch_to_previous_scene(
                seos->scene_manager, SeosSceneMainMenu);
            consumed = true;
        } else if(
            event.event >= SubmenuIndexKeyFileStart &&
            event.event < (uint32_t)(SubmenuIndexKeyFileStart + seos->key_file_count)) {
            uint8_t file_index = event.event - SubmenuIndexKeyFileStart;
            if(seos_load_keys_from_file(seos, seos->key_files[file_index])) {
                if(seos->keys_version == 1) {
                    // v1 keys: ask user if they want to migrate
                    scene_manager_next_scene(seos->scene_manager, SeosSceneMigrateKeys);
                } else {
                    scene_manager_search_and_switch_to_previous_scene(
                        seos->scene_manager, SeosSceneMainMenu);
                }
            }
            consumed = true;
        }
    }

    return consumed;
}

void seos_scene_keys_menu_on_exit(void* context) {
    Seos* seos = context;
    submenu_reset(seos->submenu);
}
