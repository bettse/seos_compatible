#include "../seos_i.h"
#include <dolphin/dolphin.h>

#define TAG "SeosSceneMigrateKeys"

void seos_scene_migrate_keys_widget_callback(GuiButtonType result, InputType type, void* context) {
    furi_assert(context);
    Seos* seos = context;

    if(type == InputTypeShort) {
        view_dispatcher_send_custom_event(seos->view_dispatcher, result);
    }
}

void seos_scene_migrate_keys_on_enter(void* context) {
    Seos* seos = context;
    Widget* widget = seos->widget;

    FuriString* one = furi_string_alloc_set("Migrate keys from v1");
    FuriString* two = furi_string_alloc_set("to v2, which features");
    FuriString* three = furi_string_alloc_set("per-device encryption");

    widget_add_button_element(
        widget, GuiButtonTypeCenter, "Do it", seos_scene_migrate_keys_widget_callback, seos);

    widget_add_string_element(
        widget, 0, 0, AlignLeft, AlignTop, FontKeyboard, furi_string_get_cstr(one));

    widget_add_string_element(
        widget, 0, 10, AlignLeft, AlignTop, FontKeyboard, furi_string_get_cstr(two));

    widget_add_string_element(
        widget, 0, 20, AlignLeft, AlignTop, FontKeyboard, furi_string_get_cstr(three));

    furi_string_free(one);
    furi_string_free(two);
    furi_string_free(three);
    view_dispatcher_switch_to_view(seos->view_dispatcher, SeosViewWidget);
}

bool seos_scene_migrate_keys_on_event(void* context, SceneManagerEvent event) {
    Seos* seos = context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == GuiButtonTypeCenter) {
            seos_migrate_keys(seos);
            scene_manager_search_and_switch_to_previous_scene(
                seos->scene_manager, SeosSceneMainMenu);
            consumed = true;
        }
    } else if(event.type == SceneManagerEventTypeBack) {
        scene_manager_search_and_switch_to_previous_scene(seos->scene_manager, SeosSceneMainMenu);
        consumed = true;
    }
    return consumed;
}

void seos_scene_migrate_keys_on_exit(void* context) {
    Seos* seos = context;

    // Clear view
    widget_reset(seos->widget);
}
