#include "../seos_i.h"
#include "seos_scene.h"

/* Second page of a finished inspection: which credential types the reader
 * accepts. */
static void seos_scene_inspect_credentials_left_callback(void* context) {
    Seos* seos = context;
    view_dispatcher_send_custom_event(seos->view_dispatcher, SeosCustomEventViewExit);
}

void seos_scene_inspect_credentials_on_enter(void* context) {
    Seos* seos = context;

    seos_inspect_view_set_data(seos->inspect_view, &seos->seos_emulator->inspect);
    seos_inspect_view_set_left_callback(
        seos->inspect_view, seos_scene_inspect_credentials_left_callback, seos);

    view_dispatcher_switch_to_view(seos->view_dispatcher, SeosViewInspect);
}

bool seos_scene_inspect_credentials_on_event(void* context, SceneManagerEvent event) {
    Seos* seos = context;
    bool consumed = false;

    if(event.type == SceneManagerEventTypeCustom) {
        if(event.event == SeosCustomEventViewExit) {
            consumed = scene_manager_previous_scene(seos->scene_manager);
        }
    }
    return consumed;
}

void seos_scene_inspect_credentials_on_exit(void* context) {
    Seos* seos = context;

    seos_inspect_view_set_left_callback(seos->inspect_view, NULL, NULL);
}
