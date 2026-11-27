#pragma once

#include <gui/view.h>

#include "seos_inspect.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SeosInspectView SeosInspectView;

SeosInspectView* seos_inspect_view_alloc(void);

void seos_inspect_view_free(SeosInspectView* instance);

View* seos_inspect_view_get_view(SeosInspectView* instance);

// Point the view at a finished inspection and scroll it back to the top. The
// data must outlive the view (it lives in the emulator).
void seos_inspect_view_set_data(SeosInspectView* instance, const SeosInspectData* data);

// Called when Left is pressed, which asks for the page before this one. Back
// is not handled here and goes to the scene manager as usual.
typedef void (*SeosInspectViewLeftCallback)(void* context);

void seos_inspect_view_set_left_callback(
    SeosInspectView* instance,
    SeosInspectViewLeftCallback callback,
    void* context);

#ifdef __cplusplus
}
#endif
