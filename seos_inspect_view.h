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

// Point the view at a finished inspection and reset it to the first page. The
// data must outlive the view (it lives in the emulator).
void seos_inspect_view_set_data(SeosInspectView* instance, const SeosInspectData* data);

#ifdef __cplusplus
}
#endif
