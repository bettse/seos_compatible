#include "seos_inspect_view.h"

#include <furi.h>
#include <gui/elements.h>

#define SCREEN_W      128
#define SCREEN_H      64
#define CRED_LINE_H   10
#define CRED_HEADER_H 16
#define CRED_VISIBLE  ((SCREEN_H - CRED_HEADER_H) / CRED_LINE_H)
#define CRED_TOTAL    (1 + SEOS_INSPECT_CRED_COUNT) // Seos row + items

typedef enum {
    SeosInspectPageReport,
    SeosInspectPageCredentials,
} SeosInspectPage;

typedef struct {
    const SeosInspectData* data;
    SeosInspectPage page;
    uint8_t cred_scroll;
} SeosInspectViewModel;

struct SeosInspectView {
    View* view;
};

static uint8_t cred_max_scroll(void) {
    return (CRED_TOTAL > CRED_VISIBLE) ? (CRED_TOTAL - CRED_VISIBLE) : 0;
}

static void draw_check(Canvas* canvas, int32_t x, int32_t y) {
    canvas_draw_line(canvas, x, y + 3, x + 2, y + 5);
    canvas_draw_line(canvas, x + 2, y + 5, x + 6, y);
}

static void draw_cross(Canvas* canvas, int32_t x, int32_t y) {
    canvas_draw_line(canvas, x, y, x + 5, y + 5);
    canvas_draw_line(canvas, x, y + 5, x + 5, y);
}

static void draw_report(Canvas* canvas, const SeosInspectData* d) {
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, SCREEN_W / 2, 0, AlignCenter, AlignTop, "Inspection Report");
    canvas_draw_line(canvas, 0, 13, SCREEN_W, 13);

    canvas_set_font(canvas, FontSecondary);
    int32_t y = 24;
    char buf[40];

    if(d->sam_ver) {
        snprintf(buf, sizeof(buf), "SAM:  0x%04X", d->sam_ver);
        canvas_draw_str(canvas, 4, y, buf);
        y += 11;
    }
    if(d->core_ver) {
        snprintf(buf, sizeof(buf), "Core: 0x%04X", d->core_ver);
        canvas_draw_str(canvas, 4, y, buf);
        y += 11;
    }
    if(d->assembly_count || d->persist_mem) {
        if(d->persist_mem)
            snprintf(
                buf, sizeof(buf), "Apps: %u   Mem: %luB", d->assembly_count,
                (unsigned long)d->persist_mem);
        else
            snprintf(buf, sizeof(buf), "Apps: %u", d->assembly_count);
        canvas_draw_str(canvas, 4, y, buf);
    } else if(!d->cred_parsed) {
        canvas_draw_str(canvas, 4, y, "Cred table: timeout");
    }

    elements_button_right(canvas, "Next Page");
}

static void draw_credentials(Canvas* canvas, const SeosInspectViewModel* m) {
    const SeosInspectData* d = m->data;
    canvas_set_font(canvas, FontPrimary);
    canvas_draw_str_aligned(canvas, SCREEN_W / 2, 2, AlignCenter, AlignTop, "Credential Config");
    canvas_draw_line(canvas, 0, 14, SCREEN_W, 14);

    canvas_set_font(canvas, FontSecondary);
    uint8_t max_scroll = cred_max_scroll();
    uint8_t scroll = (m->cred_scroll > max_scroll) ? max_scroll : m->cred_scroll;

    for(uint8_t i = 0; i < CRED_VISIBLE && (scroll + i) < CRED_TOTAL; i++) {
        uint8_t idx = scroll + i;
        int32_t y = CRED_HEADER_H + i * CRED_LINE_H;
        const char* name = (idx == 0) ? "Seos" : seos_inspect_cred_name(idx - 1);
        bool enabled = (idx == 0) ? d->seos_enabled : d->cred_enabled[idx - 1];

        canvas_draw_str(canvas, 4, y + 8, name);
        if(enabled)
            draw_check(canvas, SCREEN_W - 14, y + 2);
        else
            draw_cross(canvas, SCREEN_W - 14, y + 2);
    }

    if(scroll > 0)
        canvas_draw_str_aligned(canvas, SCREEN_W / 2, CRED_HEADER_H - 2, AlignCenter, AlignBottom, "~");
    if(scroll < max_scroll)
        canvas_draw_str_aligned(canvas, SCREEN_W / 2, SCREEN_H - 1, AlignCenter, AlignBottom, "~");
}

static void seos_inspect_view_draw(Canvas* canvas, void* model) {
    SeosInspectViewModel* m = model;
    canvas_clear(canvas);
    if(!m->data) return;

    if(m->page == SeosInspectPageCredentials)
        draw_credentials(canvas, m);
    else
        draw_report(canvas, m->data);
}

static bool seos_inspect_view_input(InputEvent* event, void* context) {
    SeosInspectView* instance = context;
    if(event->type != InputTypeShort && event->type != InputTypeRepeat) return false;

    bool consumed = false;
    bool redraw = false;
    with_view_model(
        instance->view,
        SeosInspectViewModel * m,
        {
            if(m->page == SeosInspectPageReport) {
                // Back is left unhandled so the scene manager can exit.
                if(event->key == InputKeyRight) {
                    m->cred_scroll = 0;
                    m->page = SeosInspectPageCredentials;
                    consumed = true;
                }
            } else {
                if(event->key == InputKeyLeft || event->key == InputKeyBack) {
                    m->page = SeosInspectPageReport;
                    consumed = true;
                } else if(event->key == InputKeyDown && m->cred_scroll < cred_max_scroll()) {
                    m->cred_scroll++;
                    consumed = true;
                } else if(event->key == InputKeyUp && m->cred_scroll > 0) {
                    m->cred_scroll--;
                    consumed = true;
                }
            }
            redraw = consumed;
        },
        redraw);

    return consumed;
}

SeosInspectView* seos_inspect_view_alloc(void) {
    SeosInspectView* instance = malloc(sizeof(SeosInspectView));
    instance->view = view_alloc();
    view_set_context(instance->view, instance);
    view_allocate_model(instance->view, ViewModelTypeLocking, sizeof(SeosInspectViewModel));
    view_set_draw_callback(instance->view, seos_inspect_view_draw);
    view_set_input_callback(instance->view, seos_inspect_view_input);
    return instance;
}

void seos_inspect_view_free(SeosInspectView* instance) {
    furi_assert(instance);
    view_free(instance->view);
    free(instance);
}

View* seos_inspect_view_get_view(SeosInspectView* instance) {
    furi_assert(instance);
    return instance->view;
}

void seos_inspect_view_set_data(SeosInspectView* instance, const SeosInspectData* data) {
    furi_assert(instance);
    with_view_model(
        instance->view,
        SeosInspectViewModel * m,
        {
            m->data = data;
            m->page = SeosInspectPageReport;
            m->cred_scroll = 0;
        },
        true);
}
