#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <furi.h>

#ifdef __cplusplus
extern "C" {
#endif

// Inspection walks a reader through the NfcPassThrough applet, polling its IPC
// for version, memory and credential-table data. These are the ordered steps.
typedef enum {
    SeosInspectIdle,
    SeosInspectOpSelected,
    SeosInspectSelected,
    SeosInspectSamVer,
    SeosInspectCoreVer,
    SeosInspectPersistMem,
    SeosInspectCredConfig,
    SeosInspectSuspendEnd,
    SeosInspectDone,
} SeosInspectState;

#define SEOS_INSPECT_CRED_COUNT 8
#define SEOS_INSPECT_CRED_BUF   256
#define SEOS_INSPECT_REASM_BUF  512
#define SEOS_INSPECT_WIRE_MAX   300

typedef struct {
    SeosInspectState state;
    bool cmd_sent;
    uint8_t poll_count;

    uint16_t sam_ver;
    uint16_t core_ver;
    uint32_t persist_mem;
    uint8_t segment_count;
    uint8_t assembly_count;

    bool cred_enabled[SEOS_INSPECT_CRED_COUNT];
    bool seos_enabled;
    bool cred_parsed;

    // The credential table arrives split across PUT DATA fragments; collected
    // here until the length the first fragment declared is complete.
    uint8_t cred_buf[SEOS_INSPECT_CRED_BUF];
    size_t cred_buf_len;
    size_t cred_declared;

    // ISO-DEP (T=CL) framing state. We drive the block protocol ourselves on a
    // raw 3A listener because the firmware 4A path mishandles the reader's
    // chained credential-table response and makes it drop the field.
    uint8_t cid;
    uint8_t reasm[SEOS_INSPECT_REASM_BUF];
    size_t reasm_len;
    uint8_t last_tx[SEOS_INSPECT_WIRE_MAX];
    size_t last_tx_len;
} SeosInspectData;

// What the caller should surface after handling a frame.
typedef enum {
    SeosInspectEventNone,
    SeosInspectEventAidSelected,
    SeosInspectEventDone,
} SeosInspectEvent;

// Display name of credential item i (0..SEOS_INSPECT_CRED_COUNT-1).
const char* seos_inspect_cred_name(size_t i);

void seos_inspect_reset(SeosInspectData* inspect);

// Handle one raw 3A frame (PCB + INF, no CRC): run the T=CL block protocol and,
// for a complete APDU, the inspection step. Writes the wire response (PCB + INF,
// no CRC) to out and returns its length, 0 when nothing should be sent.
size_t seos_inspect_handle_frame(
    SeosInspectData* inspect,
    const uint8_t* frame,
    size_t frame_len,
    uint8_t* out,
    size_t out_cap,
    SeosInspectEvent* event);

#ifdef __cplusplus
}
#endif
