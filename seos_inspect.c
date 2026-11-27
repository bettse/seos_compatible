#include "seos_inspect.h"

#include "seos_tlv.h"
#include "seos_protocol.h"

#include <string.h>

#define TAG "SeosInspect"

#define SEOS_INSPECT_POLL_TIMEOUT 50

// ATS we answer RATS with: TL, T0 (TA1/TB1/TC1 present, FSCI=8), TA1, TB1,
// TC1 (CID supported). FSCI=8 matches the reader and keeps its response
// fragmentation the same as the standalone tool we ported this from.
static const uint8_t HID_ATS[] = {0x05, 0x78, 0x80, 0x70, 0x02};

// The passthrough applet and the two operation selectors the reader offers.
static const uint8_t PASSTHROUGH_AID[] =
    {0xa0, 0x00, 0x00, 0x03, 0x82, 0x00, 0x2d, 0x00, 0x01, 0x01};
static const uint8_t OP_SELECTOR_AID[] =
    {0xa0, 0x00, 0x00, 0x03, 0x82, 0x00, 0x2f, 0x00, 0x01, 0x01};
static const uint8_t OP_SELECTOR_RESET_AID[] =
    {0xa0, 0x00, 0x00, 0x03, 0x82, 0x00, 0x31, 0x00, 0x01, 0x01};

static const uint8_t RESP_PASSTHROUGH_FCI[] =
    {0x6f, 0x0c, 0x84, 0x0a, 0xa0, 0x00, 0x00, 0x03, 0x82, 0x00, 0x2d, 0x00, 0x01, 0x01};
static const uint8_t RESP_ENABLE_INSPECTION[] =
    {0x6f, 0x08, 0x85, 0x06, 0x02, 0x01, 0x40, 0x02, 0x01, 0x00};
static const uint8_t SW_INS_NOT_SUPPORTED[] = {0x6d, 0x00};

// IPC commands; a 9000 status word is appended when each is sent.
static const uint8_t CMD_SAM_VER[] = {0x44, 0x0a, 0x44, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x82, 0x00};
static const uint8_t CMD_CORE_VER[] = {0x44, 0x01, 0x44, 0x00, 0x00, 0x00, 0xa5, 0x02, 0x86, 0x00};
static const uint8_t CMD_PERSIST_MEM[] =
    {0x44, 0x0a, 0x44, 0x00, 0x00, 0x00, 0xa0, 0x04, 0xb9, 0x02, 0x8a, 0x00};
static const uint8_t CMD_SUSPEND[] = {0x44, 0x0a, 0x44, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x83, 0x00};

// IPC-framed SNMPv3 GET for the credential table (OID 03 01 07 01 5F). The
// flags and context here are what the reader's SAM accepts over passthrough;
// the textbook RFC form is rejected with authorizationError.
static const uint8_t CMD_SNMP_CRED[] = {
    0x44, 0x0a, 0x44, 0x00, 0x00, 0x00, 0xa0, 0x54, 0x94, 0x52, 0x30, 0x50, 0x02, 0x01,
    0x03, 0x30, 0x0e, 0x02, 0x02, 0x03, 0xe9, 0x02, 0x02, 0x02, 0xf4, 0x04, 0x01, 0x04,
    0x02, 0x01, 0x03, 0x04, 0x18, 0x30, 0x16, 0x04, 0x04, 0x03, 0x01, 0x07, 0x05, 0x02,
    0x01, 0x00, 0x02, 0x01, 0x00, 0x04, 0x04, 0x03, 0x01, 0x07, 0x04, 0x04, 0x00, 0x04,
    0x00, 0x30, 0x21, 0x04, 0x04, 0x03, 0x01, 0x07, 0x05, 0x04, 0x00, 0xa0, 0x17, 0x02,
    0x02, 0x03, 0xe9, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06,
    0x05, 0x03, 0x01, 0x07, 0x01, 0x5f, 0x05, 0x00};

#define CT_ANY   (-1)
#define PROX_IDX 7

static const struct {
    const char* name;
    uint32_t hivecode;
    int16_t card_type;
} CRED_ITEMS[SEOS_INSPECT_CRED_COUNT] = {
    {"iCLASS", 1673300735, CT_ANY},
    {"iCLASS SE", 1283979105, 3},
    {"DESFire SIO", 1283979105, 1},
    {"MIFARE SIO", 1283979105, 2},
    {"DESFire CSN", 2270514240, 1},
    {"MIFARE CSN", 2270514240, 2},
    {"CSN Only", 2270514240, CT_ANY},
    {"125kHz Prox", 2983013903, CT_ANY},
};

// Response accumulator: a plain byte buffer the state machine writes the APDU
// reply into, before the T=CL layer wraps it in an I-block.
typedef struct {
    uint8_t* buf;
    size_t len;
    size_t cap;
} RespBuf;

static void resp_add(RespBuf* r, const uint8_t* d, size_t n) {
    if(r->len + n <= r->cap) {
        memcpy(r->buf + r->len, d, n);
        r->len += n;
    }
}

const char* seos_inspect_cred_name(size_t i) {
    return (i < SEOS_INSPECT_CRED_COUNT) ? CRED_ITEMS[i].name : "";
}

static bool is_get_data(const uint8_t* d, size_t n) {
    return n >= 4 && d[0] == 0x00 && d[1] == 0xca;
}

static bool is_put_data(const uint8_t* d, size_t n) {
    return n >= 4 && d[0] == 0x00 && d[1] == 0xda;
}

static bool aid_is(const uint8_t* aid, size_t aid_len, const uint8_t* want, size_t want_len) {
    return aid_len == want_len && memcmp(aid, want, want_len) == 0;
}

static uint32_t be_uint(const uint8_t* d, size_t len) {
    uint32_t v = 0;
    for(size_t i = 0; i < len && i < 4; i++) v = (v << 8) | d[i];
    return v;
}

// Depth-first search for the first object with the given tag.
static bool find_tag(
    const uint8_t* data,
    size_t len,
    uint16_t tag,
    const uint8_t** value,
    size_t* value_len) {
    SeosTlvCursor cursor;
    seos_tlv_cursor_init(&cursor, data, len);
    SeosTlvObject obj;
    while(!seos_tlv_cursor_done(&cursor)) {
        if(!seos_tlv_read(&cursor, &obj)) break;
        if(obj.tag == tag) {
            *value = obj.value;
            *value_len = obj.value_len;
            return true;
        }
        uint8_t first = (obj.tag > 0xff) ? (uint8_t)(obj.tag >> 8) : (uint8_t)obj.tag;
        if((first & 0x20) && obj.value_len > 0) {
            if(find_tag(obj.value, obj.value_len, tag, value, value_len)) return true;
        }
    }
    return false;
}

// Length of a BER tag+length header, or 0 if malformed.
static size_t ber_header_len(const uint8_t* d, size_t len) {
    if(len < 2) return 0;
    size_t pos = 1;
    if((d[0] & 0x1f) == 0x1f) {
        if(pos >= len) return 0;
        pos++;
    }
    uint8_t l0 = d[pos++];
    if(l0 < 0x80) return pos;
    if(l0 == 0x81) return (pos < len) ? pos + 1 : 0;
    if(l0 == 0x82) return (pos + 1 < len) ? pos + 2 : 0;
    return 0;
}

// Raw data field of a PUT DATA APDU, after CLA INS P1 P2 Lc.
static const uint8_t* put_data_field(const uint8_t* apdu, size_t apdu_len, size_t* out_len) {
    *out_len = 0;
    if(apdu_len < 5 || apdu[1] != 0xda) return NULL;
    size_t hdr, lc;
    if(apdu[4] == 0x00 && apdu_len >= 7) {
        hdr = 7;
        lc = ((size_t)apdu[5] << 8) | apdu[6];
    } else {
        hdr = 5;
        lc = apdu[4];
    }
    if(hdr > apdu_len) return NULL;
    if(hdr + lc > apdu_len) lc = apdu_len - hdr;
    *out_len = lc;
    return &apdu[hdr];
}

// Unwrap the two-level IPC BER around a PUT DATA response payload. Falls back
// to skipping the headers when the declared length runs past the frame, which
// happens on the first (truncated) fragment of a large response.
static const uint8_t* ipc_payload(const uint8_t* apdu, size_t apdu_len, size_t* out_len) {
    *out_len = 0;
    size_t lc;
    const uint8_t* ipc = put_data_field(apdu, apdu_len, &lc);
    if(!ipc || lc < 4) return NULL;

    SeosTlvObject outer, inner;
    if(seos_tlv_read_at(ipc, lc, 0, &outer) && outer.value_len > 0 &&
       seos_tlv_read_at(outer.value, outer.value_len, 0, &inner) && inner.value_len > 0) {
        *out_len = inner.value_len;
        return inner.value;
    }

    size_t h1 = ber_header_len(ipc, lc);
    if(h1 > 0 && h1 < lc) {
        size_t h2 = ber_header_len(ipc + h1, lc - h1);
        if(h2 > 0 && h1 + h2 < lc) {
            *out_len = lc - h1 - h2;
            return ipc + h1 + h2;
        }
    }
    return NULL;
}

// Find the credential-table octet string that follows the OID in an SNMP
// response. Reports the length the value declares as well as what is present.
static bool snmp_cred_value(
    const uint8_t* data,
    size_t len,
    const uint8_t** out,
    size_t* out_len,
    size_t* declared_len) {
    for(size_t i = 0; i + 8 < len; i++) {
        if(data[i] == 0x06 && data[i + 1] == 0x05 && data[i + 2] == 0x03 && data[i + 3] == 0x01 &&
           data[i + 4] == 0x07 && data[i + 5] == 0x01 && data[i + 6] == 0x5f) {
            size_t vp = i + 7;
            if(vp >= len) return false;
            uint8_t vtag = data[vp++];
            if(vtag == 0x05) return false;
            if(vp >= len) return false;
            uint8_t vl = data[vp];
            size_t vlen;
            if(vl < 0x80) {
                vlen = vl;
                vp += 1;
            } else if(vl == 0x81 && vp + 1 < len) {
                vlen = data[vp + 1];
                vp += 2;
            } else if(vl == 0x82 && vp + 2 < len) {
                vlen = ((size_t)data[vp + 1] << 8) | data[vp + 2];
                vp += 3;
            } else {
                return false;
            }
            *declared_len = vlen;
            if(vp + vlen > len) vlen = len - vp;
            *out = &data[vp];
            *out_len = vlen;
            return true;
        }
    }
    return false;
}

// The table is a run of (protocol, count, count * 9-byte entry) groups.
static void parse_cred_table(const uint8_t* table, size_t len, SeosInspectData* ins) {
    memset(ins->cred_enabled, 0, sizeof(ins->cred_enabled));
    ins->seos_enabled = false;

    size_t pos = 0;
    while(pos + 1 < len) {
        uint8_t proto = table[pos];
        uint8_t count = table[pos + 1];
        pos += 2;
        if(pos + (size_t)count * 9 > len) break;

        if(proto == 0x15 && count > 0) ins->seos_enabled = true;
        if((proto == 0x09 || proto == 0x0a || proto == 0x0b) && count > 0)
            ins->cred_enabled[PROX_IDX] = true;

        for(uint8_t i = 0; i < count; i++) {
            uint32_t hv = be_uint(&table[pos], 4);
            uint8_t ct = table[pos + 7];
            FURI_LOG_D(TAG, "cred proto=%02X hc=%08lX ct=%u", proto, (unsigned long)hv, ct);

            for(size_t ci = 0; ci < SEOS_INSPECT_CRED_COUNT; ci++) {
                if(hv == CRED_ITEMS[ci].hivecode &&
                   (CRED_ITEMS[ci].card_type == CT_ANY || (int16_t)ct == CRED_ITEMS[ci].card_type ||
                    ct == 0)) {
                    ins->cred_enabled[ci] = true;
                }
            }
            if(hv == 1283979105 && ct == 7) ins->seos_enabled = true;
            pos += 9;
        }
    }

    // A 125kHz group cut off at a frame boundary still implies Prox.
    if(pos < len) {
        uint8_t t = table[pos];
        if(t == 0x09 || t == 0x0a || t == 0x0b) ins->cred_enabled[PROX_IDX] = true;
    }
}

static void append_sw(RespBuf* r, const uint8_t sw[2]) {
    resp_add(r, sw, 2);
}

static void send_cmd(SeosInspectData* ins, const uint8_t* cmd, size_t len, RespBuf* r) {
    resp_add(r, cmd, len);
    append_sw(r, SEOS_SW_SUCCESS);
    ins->cmd_sent = true;
}

static void accumulate_cred(
    SeosInspectData* ins,
    const uint8_t* apdu,
    size_t apdu_len,
    const uint8_t* payload,
    size_t payload_len) {
    if(ins->cred_declared == 0) {
        const uint8_t* tbl;
        size_t tbl_len, declared;
        if(payload && snmp_cred_value(payload, payload_len, &tbl, &tbl_len, &declared)) {
            if(tbl_len > sizeof(ins->cred_buf)) tbl_len = sizeof(ins->cred_buf);
            memcpy(ins->cred_buf, tbl, tbl_len);
            ins->cred_buf_len = tbl_len;
            ins->cred_declared = declared;
        }
        return;
    }
    size_t raw_len;
    const uint8_t* raw = put_data_field(apdu, apdu_len, &raw_len);
    size_t space = sizeof(ins->cred_buf) - ins->cred_buf_len;
    if(raw_len > space) raw_len = space;
    if(raw && raw_len) {
        memcpy(ins->cred_buf + ins->cred_buf_len, raw, raw_len);
        ins->cred_buf_len += raw_len;
    }
}

void seos_inspect_reset(SeosInspectData* inspect) {
    memset(inspect, 0, sizeof(SeosInspectData));
}

// Answer a SELECT in any pre-inspection state, or begin the IPC poll loop.
static SeosInspectEvent
    handshake(SeosInspectData* ins, const uint8_t* apdu, size_t apdu_len, RespBuf* r) {
    const uint8_t* aid = NULL;
    size_t aid_len = 0;

    if(seos_parse_select_aid(apdu, apdu_len, &aid, &aid_len)) {
        if(aid_is(aid, aid_len, PASSTHROUGH_AID, sizeof(PASSTHROUGH_AID))) {
            ins->state = SeosInspectSelected;
            resp_add(r, RESP_PASSTHROUGH_FCI, sizeof(RESP_PASSTHROUGH_FCI));
            append_sw(r, SEOS_SW_SUCCESS);
            return SeosInspectEventNone;
        }
        if(aid_is(aid, aid_len, OP_SELECTOR_AID, sizeof(OP_SELECTOR_AID)) ||
           aid_is(aid, aid_len, OP_SELECTOR_RESET_AID, sizeof(OP_SELECTOR_RESET_AID))) {
            SeosInspectEvent ev = SeosInspectEventNone;
            if(ins->state == SeosInspectIdle) {
                ins->state = SeosInspectOpSelected;
                ev = SeosInspectEventAidSelected;
            }
            resp_add(r, RESP_ENABLE_INSPECTION, sizeof(RESP_ENABLE_INSPECTION));
            append_sw(r, SEOS_SW_SUCCESS);
            return ev;
        }
        append_sw(r, SEOS_SW_FILE_NOT_FOUND);
        return SeosInspectEventNone;
    }

    if(ins->state != SeosInspectIdle) {
        if(is_get_data(apdu, apdu_len)) {
            ins->state = SeosInspectSamVer;
            send_cmd(ins, CMD_SAM_VER, sizeof(CMD_SAM_VER), r);
            return SeosInspectEventNone;
        }
        if(is_put_data(apdu, apdu_len)) {
            append_sw(r, SEOS_SW_SUCCESS);
            return SeosInspectEventNone;
        }
    }
    append_sw(r, SW_INS_NOT_SUPPORTED);
    return SeosInspectEventNone;
}

static SeosInspectEvent
    collection(SeosInspectData* ins, const uint8_t* apdu, size_t apdu_len, RespBuf* r) {
    bool is_ca = is_get_data(apdu, apdu_len);
    bool is_da = is_put_data(apdu, apdu_len);
    size_t payload_len = 0;
    const uint8_t* payload = is_da ? ipc_payload(apdu, apdu_len, &payload_len) : NULL;

    // The credential table spans several PUT DATA fragments; reassemble, then
    // parse once the declared length is complete.
    if(is_da && ins->state == SeosInspectCredConfig) {
        if(ins->cred_declared == 0 && !payload) {
            if(++ins->poll_count >= SEOS_INSPECT_POLL_TIMEOUT) ins->state = SeosInspectSuspendEnd;
        } else {
            accumulate_cred(ins, apdu, apdu_len, payload, payload_len);
            if(ins->cred_declared && ins->cred_buf_len >= ins->cred_declared) {
                FURI_LOG_I(TAG, "Cred table complete: %u bytes", (unsigned)ins->cred_buf_len);
                parse_cred_table(ins->cred_buf, ins->cred_declared, ins);
                ins->cred_parsed = true;
                ins->state = SeosInspectSuspendEnd;
            }
        }
        ins->cmd_sent = false;
        append_sw(r, SEOS_SW_SUCCESS);
        return SeosInspectEventNone;
    }

    // Version / memory responses.
    if(payload) {
        const uint8_t* v = NULL;
        size_t vl = 0;
        switch(ins->state) {
        case SeosInspectSamVer:
            if(find_tag(payload, payload_len, 0x80, &v, &vl)) ins->sam_ver = (uint16_t)be_uint(v, vl);
            FURI_LOG_I(TAG, "SAM=0x%04X", ins->sam_ver);
            ins->state = SeosInspectCoreVer;
            break;
        case SeosInspectCoreVer:
            if(find_tag(payload, payload_len, 0x80, &v, &vl)) ins->core_ver = (uint16_t)be_uint(v, vl);
            FURI_LOG_I(TAG, "Core=0x%04X", ins->core_ver);
            ins->state = SeosInspectPersistMem;
            break;
        case SeosInspectPersistMem:
            if(find_tag(payload, payload_len, 0x80, &v, &vl)) ins->segment_count = (uint8_t)be_uint(v, vl);
            if(find_tag(payload, payload_len, 0x81, &v, &vl)) ins->assembly_count = (uint8_t)be_uint(v, vl);
            if(find_tag(payload, payload_len, 0x82, &v, &vl)) ins->persist_mem = be_uint(v, vl);
            FURI_LOG_I(
                TAG, "Apps=%u Segs=%u Mem=%lu", ins->assembly_count, ins->segment_count,
                (unsigned long)ins->persist_mem);
            ins->state = SeosInspectCredConfig;
            break;
        default:
            break;
        }
        ins->cmd_sent = false;
        append_sw(r, SEOS_SW_SUCCESS);
        return SeosInspectEventNone;
    }

    // Empty PUT DATA ack, including the one after the final suspend.
    if(is_da) {
        SeosInspectEvent ev = SeosInspectEventNone;
        if(ins->state == SeosInspectSuspendEnd && ins->cmd_sent) {
            ins->state = SeosInspectDone;
            ev = SeosInspectEventDone;
        }
        ins->cmd_sent = false;
        append_sw(r, SEOS_SW_SUCCESS);
        return ev;
    }

    // Reader poll: issue the command for the current step.
    if(is_ca && !ins->cmd_sent) {
        switch(ins->state) {
        case SeosInspectCoreVer:
            send_cmd(ins, CMD_CORE_VER, sizeof(CMD_CORE_VER), r);
            return SeosInspectEventNone;
        case SeosInspectPersistMem:
            send_cmd(ins, CMD_PERSIST_MEM, sizeof(CMD_PERSIST_MEM), r);
            return SeosInspectEventNone;
        case SeosInspectCredConfig:
            ins->poll_count = 0;
            send_cmd(ins, CMD_SNMP_CRED, sizeof(CMD_SNMP_CRED), r);
            return SeosInspectEventNone;
        case SeosInspectSuspendEnd:
            send_cmd(ins, CMD_SUSPEND, sizeof(CMD_SUSPEND), r);
            return SeosInspectEventNone;
        default:
            break;
        }
    }

    append_sw(r, SEOS_SW_SUCCESS);
    return SeosInspectEventNone;
}

// Run one complete APDU through the inspection step, writing the reply (data
// plus status word) to r.
static SeosInspectEvent
    handle_apdu(SeosInspectData* ins, const uint8_t* apdu, size_t apdu_len, RespBuf* r) {
    if(apdu_len == 0) {
        append_sw(r, SEOS_SW_SUCCESS);
        return SeosInspectEventNone;
    }
    if(ins->state == SeosInspectDone) {
        append_sw(r, SEOS_SW_FILE_NOT_FOUND);
        return SeosInspectEventNone;
    }
    if(ins->state <= SeosInspectSelected) {
        return handshake(ins, apdu, apdu_len, r);
    }
    return collection(ins, apdu, apdu_len, r);
}

size_t seos_inspect_handle_frame(
    SeosInspectData* ins,
    const uint8_t* frame,
    size_t frame_len,
    uint8_t* out,
    size_t out_cap,
    SeosInspectEvent* event) {
    *event = SeosInspectEventNone;
    if(frame_len < 1 || out_cap < 1) return 0;
    uint8_t pcb = frame[0];

    // RATS: record CID, answer with our ATS.
    if(pcb == 0xe0 && frame_len >= 2) {
        ins->cid = frame[1] & 0x0f;
        ins->reasm_len = 0;
        if(sizeof(HID_ATS) > out_cap) return 0;
        memcpy(out, HID_ATS, sizeof(HID_ATS));
        return sizeof(HID_ATS);
    }

    // PPS: echo the PPSS byte.
    if((pcb & 0xf0) == 0xd0) {
        out[0] = pcb;
        return 1;
    }

    // I-block.
    if((pcb & 0xe2) == 0x02) {
        bool chain = pcb & 0x10;
        bool has_cid = pcb & 0x08;
        bool has_nad = pcb & 0x04;
        uint8_t blk = pcb & 0x01;
        size_t off = 1 + (has_cid ? 1 : 0) + (has_nad ? 1 : 0);

        if(off <= frame_len) {
            size_t inf = frame_len - off;
            if(ins->reasm_len + inf <= sizeof(ins->reasm)) {
                memcpy(ins->reasm + ins->reasm_len, frame + off, inf);
                ins->reasm_len += inf;
            }
        }

        // More to come: ACK with the block number echoed, wait for the rest.
        if(chain) {
            size_t n = 0;
            out[n++] = 0xa2 | blk | (has_cid ? 0x08 : 0);
            if(has_cid && n < out_cap) out[n++] = ins->cid;
            return n;
        }

        // Last block: run the APDU, wrap the reply as an I-block.
        uint8_t resp[SEOS_INSPECT_WIRE_MAX];
        RespBuf r = {resp, 0, sizeof(resp)};
        *event = handle_apdu(ins, ins->reasm, ins->reasm_len, &r);
        ins->reasm_len = 0;

        size_t n = 0;
        out[n++] = 0x02 | blk | (has_cid ? 0x08 : 0);
        if(has_cid && n < out_cap) out[n++] = ins->cid;
        if(r.len && n + r.len <= out_cap) {
            memcpy(out + n, resp, r.len);
            n += r.len;
        }
        if(n <= sizeof(ins->last_tx)) {
            memcpy(ins->last_tx, out, n);
            ins->last_tx_len = n;
        }
        return n;
    }

    // R-block: retransmit our last I-block.
    if((pcb & 0xa0) == 0xa0) {
        if(ins->last_tx_len && ins->last_tx_len <= out_cap) {
            memcpy(out, ins->last_tx, ins->last_tx_len);
            return ins->last_tx_len;
        }
        return 0;
    }

    // S-block: WTX (echo request) or DESELECT (echo, reset).
    if((pcb & 0xc0) == 0xc0) {
        bool has_cid = pcb & 0x08;
        size_t n = 0;
        out[n++] = pcb;
        if(has_cid && n < out_cap) out[n++] = ins->cid;
        if((pcb & 0x30) == 0x30) {
            size_t inf_off = 1 + (has_cid ? 1 : 0);
            if(inf_off < frame_len && n < out_cap) out[n++] = frame[inf_off] & 0x3f;
        } else {
            ins->reasm_len = 0;
        }
        return n;
    }

    return 0;
}
