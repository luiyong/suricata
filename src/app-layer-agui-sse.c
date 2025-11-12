/* Copyright (C) 2024 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include "suricata-common.h"

#include <stdint.h>

#include "app-layer-agui-sse.h"

#include "app-layer-htp.h"
#include "conf.h"
#include "htp/htp.h"
#include "stream-tcp-private.h"
#include "util-buffer.h"
#include "util-mem.h"
#include "util-streaming-buffer.h"

#include <jansson.h>

static bool agui_sse_initialized = false;
static bool agui_sse_enabled = true;

static void AguiSseLoadConfig(void)
{
    int val = 0;
    if (ConfGetBool("app-layer.protocols.ag-ui-sse.enabled", &val) == 1) {
        agui_sse_enabled = (val != 0);
    }
}

void AguiSseInit(void)
{
    if (agui_sse_initialized) {
        return;
    }

    AguiSseLoadConfig();
    if (!agui_sse_enabled) {
        agui_sse_initialized = true;
        return;
    }

    AppLayerHtpEnableResponseBodyCallback();
    agui_sse_initialized = true;
}

static inline bool AguiSseIsEnabled(void)
{
    return agui_sse_enabled;
}

static AguiSseTxData *AguiSseTxDataGetMutable(htp_tx_t *tx)
{
    if (!AguiSseIsEnabled() || tx == NULL) {
        return NULL;
    }

    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud == NULL) {
        return NULL;
    }

    if (htud->agui_sse_tx == NULL) {
        htud->agui_sse_tx = SCCalloc(1, sizeof(AguiSseTxData));
    }
    return htud->agui_sse_tx;
}

const AguiSseTxData *AguiSseGetTxData(const htp_tx_t *tx)
{
    if (!AguiSseIsEnabled() || tx == NULL) {
        return NULL;
    }

    const HtpTxUserData *htud = (const HtpTxUserData *)htp_tx_get_user_data((htp_tx_t *)tx);
    if (htud == NULL) {
        return NULL;
    }
    return htud->agui_sse_tx;
}

static bool AguiSseBstrContainsNocase(const bstr *value, const char *needle)
{
    if (value == NULL || needle == NULL) {
        return false;
    }
    const size_t haystack_len = bstr_len(value);
    const uint8_t *haystack = bstr_ptr(value);
    const size_t needle_len = strlen(needle);
    if (needle_len == 0 || haystack == NULL || haystack_len < needle_len) {
        return false;
    }
    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (strncasecmp((const char *)&haystack[i], needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

static bool AguiSseHeaderContainsValue(htp_table_t *headers, const char *name, const char *needle)
{
    if (headers == NULL || name == NULL || needle == NULL) {
        return false;
    }
    htp_header_t *header = (htp_header_t *)htp_table_get_c(headers, name);
    if (header == NULL || header->value == NULL) {
        return false;
    }
    return AguiSseBstrContainsNocase(header->value, needle);
}

static void AguiSseRequestInspect(htp_tx_t *tx)
{
    if (!AguiSseIsEnabled() || tx == NULL || tx->request_headers == NULL) {
        return;
    }
    if (!AguiSseHeaderContainsValue(tx->request_headers, "Accept", "text/event-stream")) {
        return;
    }
    AguiSseTxData *txmeta = AguiSseTxDataGetMutable(tx);
    if (txmeta != NULL) {
        txmeta->request_wants_sse = true;
    }
}

static void AguiSseFlushEvent(MemBuffer *payload, AguiSseTxData *txmeta)
{
    if (payload == NULL || txmeta == NULL) {
        return;
    }
    const uint32_t len = MEMBUFFER_OFFSET(payload);
    if (len == 0) {
        return;
    }

    txmeta->event_count++;
    txmeta->payload_bytes += len;

    json_error_t error;
    json_t *root = json_loadb((const char *)MEMBUFFER_BUFFER(payload), len, 0, &error);
    if (root != NULL) {
        txmeta->json_parsed++;
        if (json_is_object(root)) {
            json_t *type = json_object_get(root, "type");
            if (json_is_string(type)) {
                const char *type_str = json_string_value(type);
                if (type_str != NULL) {
                    strlcpy(txmeta->last_event_type, type_str, sizeof(txmeta->last_event_type));
                }
            }
        }
        json_decref(root);
    } else {
        txmeta->json_failed++;
    }

    MemBufferReset(payload);
}

static void AguiSseProcessBuffer(const uint8_t *data, uint32_t len, AguiSseTxData *txmeta)
{
    if (data == NULL || len == 0 || txmeta == NULL) {
        return;
    }

    uint32_t buffer_size = len;
    if (buffer_size >= (UINT32_MAX - 1)) {
        buffer_size = UINT32_MAX;
    } else {
        buffer_size++;
    }
    if (buffer_size < 1024U) {
        buffer_size = 1024U;
    }
    MemBuffer *payload = MemBufferCreateNew(buffer_size);
    if (payload == NULL) {
        return;
    }

    uint32_t pos = 0;
    while (pos < len) {
        uint32_t line_end = pos;
        while (line_end < len && data[line_end] != '\n' && data[line_end] != '\r') {
            line_end++;
        }
        uint32_t line_len = line_end - pos;

        /* Determine newline length to skip CR/LF combos. */
        uint32_t newline_len = 0;
        if (line_end < len) {
            if (data[line_end] == '\r') {
                newline_len++;
                line_end++;
                if (line_end < len && data[line_end] == '\n') {
                    newline_len++;
                    line_end++;
                }
            } else if (data[line_end] == '\n') {
                newline_len++;
                line_end++;
                if (line_end < len && data[line_end] == '\r') {
                    newline_len++;
                    line_end++;
                }
            }
        }

        const uint8_t *line = &data[pos];
        const bool blank_line = (line_len == 0);

        if (!blank_line && line_len >= 5 && memcmp(line, "data:", 5) == 0) {
            uint32_t offset = 5;
            if (offset < line_len && line[offset] == ' ') {
                offset++;
            }
            const uint32_t data_len = line_len > offset ? line_len - offset : 0;
            if (data_len > 0) {
                uint32_t written = MemBufferWriteRaw(payload, line + offset, data_len);
                if (written < data_len) {
                    if (MemBufferExpand(&payload, data_len + 1024) == 0) {
                        MemBufferWriteRaw(payload, line + offset + written, data_len - written);
                    }
                }
                const uint8_t newline = '\n';
                MemBufferWriteRaw(payload, &newline, 1);
            }
        }

        if (blank_line) {
            AguiSseFlushEvent(payload, txmeta);
        }

        if (newline_len == 0 && line_end >= len) {
            pos = len;
        } else {
            pos = line_end;
        }
    }

    AguiSseFlushEvent(payload, txmeta);
    MemBufferFree(payload);
}

static void AguiSseResponseInspect(htp_tx_t *tx)
{
    if (!AguiSseIsEnabled() || tx == NULL) {
        return;
    }

    htp_table_t *headers = tx->response_headers;
    if (headers == NULL) {
        return;
    }

    if (!AguiSseHeaderContainsValue(headers, "Content-Type", "text/event-stream") &&
            !AguiSseHeaderContainsValue(headers, "Content-Type", "application/vnd.ag-ui.event")) {
        return;
    }

    AguiSseTxData *txmeta = AguiSseTxDataGetMutable(tx);
    if (txmeta == NULL) {
        return;
    }
    txmeta->response_is_sse = true;

    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud == NULL || htud->response_body.sb == NULL) {
        return;
    }

    const uint8_t *body_data = NULL;
    uint32_t body_len = 0;
    uint64_t body_offset = 0;
    if (StreamingBufferGetData(htud->response_body.sb, &body_data, &body_len, &body_offset) == 0 ||
            body_len == 0) {
        return;
    }

    AguiSseProcessBuffer(body_data, body_len, txmeta);
}

void AguiSseOnHttpRequestComplete(Flow *f, htp_tx_t *tx)
{
    (void)f;
    if (!AguiSseIsEnabled()) {
        return;
    }
    AguiSseRequestInspect(tx);
}

void AguiSseOnHttpResponseComplete(Flow *f, htp_tx_t *tx)
{
    (void)f;
    if (!AguiSseIsEnabled()) {
        return;
    }
    AguiSseResponseInspect(tx);
}

void AguiSseTxDataMarkLogged(htp_tx_t *tx)
{
    if (!AguiSseIsEnabled() || tx == NULL) {
        return;
    }
    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud != NULL && htud->agui_sse_tx != NULL) {
        htud->agui_sse_tx->event_logged = true;
    }
}

#ifdef UNITTESTS
bool AguiSseTestParseSample(
        const char *payload, uint32_t *out_count, char *last_type, size_t last_type_len)
{
    if (payload == NULL) {
        return false;
    }
    AguiSseTxData txmeta = { 0 };
    AguiSseProcessBuffer((const uint8_t *)payload, (uint32_t)strlen(payload), &txmeta);
    if (out_count != NULL) {
        *out_count = txmeta.event_count;
    }
    if (last_type != NULL && last_type_len > 0) {
        strlcpy(last_type, txmeta.last_event_type, last_type_len);
    }
    return (txmeta.event_count > 0);
}

#include "tests/app-layer-agui-sse.c"
#endif
