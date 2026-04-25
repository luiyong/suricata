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
#include <inttypes.h>
#include <ctype.h>

#include "app-layer-agui-sse.h"

#include "app-layer-htp.h"
#include "counters.h"
#include "conf.h"
#include "flow-storage.h"
#include "flow.h"
#include "htp/htp.h"
#include "stream-tcp-private.h"
#include "util-buffer.h"
#include "util-mem.h"
#include "util-streaming-buffer.h"
#include "util-debug.h"

#include <jansson.h>

#define AGUI_SSE_MAX_REQUEST_BODY_DEFAULT       (128 * 1024U)
#define AGUI_SSE_MESSAGE_SAMPLE_MAX_DEFAULT     5U
#define AGUI_SSE_MULTIPART_BOUNDARY_MAX_DEFAULT 64U

static const char *const agui_valid_roles[] = {
    "developer",
    "system",
    "assistant",
    "user",
    "tool",
    "activity",
    NULL,
};

static bool agui_sse_initialized = false;
static bool agui_sse_enabled = true;

typedef struct AguiSseOptions_ {
    bool standard_mode;
    bool graphql_mode;
    uint32_t max_request_body;
    uint32_t message_sample_max;
    uint32_t multipart_boundary_max;
} AguiSseOptions;

static AguiSseOptions agui_sse_options = {
    .standard_mode = true,
    .graphql_mode = true,
    .max_request_body = AGUI_SSE_MAX_REQUEST_BODY_DEFAULT,
    .message_sample_max = AGUI_SSE_MESSAGE_SAMPLE_MAX_DEFAULT,
    .multipart_boundary_max = AGUI_SSE_MULTIPART_BOUNDARY_MAX_DEFAULT,
};

typedef struct AguiSseFlowState_ {
    bool counted;
} AguiSseFlowState;

static FlowStorageId agui_sse_flow_storage_id = { .id = -1 };
static bool agui_sse_stats_registered = false;
static SC_ATOMIC_DECLARE(uint64_t, agui_sse_flow_count);

static void AguiSseMaybeConfirm(AguiSseTxData *txmeta);
static void AguiSseApplySchemeIfReady(htp_tx_t *tx, AguiSseTxData *txmeta);
static bool AguiSseBodyLooksLikeRunAgentInput(const uint8_t *body, uint32_t len);
static bool AguiSseInspectRequestBody(htp_tx_t *tx, AguiSseTxData *txmeta);
static void AguiSseRequestInspect(Flow *f, htp_tx_t *tx);
static void AguiSseResponseInspect(Flow *f, htp_tx_t *tx);
static bool AguiSseExtractMultipartBoundary(
        htp_table_t *headers, char *boundary, size_t boundary_len);
static void AguiSseProcessMultipartGraphql(
        const uint8_t *data, uint32_t len, AguiSseTxData *txmeta, const char *boundary);
static void AguiSseProcessMultipartJson(
        const uint8_t *json_data, uint32_t json_len, AguiSseTxData *txmeta);
static bool AguiSseScanJsonForEventTypes(
        const uint8_t *json_data, uint32_t json_len, AguiSseTxData *txmeta);

static void *AguiSseFlowStateAlloc(unsigned int size)
{
    return SCCalloc(1, size);
}

static void AguiSseFlowStateFree(void *ptr)
{
    if (ptr != NULL) {
        SCFree(ptr);
    }
}

static void AguiSseRegisterFlowStorage(void)
{
    if (agui_sse_flow_storage_id.id >= 0) {
        return;
    }

    agui_sse_flow_storage_id = FlowStorageRegister("agui_sse_flow_state", sizeof(AguiSseFlowState),
            AguiSseFlowStateAlloc, AguiSseFlowStateFree);
    if (agui_sse_flow_storage_id.id < 0) {
        FatalError("agui_sse_flow_state storage registration failed");
    }
}

static uint64_t AguiSseStatsGetFlows(void)
{
    return SC_ATOMIC_GET(agui_sse_flow_count);
}

void AguiSseRegisterGlobalCounters(void)
{
    if (agui_sse_stats_registered) {
        return;
    }
    StatsRegisterGlobalCounter("app_layer.flow.http.agui", AguiSseStatsGetFlows);
    agui_sse_stats_registered = true;
}

static void AguiSseMarkFlowConfirmed(Flow *f, const char *reason)
{
    if (f == NULL || agui_sse_flow_storage_id.id < 0) {
        return;
    }

    AguiSseFlowState *state = FlowGetStorageById(f, agui_sse_flow_storage_id);
    if (state == NULL) {
        state = FlowAllocStorageById(f, agui_sse_flow_storage_id);
        if (state == NULL) {
            return;
        }
        memset(state, 0x00, sizeof(*state));
    }

    if (state->counted) {
        return;
    }

    state->counted = true;
    SC_ATOMIC_ADD(agui_sse_flow_count, 1);

    const char *why = (reason != NULL) ? reason : "unspecified";
    SCLogInfo("agui flow %" PRId64 " confirmed (%s)", FlowGetId(f), why);
}

static void AguiSseLoadConfig(void)
{
    int val = 0;
    if (ConfGetBool("app-layer.protocols.ag-ui-sse.enabled", &val) == 1) {
        agui_sse_enabled = (val != 0);
    }

    agui_sse_options.standard_mode = true;
    agui_sse_options.graphql_mode = true;
    agui_sse_options.max_request_body = AGUI_SSE_MAX_REQUEST_BODY_DEFAULT;
    agui_sse_options.message_sample_max = AGUI_SSE_MESSAGE_SAMPLE_MAX_DEFAULT;
    agui_sse_options.multipart_boundary_max = AGUI_SSE_MULTIPART_BOUNDARY_MAX_DEFAULT;

    ConfNode *node = ConfGetNode("app-layer.protocols.ag-ui-sse");
    if (node != NULL) {
        if (ConfGetChildValueBool(node, "standard-mode", &val) == 1) {
            agui_sse_options.standard_mode = (val != 0);
        }
        if (ConfGetChildValueBool(node, "graphql-mode", &val) == 1) {
            agui_sse_options.graphql_mode = (val != 0);
        }
        intmax_t tmp = 0;
        if (ConfGetChildValueInt(node, "max-request-body", &tmp) == 1 && tmp > 0) {
            if ((uintmax_t)tmp > UINT32_MAX) {
                agui_sse_options.max_request_body = UINT32_MAX;
            } else {
                agui_sse_options.max_request_body = (uint32_t)tmp;
            }
        }
        if (ConfGetChildValueInt(node, "message-sample-max", &tmp) == 1 && tmp > 0) {
            if ((uintmax_t)tmp > UINT32_MAX) {
                agui_sse_options.message_sample_max = UINT32_MAX;
            } else {
                agui_sse_options.message_sample_max = (uint32_t)tmp;
            }
        }
        if (ConfGetChildValueInt(node, "multipart-boundary-max", &tmp) == 1 && tmp > 0) {
            if ((uintmax_t)tmp > UINT32_MAX) {
                agui_sse_options.multipart_boundary_max = UINT32_MAX;
            } else {
                agui_sse_options.multipart_boundary_max = (uint32_t)tmp;
            }
        }
    }

    if (agui_sse_options.message_sample_max == 0) {
        agui_sse_options.message_sample_max = 1;
    }
    if (agui_sse_options.multipart_boundary_max == 0) {
        agui_sse_options.multipart_boundary_max = AGUI_SSE_MULTIPART_BOUNDARY_MAX_DEFAULT;
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

    AguiSseRegisterFlowStorage();
    AppLayerHtpEnableRequestBodyCallback();
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

static inline bool AguiSseRequestConfidence(const AguiSseTxData *txmeta)
{
    if (txmeta == NULL) {
        return false;
    }
    return (txmeta->request_has_run_input || txmeta->request_accepts_proto);
}

static inline bool AguiSseResponseConfidence(const AguiSseTxData *txmeta)
{
    if (txmeta == NULL) {
        return false;
    }
    if (txmeta->response_is_proto) {
        return true;
    }
    return (txmeta->response_is_sse && txmeta->response_has_valid_events);
}

static void AguiSseMaybeConfirm(AguiSseTxData *txmeta)
{
    if (txmeta == NULL || txmeta->agui_confirmed) {
        return;
    }
    if (AguiSseRequestConfidence(txmeta) && AguiSseResponseConfidence(txmeta)) {
        txmeta->agui_confirmed = true;
    }
}

static void AguiSseApplySchemeIfReady(htp_tx_t *tx, AguiSseTxData *txmeta)
{
    if (tx == NULL || txmeta == NULL) {
        return;
    }
    if (txmeta->agui_confirmed && !txmeta->scheme_applied) {
        HtpTxSetScheme(tx, "ag-ui");
        txmeta->scheme_applied = true;
    }
}

static bool AguiSseEventTypeLooksValid(const char *type)
{
    if (type == NULL || type[0] == '\0') {
        return false;
    }

    static const char *const valid_types[] = {
        "TEXT_MESSAGE_START",
        "TEXT_MESSAGE_CONTENT",
        "TEXT_MESSAGE_END",
        "TEXT_MESSAGE_CHUNK",
        "THINKING_TEXT_MESSAGE_START",
        "THINKING_TEXT_MESSAGE_CONTENT",
        "THINKING_TEXT_MESSAGE_END",
        "TOOL_CALL_START",
        "TOOL_CALL_ARGS",
        "TOOL_CALL_END",
        "TOOL_CALL_CHUNK",
        "TOOL_CALL_RESULT",
        "THINKING_START",
        "THINKING_END",
        "STATE_SNAPSHOT",
        "STATE_DELTA",
        "MESSAGES_SNAPSHOT",
        "ACTIVITY_SNAPSHOT",
        "ACTIVITY_DELTA",
        "RAW",
        "CUSTOM",
        "RUN_STARTED",
        "RUN_FINISHED",
        "RUN_ERROR",
        "STEP_STARTED",
        "STEP_FINISHED",
        NULL,
    };

    for (size_t i = 0; valid_types[i] != NULL; i++) {
        if (strcmp(type, valid_types[i]) == 0) {
            return true;
        }
    }
    return false;
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

static bool AguiSseExtractMultipartBoundary(
        htp_table_t *headers, char *boundary, size_t boundary_len)
{
    if (headers == NULL || boundary == NULL || boundary_len == 0) {
        return false;
    }

    boundary[0] = '\0';

    htp_header_t *header = (htp_header_t *)htp_table_get_c(headers, "Content-Type");
    if (header == NULL || header->value == NULL) {
        return false;
    }

    const char *value = (const char *)bstr_ptr(header->value);
    const size_t value_len = bstr_len(header->value);
    if (value == NULL || value_len == 0) {
        return false;
    }

    bool has_multipart = false;
    for (size_t i = 0; i + 15 <= value_len; i++) {
        if (strncasecmp(&value[i], "multipart/mixed", 15) == 0) {
            has_multipart = true;
            break;
        }
    }
    if (!has_multipart) {
        return false;
    }

    static const char boundary_key[] = "boundary=";
    const size_t key_len = sizeof(boundary_key) - 1U;

    for (size_t i = 0; i + key_len < value_len; i++) {
        if (strncasecmp(&value[i], boundary_key, key_len) == 0) {
            const char *start = &value[i + key_len];
            while ((size_t)(start - value) < value_len && isspace((unsigned char)*start)) {
                start++;
            }
            char quote = 0;
            if (*start == '"' || *start == '\'') {
                quote = *start;
                start++;
            }
            const char *end = start;
            while ((size_t)(end - value) < value_len) {
                const char ch = *end;
                if ((quote != 0 && ch == quote) ||
                        (quote == 0 && (ch == ';' || isspace((unsigned char)ch)))) {
                    break;
                }
                end++;
            }
            const size_t copy_len = (size_t)(end - start);
            if (copy_len > 0 && copy_len < boundary_len) {
                memcpy(boundary, start, copy_len);
                boundary[copy_len] = '\0';
                return true;
            }
            break;
        }
    }
    return false;
}

static bool AguiSseRoleAllowed(const char *role)
{
    if (role == NULL || role[0] == '\0') {
        return false;
    }
    for (size_t i = 0; agui_valid_roles[i] != NULL; i++) {
        if (strcasecmp(role, agui_valid_roles[i]) == 0) {
            return true;
        }
    }
    return false;
}

static bool AguiSseMessagesLookValid(json_t *messages)
{
    if (!json_is_array(messages) || json_array_size(messages) == 0) {
        return false;
    }

    const size_t total = json_array_size(messages);
    const size_t sample = MIN(total, (size_t)agui_sse_options.message_sample_max);
    size_t inspected = 0;

    for (size_t i = 0; i < sample; i++) {
        json_t *msg = json_array_get(messages, i);
        if (!json_is_object(msg)) {
            return false;
        }
        json_t *role = json_object_get(msg, "role");
        if (!json_is_string(role) || !AguiSseRoleAllowed(json_string_value(role))) {
            json_t *text_msg = json_object_get(msg, "textMessage");
            if (!json_is_object(text_msg)) {
                return false;
            }
            role = json_object_get(text_msg, "role");
            if (!json_is_string(role) || !AguiSseRoleAllowed(json_string_value(role))) {
                return false;
            }
        }
        if (!json_is_string(role)) {
            return false;
        }
        inspected++;
    }

    return (inspected > 0);
}

static bool AguiSseBodyLooksLikeRunAgentInput(const uint8_t *body, uint32_t len)
{
    if (body == NULL || len == 0) {
        return false;
    }

    json_error_t error;
    json_t *root = json_loadb((const char *)body, len, JSON_DISABLE_EOF_CHECK, &error);
    if (root == NULL) {
        return false;
    }

    bool looks_valid = false;

    if (json_is_object(root)) {
        json_t *payload = root;
        json_t *variables = json_object_get(root, "variables");
        if (json_is_object(variables)) {
            json_t *data = json_object_get(variables, "data");
            if (json_is_object(data)) {
                payload = data;
            }
        }

        json_t *thread_id = json_object_get(payload, "threadId");
        json_t *run_id = json_object_get(payload, "runId");
        json_t *messages = json_object_get(payload, "messages");
        const bool run_id_ok =
                (json_is_string(run_id) && json_string_length(run_id) > 0) || json_is_null(run_id);
        if (json_is_string(thread_id) && json_string_length(thread_id) > 0 && run_id_ok &&
                AguiSseMessagesLookValid(messages)) {
            looks_valid = true;
        }
    }

    json_decref(root);
    return looks_valid;
}

static bool AguiSseInspectRequestBody(htp_tx_t *tx, AguiSseTxData *txmeta)
{
    if (tx == NULL || txmeta == NULL) {
        return false;
    }
    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud == NULL || htud->request_body.sb == NULL) {
        return false;
    }

    const uint8_t *body_data = NULL;
    uint32_t body_len = 0;
    uint64_t body_offset = 0;
    if (StreamingBufferGetData(htud->request_body.sb, &body_data, &body_len, &body_offset) == 0 ||
            body_data == NULL || body_len == 0) {
        return false;
    }

    if (body_len > agui_sse_options.max_request_body) {
        body_len = agui_sse_options.max_request_body;
    }

    if (AguiSseBodyLooksLikeRunAgentInput(body_data, body_len)) {
        txmeta->request_has_run_input = true;
        return true;
    }
    return false;
}

static void AguiSseRequestInspect(Flow *f, htp_tx_t *tx)
{
    if (!AguiSseIsEnabled() || tx == NULL || tx->request_headers == NULL) {
        return;
    }
    const bool accept_sse =
            AguiSseHeaderContainsValue(tx->request_headers, "Accept", "text/event-stream");
    const bool accept_proto = AguiSseHeaderContainsValue(
            tx->request_headers, "Accept", "application/vnd.ag-ui.event+proto");
    if (!accept_sse && !accept_proto) {
        return;
    }

    AguiSseTxData *txmeta = AguiSseTxDataGetMutable(tx);
    if (txmeta != NULL) {
        txmeta->request_wants_sse = accept_sse;
        txmeta->request_accepts_proto = accept_proto;
        txmeta->request_content_type_json = AguiSseHeaderContainsValue(tx->request_headers,
                                                    "Content-Type", "application/json") ||
                                            AguiSseHeaderContainsValue(tx->request_headers,
                                                    "Content-Type", "application/vnd.ag-ui+json");
        if (f != NULL) {
            SCLogInfo("agui flow %" PRId64 " request hints sse=%s proto=%s content-json=%s",
                    FlowGetId(f), accept_sse ? "yes" : "no", accept_proto ? "yes" : "no",
                    txmeta->request_content_type_json ? "yes" : "no");
        }
        if (txmeta->request_content_type_json) {
            AguiSseInspectRequestBody(tx, txmeta);
        }
        AguiSseMaybeConfirm(txmeta);
        AguiSseApplySchemeIfReady(tx, txmeta);
        if (f != NULL && txmeta->agui_confirmed) {
            AguiSseMarkFlowConfirmed(f, "request_inspection");
        }
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

    json_error_t error;
    json_t *root = json_loadb((const char *)MEMBUFFER_BUFFER(payload), len, 0, &error);
    if (root != NULL) {
        txmeta->json_parsed++;
        if (json_is_object(root)) {
            json_t *type = json_object_get(root, "type");
            if (json_is_string(type)) {
                const char *type_str = json_string_value(type);
                if (type_str != NULL && AguiSseEventTypeLooksValid(type_str)) {
                    txmeta->event_count++;
                    txmeta->payload_bytes += len;
                    txmeta->response_has_valid_events = true;
                    strlcpy(txmeta->last_event_type, type_str, sizeof(txmeta->last_event_type));
                    AguiSseMaybeConfirm(txmeta);
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

static bool AguiSseScanJsonForEventTypes(
        const uint8_t *json_data, uint32_t json_len, AguiSseTxData *txmeta)
{
    if (json_data == NULL || json_len == 0 || txmeta == NULL) {
        return false;
    }

    static const char prefix[] = "\"type\":\"";
    const size_t prefix_len = sizeof(prefix) - 1U;

    uint32_t pos = 0;
    bool found = false;
    while (pos + prefix_len < json_len) {
        if (memcmp(&json_data[pos], prefix, prefix_len) != 0) {
            pos++;
            continue;
        }

        const uint8_t *value_start = &json_data[pos + prefix_len];
        const uint8_t *cur = value_start;
        const uint8_t *end = json_data + json_len;
        while (cur < end) {
            if (*cur == '\\') {
                if ((cur + 1) < end) {
                    cur += 2;
                    continue;
                }
                cur = end;
                break;
            }
            if (*cur == '"') {
                break;
            }
            cur++;
        }

        if (cur < end && cur > value_start) {
            const size_t value_len = (size_t)(cur - value_start);
            if (value_len < sizeof(txmeta->last_event_type)) {
                char type_buf[sizeof(txmeta->last_event_type)];
                memcpy(type_buf, value_start, value_len);
                type_buf[value_len] = '\0';
                if (AguiSseEventTypeLooksValid(type_buf)) {
                    txmeta->event_count++;
                    txmeta->payload_bytes += json_len;
                    txmeta->response_has_valid_events = true;
                    strlcpy(txmeta->last_event_type, type_buf, sizeof(txmeta->last_event_type));
                    AguiSseMaybeConfirm(txmeta);
                    found = true;
                }
            }
        }

        if (cur < end) {
            pos = (uint32_t)(cur - json_data) + 1U;
        } else {
            break;
        }
    }
    return found;
}

static void AguiSseProcessMultipartJson(
        const uint8_t *json_data, uint32_t json_len, AguiSseTxData *txmeta)
{
    if (json_data == NULL || json_len == 0 || txmeta == NULL) {
        return;
    }

    json_error_t error;
    json_t *root = json_loadb((const char *)json_data, json_len, JSON_DISABLE_EOF_CHECK, &error);
    if (root != NULL) {
        txmeta->json_parsed++;
        json_decref(root);
    } else {
        txmeta->json_failed++;
    }

    if (!AguiSseScanJsonForEventTypes(json_data, json_len, txmeta)) {
        txmeta->event_count++;
        txmeta->payload_bytes += json_len;
        txmeta->response_has_valid_events = true;
        if (txmeta->last_event_type[0] == '\0') {
            strlcpy(txmeta->last_event_type, "graphql", sizeof(txmeta->last_event_type));
        }
        AguiSseMaybeConfirm(txmeta);
    }
}

static const uint8_t *AguiSseFindBoundary(
        const uint8_t *cursor, const uint8_t *end, const char *boundary, size_t boundary_len)
{
    if (cursor == NULL || end == NULL || boundary == NULL || boundary_len == 0) {
        return NULL;
    }
    while (cursor + 2 + boundary_len <= end) {
        if (cursor[0] == '-' && cursor[1] == '-' &&
                memcmp(cursor + 2, boundary, boundary_len) == 0) {
            return cursor;
        }
        cursor++;
    }
    return NULL;
}

static void AguiSseProcessMultipartPart(
        const uint8_t *part, uint32_t part_len, AguiSseTxData *txmeta)
{
    if (part == NULL || part_len == 0 || txmeta == NULL) {
        return;
    }

    uint32_t pos = 0;
    while (pos + 1 < part_len) {
        if (part[pos] == '\r' && (pos + 3) < part_len && part[pos + 1] == '\n' &&
                part[pos + 2] == '\r' && part[pos + 3] == '\n') {
            pos += 4;
            break;
        }
        if (part[pos] == '\n' && part[pos + 1] == '\n') {
            pos += 2;
            break;
        }
        pos++;
    }
    if (pos >= part_len) {
        return;
    }

    const uint8_t *json_data = &part[pos];
    uint32_t json_len = part_len - pos;
    while (json_len > 0 && (json_data[json_len - 1] == '\n' || json_data[json_len - 1] == '\r')) {
        json_len--;
    }
    if (json_len == 0) {
        return;
    }

    AguiSseProcessMultipartJson(json_data, json_len, txmeta);
}

static void AguiSseProcessMultipartGraphql(
        const uint8_t *data, uint32_t len, AguiSseTxData *txmeta, const char *boundary)
{
    if (data == NULL || len == 0 || txmeta == NULL || boundary == NULL || boundary[0] == '\0') {
        return;
    }

    const size_t boundary_len = strlen(boundary);
    if (boundary_len == 0) {
        return;
    }

    const uint8_t *cursor = data;
    const uint8_t *end = data + len;

    while (cursor < end) {
        const uint8_t *boundary_pos = AguiSseFindBoundary(cursor, end, boundary, boundary_len);
        if (boundary_pos == NULL) {
            break;
        }
        cursor = boundary_pos + 2 + boundary_len;

        bool final_boundary = false;
        if ((size_t)(end - cursor) >= 2 && cursor[0] == '-' && cursor[1] == '-') {
            final_boundary = true;
            cursor += 2;
        }

        while (cursor < end && (cursor[0] == '\r' || cursor[0] == '\n')) {
            cursor++;
        }

        if (final_boundary) {
            break;
        }

        const uint8_t *next_boundary = AguiSseFindBoundary(cursor, end, boundary, boundary_len);
        const uint8_t *part_end = (next_boundary != NULL) ? next_boundary : end;
        const uint8_t *part_start = cursor;
        while (part_end > part_start && (part_end[-1] == '\r' || part_end[-1] == '\n')) {
            part_end--;
        }
        if (part_end > part_start) {
            AguiSseProcessMultipartPart(part_start, (uint32_t)(part_end - part_start), txmeta);
        }

        if (next_boundary == NULL) {
            break;
        }
        cursor = next_boundary;
    }
}

static void AguiSseResponseInspect(Flow *f, htp_tx_t *tx)
{
    if (!AguiSseIsEnabled() || tx == NULL) {
        return;
    }

    htp_table_t *headers = tx->response_headers;
    if (headers == NULL) {
        return;
    }

    const bool header_proto = AguiSseHeaderContainsValue(
            headers, "Content-Type", "application/vnd.ag-ui.event+proto");
    const bool header_sse =
            AguiSseHeaderContainsValue(headers, "Content-Type", "text/event-stream");
    const bool header_json =
            AguiSseHeaderContainsValue(headers, "Content-Type", "application/vnd.ag-ui.event+json");
    const bool header_generic =
            (!header_proto && AguiSseHeaderContainsValue(
                                      headers, "Content-Type", "application/vnd.ag-ui.event"));

    const bool treat_proto = header_proto && agui_sse_options.standard_mode;
    char *boundary = NULL;
    size_t boundary_capacity = 0;
    bool treat_multipart = false;
    if (!treat_proto && agui_sse_options.graphql_mode) {
        boundary_capacity = (size_t)agui_sse_options.multipart_boundary_max + 1U;
        if (boundary_capacity == 0) {
            boundary_capacity = AGUI_SSE_MULTIPART_BOUNDARY_MAX_DEFAULT + 1U;
        }
        boundary = SCCalloc(boundary_capacity, sizeof(char));
        if (boundary == NULL) {
            SCLogWarning("agui: unable to allocate multipart boundary buffer");
        } else {
            treat_multipart = AguiSseExtractMultipartBoundary(headers, boundary, boundary_capacity);
            if (!treat_multipart) {
                SCFree(boundary);
                boundary = NULL;
            }
        }
    }
    const bool treat_sse = (!treat_proto) && (!treat_multipart) && agui_sse_options.standard_mode &&
                           (header_sse || header_json || header_generic);

    if (!treat_proto && !treat_sse && !treat_multipart) {
        if (boundary != NULL) {
            SCFree(boundary);
        }
        return;
    }

    AguiSseTxData *txmeta = AguiSseTxDataGetMutable(tx);
    if (txmeta == NULL) {
        if (boundary != NULL) {
            SCFree(boundary);
        }
        return;
    }

    if (treat_proto) {
        txmeta->response_is_proto = true;
        if (f != NULL) {
            SCLogInfo("agui flow %" PRId64 " response indicates proto stream", FlowGetId(f));
        }
        AguiSseMaybeConfirm(txmeta);
        AguiSseApplySchemeIfReady(tx, txmeta);
        if (f != NULL && txmeta->agui_confirmed) {
            AguiSseMarkFlowConfirmed(f, "proto_response");
        }
        if (boundary != NULL) {
            SCFree(boundary);
        }
        return;
    }

    if (treat_multipart) {
        txmeta->response_is_sse = true;
        if (f != NULL) {
            SCLogInfo("agui flow %" PRId64 " response indicates multipart stream", FlowGetId(f));
        }

        HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
        if (htud == NULL || htud->response_body.sb == NULL) {
            if (boundary != NULL) {
                SCFree(boundary);
            }
            return;
        }

        const uint8_t *body_data = NULL;
        uint32_t body_len = 0;
        uint64_t body_offset = 0;
        if (StreamingBufferGetData(htud->response_body.sb, &body_data, &body_len, &body_offset) ==
                        0 ||
                body_len == 0) {
            if (boundary != NULL) {
                SCFree(boundary);
            }
            return;
        }

        AguiSseProcessMultipartGraphql(body_data, body_len, txmeta, boundary);
        SCFree(boundary);
        boundary = NULL;
        if (f != NULL && txmeta->event_count > 0) {
            SCLogInfo("agui flow %" PRId64 " parsed %u SSE events (last=%s)", FlowGetId(f),
                    txmeta->event_count,
                    (txmeta->last_event_type[0] != '\0') ? txmeta->last_event_type : "unknown");
        }
        AguiSseMaybeConfirm(txmeta);
        AguiSseApplySchemeIfReady(tx, txmeta);
        if (f != NULL && txmeta->agui_confirmed) {
            AguiSseMarkFlowConfirmed(f, "multipart_response");
        }
        return;
    }
    if (boundary != NULL) {
        SCFree(boundary);
        boundary = NULL;
    }

    txmeta->response_is_sse = true;
    if (f != NULL) {
        SCLogInfo("agui flow %" PRId64 " response indicates SSE stream", FlowGetId(f));
    }

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
    if (f != NULL && txmeta->event_count > 0) {
        SCLogInfo("agui flow %" PRId64 " parsed %u SSE events (last=%s)", FlowGetId(f),
                txmeta->event_count,
                (txmeta->last_event_type[0] != '\0') ? txmeta->last_event_type : "unknown");
    }
    AguiSseMaybeConfirm(txmeta);
    AguiSseApplySchemeIfReady(tx, txmeta);
    if (f != NULL && txmeta->agui_confirmed) {
        AguiSseMarkFlowConfirmed(f, "sse_response");
    }
}

void AguiSseOnHttpRequestComplete(Flow *f, htp_tx_t *tx)
{
    if (!AguiSseIsEnabled()) {
        return;
    }
    AguiSseRequestInspect(f, tx);
}

void AguiSseOnHttpResponseComplete(Flow *f, htp_tx_t *tx)
{
    if (!AguiSseIsEnabled()) {
        return;
    }
    AguiSseResponseInspect(f, tx);
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
    txmeta.request_has_run_input = true;
    txmeta.response_is_sse = true;
    AguiSseProcessBuffer((const uint8_t *)payload, (uint32_t)strlen(payload), &txmeta);
    if (out_count != NULL) {
        *out_count = txmeta.event_count;
    }
    if (last_type != NULL && last_type_len > 0) {
        strlcpy(last_type, txmeta.last_event_type, last_type_len);
    }
    return txmeta.agui_confirmed;
}

bool AguiSseTestBodyLooksLikeRunAgentInput(const char *body)
{
    if (body == NULL) {
        return false;
    }
    return AguiSseBodyLooksLikeRunAgentInput((const uint8_t *)body, (uint32_t)strlen(body));
}

bool AguiSseTestParseMultipartSample(const char *boundary, const char *body, uint32_t *out_count,
        char *last_type, size_t last_type_len)
{
    if (boundary == NULL || body == NULL) {
        return false;
    }

    AguiSseTxData txmeta = { 0 };
    txmeta.request_has_run_input = true;
    txmeta.request_wants_sse = true;

    AguiSseProcessMultipartGraphql(
            (const uint8_t *)body, (uint32_t)strlen(body), &txmeta, boundary);

    if (out_count != NULL) {
        *out_count = txmeta.event_count;
    }
    if (last_type != NULL && last_type_len > 0) {
        strlcpy(last_type, txmeta.last_event_type, last_type_len);
    }
    return txmeta.response_has_valid_events;
}

#include "tests/app-layer-agui-sse.c"
#endif
