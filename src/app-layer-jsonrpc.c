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
#include "app-layer-jsonrpc.h"
#include "app-layer-jsonrpc-internal.h"

#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <strings.h>

#include "app-layer-events.h"
#include "app-layer-htp.h"
#include "conf.h"
#include "counters.h"
#include "decode.h"
#include "flow-storage.h"
#include "host-storage.h"
#include "host.h"
#include "util-streaming-buffer.h"
#include "util-debug.h"
#include "util-print.h"

#include <htp/htp.h>
#include <htp/bstr.h>

#define JSONRPC_MAX_SERVICES 16
#define JSONRPC_HOST_CACHE_TTL 600

typedef struct JsonRpcHostState_ {
    uint8_t service_id;
    uint8_t stage;
    uint32_t padding;
    uint64_t last_seen;
} JsonRpcHostState;

typedef struct JsonRpcServiceEntry_ {
    const JsonRpcServiceDef *def;
} JsonRpcServiceEntry;

typedef struct JsonRpcConfig_ {
    bool a2a_enabled;
    bool mcp_enabled;
} JsonRpcConfig;

typedef struct JsonRpcServiceStats_ {
    SC_ATOMIC_DECLARE(uint64_t, card_seen);
    SC_ATOMIC_DECLARE(uint64_t, init_seen);
    SC_ATOMIC_DECLARE(uint64_t, rpc_seen);
    SC_ATOMIC_DECLARE(uint64_t, stream_seen);
} JsonRpcServiceStats;

static JsonRpcServiceEntry jsonrpc_services[JSONRPC_MAX_SERVICES];
static size_t jsonrpc_service_cnt = 0;

static FlowStorageId jsonrpc_flow_storage_id = { .id = -1 };
static HostStorageId jsonrpc_host_storage_id = { .id = -1 };
static bool jsonrpc_initialized = false;
static bool jsonrpc_stats_registered = false;

static JsonRpcConfig jsonrpc_config = {
    .a2a_enabled = true,
    .mcp_enabled = true,
};
static JsonRpcServiceStats jsonrpc_service_stats[JSONRPC_SERVICE_MAX];

static inline bool JsonRpcAnyServiceEnabled(void)
{
    return jsonrpc_config.a2a_enabled || jsonrpc_config.mcp_enabled;
}

static inline JsonRpcServiceStats *JsonRpcGetStatsForService(uint8_t service_id)
{
    if (service_id == JSONRPC_SERVICE_UNKNOWN || service_id >= JSONRPC_SERVICE_MAX) {
        return NULL;
    }
    return &jsonrpc_service_stats[service_id];
}

static inline void JsonRpcStatsIncrementCard(uint8_t service_id)
{
    JsonRpcServiceStats *stats = JsonRpcGetStatsForService(service_id);
    if (stats != NULL) {
        SC_ATOMIC_ADD(stats->card_seen, 1);
    }
}

static inline void JsonRpcStatsIncrementStage(uint8_t service_id, JsonRpcStage stage)
{
    JsonRpcServiceStats *stats = JsonRpcGetStatsForService(service_id);
    if (stats == NULL) {
        return;
    }

    switch (stage) {
        case JSONRPC_STAGE_INIT:
            SC_ATOMIC_ADD(stats->init_seen, 1);
            break;
        case JSONRPC_STAGE_RPC:
            SC_ATOMIC_ADD(stats->rpc_seen, 1);
            break;
        case JSONRPC_STAGE_STREAM:
            SC_ATOMIC_ADD(stats->stream_seen, 1);
            break;
        case JSONRPC_STAGE_NONE:
        case JSONRPC_STAGE_DISCOVERY:
        default:
            break;
    }
}

static void *JsonRpcFlowStateAlloc(unsigned int size)
{
    return SCCalloc(1, size);
}

static void JsonRpcFlowStateFree(void *ptr)
{
    if (ptr != NULL) {
        SCFree(ptr);
    }
}

static void JsonRpcRegisterFlowStorage(void)
{
    if (jsonrpc_flow_storage_id.id >= 0) {
        return;
    }

    jsonrpc_flow_storage_id = FlowStorageRegister("jsonrpc_flow_state",
            sizeof(JsonRpcFlowState), JsonRpcFlowStateAlloc, JsonRpcFlowStateFree);
    if (jsonrpc_flow_storage_id.id < 0) {
        FatalError("jsonrpc_flow_state storage registration failed");
    }
}

static void *JsonRpcHostStateAlloc(unsigned int size)
{
    return SCCalloc(1, size);
}

static void JsonRpcHostStateFree(void *ptr)
{
    if (ptr != NULL) {
        SCFree(ptr);
    }
}

static void JsonRpcRegisterHostStorage(void)
{
    if (jsonrpc_host_storage_id.id >= 0) {
        return;
    }

    jsonrpc_host_storage_id = HostStorageRegister("jsonrpc_host_state",
            sizeof(JsonRpcHostState), JsonRpcHostStateAlloc, JsonRpcHostStateFree);
    if (jsonrpc_host_storage_id.id < 0) {
        FatalError("jsonrpc_host_state storage registration failed");
    }
}

static void JsonRpcLoadConfig(void)
{
    int val = 0;
    if (ConfGetBool("app-layer.protocols.ai-a2a.enabled", &val) == 1) {
        jsonrpc_config.a2a_enabled = (val != 0);
    }
    val = 0;
    if (ConfGetBool("app-layer.protocols.ai-mcp.enabled", &val) == 1) {
        jsonrpc_config.mcp_enabled = (val != 0);
    }
}

static uint64_t JsonRpcStatsGetA2ACard(void)
{
    return SC_ATOMIC_GET(jsonrpc_service_stats[JSONRPC_SERVICE_A2A].card_seen);
}

static uint64_t JsonRpcStatsGetA2AInit(void)
{
    return SC_ATOMIC_GET(jsonrpc_service_stats[JSONRPC_SERVICE_A2A].init_seen);
}

static uint64_t JsonRpcStatsGetA2ARpc(void)
{
    return SC_ATOMIC_GET(jsonrpc_service_stats[JSONRPC_SERVICE_A2A].rpc_seen);
}

static uint64_t JsonRpcStatsGetA2AStream(void)
{
    return SC_ATOMIC_GET(jsonrpc_service_stats[JSONRPC_SERVICE_A2A].stream_seen);
}

static uint64_t JsonRpcStatsGetMcpCard(void)
{
    return SC_ATOMIC_GET(jsonrpc_service_stats[JSONRPC_SERVICE_MCP].card_seen);
}

static uint64_t JsonRpcStatsGetMcpInit(void)
{
    return SC_ATOMIC_GET(jsonrpc_service_stats[JSONRPC_SERVICE_MCP].init_seen);
}

static uint64_t JsonRpcStatsGetMcpRpc(void)
{
    return SC_ATOMIC_GET(jsonrpc_service_stats[JSONRPC_SERVICE_MCP].rpc_seen);
}

static uint64_t JsonRpcStatsGetMcpStream(void)
{
    return SC_ATOMIC_GET(jsonrpc_service_stats[JSONRPC_SERVICE_MCP].stream_seen);
}

void JsonRpcRegisterGlobalCounters(void)
{
    if (jsonrpc_stats_registered) {
        return;
    }
    if (!JsonRpcAnyServiceEnabled()) {
        return;
    }

    StatsRegisterGlobalCounter("detect.a2a.card_seen", JsonRpcStatsGetA2ACard);
    StatsRegisterGlobalCounter("detect.a2a.init_seen", JsonRpcStatsGetA2AInit);
    StatsRegisterGlobalCounter("detect.a2a.rpc_seen", JsonRpcStatsGetA2ARpc);
    StatsRegisterGlobalCounter("detect.a2a.stream_seen", JsonRpcStatsGetA2AStream);

    StatsRegisterGlobalCounter("detect.mcp.card_seen", JsonRpcStatsGetMcpCard);
    StatsRegisterGlobalCounter("detect.mcp.init_seen", JsonRpcStatsGetMcpInit);
    StatsRegisterGlobalCounter("detect.mcp.rpc_seen", JsonRpcStatsGetMcpRpc);
    StatsRegisterGlobalCounter("detect.mcp.stream_seen", JsonRpcStatsGetMcpStream);
    jsonrpc_stats_registered = true;
}

static JsonRpcTxData *JsonRpcTxDataGetMutable(htp_tx_t *tx)
{
    if (tx == NULL) {
        return NULL;
    }
    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud == NULL) {
        return NULL;
    }
    if (htud->jsonrpc_tx == NULL) {
        htud->jsonrpc_tx = SCCalloc(1, sizeof(JsonRpcTxData));
        if (htud->jsonrpc_tx != NULL) {
            htud->jsonrpc_tx->service_id = JSONRPC_SERVICE_UNKNOWN;
            htud->jsonrpc_tx->rpc_stage = JSONRPC_STAGE_NONE;
        }
    }
    return htud->jsonrpc_tx;
}

static const JsonRpcServiceDef *JsonRpcMatchDiscoveryByPath(const bstr *path)
{
    if (path == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < jsonrpc_service_cnt; i++) {
        const JsonRpcServiceDef *def = jsonrpc_services[i].def;
        if (def == NULL || def->discovery_paths == NULL) {
            continue;
        }

        for (size_t j = 0; j < def->discovery_path_cnt; j++) {
            const char *needle = def->discovery_paths[j];
            if (needle == NULL) {
                continue;
            }
            if (bstr_cmp_c_nocase(path, needle) == 0) {
                return def;
            }
        }
    }

    return NULL;
}

static const JsonRpcServiceDef *JsonRpcServiceFindById(uint8_t service_id)
{
    if (service_id == JSONRPC_SERVICE_UNKNOWN) {
        return NULL;
    }

    for (size_t i = 0; i < jsonrpc_service_cnt; i++) {
        const JsonRpcServiceDef *def = jsonrpc_services[i].def;
        if (def != NULL && def->id == service_id) {
            return def;
        }
    }
    return NULL;
}

static const JsonRpcServiceDef *JsonRpcDetectServiceByMethod(const char *method)
{
    if (method == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < jsonrpc_service_cnt; i++) {
        const JsonRpcServiceDef *def = jsonrpc_services[i].def;
        if (def != NULL && def->method_match != NULL && def->method_match(method)) {
            return def;
        }
    }
    return NULL;
}

const JsonRpcServiceDef *JsonRpcServiceLookup(uint8_t service_id)
{
    return JsonRpcServiceFindById(service_id);
}

static bool JsonRpcIsGetMethod(const htp_tx_t *tx)
{
    if (tx == NULL || tx->request_method == NULL) {
        return false;
    }
    return (bstr_cmp_c_nocase(tx->request_method, "GET") == 0);
}

static bool JsonRpcFlowToServerAddress(const Flow *f, Address *addr)
{
    if (f == NULL || addr == NULL) {
        return false;
    }

    memset(addr, 0x00, sizeof(*addr));
    if (FLOW_IS_IPV4(f)) {
        addr->family = AF_INET;
    } else if (FLOW_IS_IPV6(f)) {
        addr->family = AF_INET6;
    } else {
        return false;
    }

    const FlowAddress *flow_addr = &f->dst;
    addr->addr_data32[0] = flow_addr->address.address_un_data32[0];
    addr->addr_data32[1] = flow_addr->address.address_un_data32[1];
    addr->addr_data32[2] = flow_addr->address.address_un_data32[2];
    addr->addr_data32[3] = flow_addr->address.address_un_data32[3];
    return true;
}

static JsonRpcHostState *JsonRpcHostStateLock(const Address *addr, bool create, Host **locked_host)
{
    if (jsonrpc_host_storage_id.id < 0 || addr == NULL || locked_host == NULL) {
        return NULL;
    }

    Host *host = create ? HostGetHostFromHash((Address *)addr)
                        : HostLookupHostFromHash((Address *)addr);
    if (host == NULL) {
        return NULL;
    }

    JsonRpcHostState *state = HostGetStorageById(host, jsonrpc_host_storage_id);
    if (state == NULL && create) {
        state = HostAllocStorageById(host, jsonrpc_host_storage_id);
        if (state != NULL) {
            memset(state, 0x00, sizeof(*state));
        }
    }

    if (state == NULL) {
        HostUnlock(host);
        HostDeReference(&host);
        return NULL;
    }

    *locked_host = host;
    return state;
}

static void JsonRpcHostStateUnlock(Host **host)
{
    if (host != NULL && *host != NULL) {
        HostUnlock(*host);
        HostDeReference(host);
    }
}

static void JsonRpcHostStateMaybeSeedFlow(Flow *f, JsonRpcFlowState *state)
{
    if (jsonrpc_host_storage_id.id < 0 || f == NULL || state == NULL) {
        return;
    }

    Address addr;
    if (!JsonRpcFlowToServerAddress(f, &addr)) {
        return;
    }

    Host *host = NULL;
    JsonRpcHostState *host_state = JsonRpcHostStateLock(&addr, false, &host);
    if (host_state == NULL) {
        return;
    }

    if (host_state->stage != JSONRPC_STAGE_NONE) {
        uint64_t now = SCTIME_SECS(f->lastts);
        if (now <= host_state->last_seen + JSONRPC_HOST_CACHE_TTL) {
            state->service_id = host_state->service_id;
            state->stage = host_state->stage;
            state->host_cached = true;
        } else {
            memset(host_state, 0x00, sizeof(*host_state));
        }
    }

    JsonRpcHostStateUnlock(&host);
}

static void JsonRpcHostStateUpdate(Flow *f, const JsonRpcServiceDef *service, JsonRpcStage stage)
{
    if (jsonrpc_host_storage_id.id < 0 || f == NULL || service == NULL) {
        return;
    }

    Address addr;
    if (!JsonRpcFlowToServerAddress(f, &addr)) {
        return;
    }

    Host *host = NULL;
    JsonRpcHostState *host_state = JsonRpcHostStateLock(&addr, true, &host);
    if (host_state == NULL) {
        return;
    }

    if (host_state->stage < stage || host_state->service_id != service->id) {
        host_state->stage = stage;
        host_state->service_id = service->id;
    }
    host_state->last_seen = SCTIME_SECS(f->lastts);

    JsonRpcHostStateUnlock(&host);
}

static void JsonRpcStagePromote(
        Flow *f, JsonRpcFlowState *state, const JsonRpcServiceDef *service, JsonRpcStage target)
{
    if (state == NULL || service == NULL) {
        return;
    }

    bool advanced = false;
    if (state->stage < target) {
        state->stage = target;
        advanced = true;
    }

    if (f != NULL) {
        state->last_seen = f->lastts;
    }
    JsonRpcHostStateUpdate(f, service, target);

    if (advanced) {
        JsonRpcStatsIncrementStage(service->id, target);
    }
}

static void JsonRpcSetDecoderEvent(htp_tx_t *tx, uint8_t event_id)
{
    if (tx == NULL || event_id == 0) {
        return;
    }

    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud == NULL) {
        return;
    }

    AppLayerDecoderEventsSetEventRaw(&htud->tx_data.events, event_id);
}

static uint8_t JsonRpcResolveStageEventId(JsonRpcStage stage, uint8_t service_id)
{
    const bool is_mcp = (service_id == JSONRPC_SERVICE_MCP);

    switch (stage) {
        case JSONRPC_STAGE_DISCOVERY:
            return is_mcp ? HTTP_DECODER_EVENT_MCP_AGENT_CARD : HTTP_DECODER_EVENT_A2A_AGENT_CARD;
        case JSONRPC_STAGE_INIT:
            return is_mcp ? HTTP_DECODER_EVENT_MCP_STAGE_INIT : HTTP_DECODER_EVENT_A2A_STAGE_INIT;
        case JSONRPC_STAGE_RPC:
            return is_mcp ? HTTP_DECODER_EVENT_MCP_STAGE_RPC : HTTP_DECODER_EVENT_A2A_STAGE_RPC;
        case JSONRPC_STAGE_STREAM:
            return is_mcp ? HTTP_DECODER_EVENT_MCP_STAGE_STREAM : HTTP_DECODER_EVENT_A2A_STAGE_STREAM;
        case JSONRPC_STAGE_NONE:
        default:
            return 0;
    }
}

static uint8_t JsonRpcResolveAnomalyEventId(uint8_t service_id)
{
    return (service_id == JSONRPC_SERVICE_MCP) ? HTTP_DECODER_EVENT_MCP_ANOMALY
                                               : HTTP_DECODER_EVENT_A2A_ANOMALY;
}

static void JsonRpcEmitStageEvent(htp_tx_t *tx, JsonRpcStage stage, uint8_t service_id)
{
    const uint8_t event_id = JsonRpcResolveStageEventId(stage, service_id);
    JsonRpcSetDecoderEvent(tx, event_id);
}

static void JsonRpcEmitAnomalyEvent(htp_tx_t *tx, uint8_t service_id)
{
    const uint8_t event_id = JsonRpcResolveAnomalyEventId(service_id);
    JsonRpcSetDecoderEvent(tx, event_id);
}

static bool JsonRpcBstrContainsNocase(const bstr *value, const char *needle)
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

static bool JsonRpcHeaderContainsValue(htp_table_t *headers, const char *name, const char *needle)
{
    if (headers == NULL || name == NULL || needle == NULL) {
        return false;
    }
    htp_header_t *header = (htp_header_t *)htp_table_get_c(headers, name);
    if (header == NULL || header->value == NULL) {
        return false;
    }
    return JsonRpcBstrContainsNocase(header->value, needle);
}

static bool JsonRpcHeaderExists(htp_table_t *headers, const char *name)
{
    if (headers == NULL || name == NULL) {
        return false;
    }
    return (htp_table_get_c(headers, name) != NULL);
}

static void JsonRpcCaptureHttpHints(htp_tx_t *tx, JsonRpcTxData *txmeta)
{
    if (tx == NULL || txmeta == NULL) {
        return;
    }

    JsonRpcHttpHints *hints = &txmeta->http;
    memset(hints, 0x00, sizeof(*hints));

    if (tx->parsed_uri != NULL && tx->parsed_uri->path != NULL) {
        hints->path_contains_mcp = JsonRpcBstrContainsNocase(tx->parsed_uri->path, "mcp");
    }

    htp_table_t *headers = tx->request_headers;
    if (headers == NULL) {
        return;
    }

    hints->has_mcp_session_id = JsonRpcHeaderExists(headers, "mcp-session-id");
    hints->has_mcp_protocol_version = JsonRpcHeaderExists(headers, "mcp-protocol-version");
    hints->content_type_is_json =
            JsonRpcHeaderContainsValue(headers, "Content-Type", "application/json") ||
            JsonRpcHeaderContainsValue(headers, "Content-Type", "application/json-rpc") ||
            JsonRpcHeaderContainsValue(headers, "Content-Type", "application/mcp");
    hints->accept_event_stream =
            JsonRpcHeaderContainsValue(headers, "Accept", "text/event-stream");
}

static bool JsonRpcHttpHintsSuggestMcp(const JsonRpcHttpHints *hints)
{
    if (hints == NULL) {
        return false;
    }
    if (hints->has_mcp_session_id || hints->has_mcp_protocol_version) {
        return true;
    }
    if (hints->path_contains_mcp && hints->content_type_is_json) {
        return true;
    }
    if (hints->content_type_is_json && hints->accept_event_stream) {
        return true;
    }
    return false;
}

static bool JsonRpcMcpHttpHintsSatisfied(
        const JsonRpcFlowState *state, const JsonRpcTxData *txmeta)
{
    if (state != NULL && state->service_id == JSONRPC_SERVICE_MCP &&
            state->stage >= JSONRPC_STAGE_DISCOVERY) {
        return true;
    }
    if (txmeta == NULL) {
        return false;
    }

    const JsonRpcHttpHints *hints = &txmeta->http;
    return JsonRpcHttpHintsSuggestMcp(hints);
}

static void JsonRpcMaybeDetectStreamUpgrade(
        Flow *f, JsonRpcFlowState *state, const JsonRpcServiceDef *service, htp_tx_t *tx)
{
    if (f == NULL || state == NULL || service == NULL || tx == NULL) {
        return;
    }
    if (!service->supports_stream) {
        return;
    }
    if (state->stage < JSONRPC_STAGE_INIT || tx->request_method_number != HTP_M_GET) {
        return;
    }
    if (tx->request_headers == NULL) {
        return;
    }

    const bool has_sse = JsonRpcHeaderContainsValue(tx->request_headers, "Accept", "text/event-stream");
    const bool has_ws = JsonRpcHeaderContainsValue(tx->request_headers, "Upgrade", "websocket");
    if (!has_sse && !has_ws) {
        return;
    }

    JsonRpcTxData *txmeta = JsonRpcTxDataGetMutable(tx);
    if (txmeta != NULL) {
        txmeta->service_id = service->id;
        txmeta->stream_upgrade = true;
        txmeta->stream_ready = true;
        txmeta->stream_logged = false;
        txmeta->stream_stage = JSONRPC_STAGE_STREAM;
        if (has_sse) {
            strlcpy(txmeta->stream_type, "sse", sizeof(txmeta->stream_type));
        } else if (has_ws) {
            strlcpy(txmeta->stream_type, "websocket", sizeof(txmeta->stream_type));
        } else {
            txmeta->stream_type[0] = '\0';
        }
    }

    JsonRpcStagePromote(f, state, service, JSONRPC_STAGE_STREAM);
    JsonRpcEmitStageEvent(tx, JSONRPC_STAGE_STREAM, service->id);
}

typedef struct JsonRpcMessage_ {
    bool has_jsonrpc;
    bool has_method;
    char method[64];
    bool has_id;
    char id[40];
    bool has_params;
    uint32_t params_len;
    bool has_result;
    uint32_t result_len;
    bool has_error;
    uint32_t error_len;
} JsonRpcMessage;

const uint8_t *JsonRpcMemmem(
        const uint8_t *haystack, size_t haystack_len, const char *needle)
{
    const size_t needle_len = strlen(needle);
    if (needle_len == 0 || haystack_len < needle_len) {
        return NULL;
    }

    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (haystack[i] == (uint8_t)needle[0] &&
                memcmp(&haystack[i], needle, needle_len) == 0) {
            return &haystack[i];
        }
    }
    return NULL;
}

static bool JsonRpcExtractQuotedString(
        const uint8_t *ptr, const uint8_t *end, char *out, size_t out_len)
{
    if (ptr >= end || *ptr != '"') {
        return false;
    }
    ptr++;

    size_t written = 0;
    while (ptr < end) {
        if (*ptr == '\\' && ptr + 1 < end) {
            ptr++;
        } else if (*ptr == '"') {
            if (out_len > 0) {
                out[MIN(written, out_len - 1)] = '\0';
            }
            return true;
        }

        if (written + 1 < out_len) {
            out[written++] = (char)*ptr;
        }
        ptr++;
    }
    return false;
}

static bool JsonRpcExtractStringValue(
        const uint8_t *data, size_t len, const char *key, char *out, size_t out_len)
{
    const uint8_t *start = JsonRpcMemmem(data, len, key);
    if (start == NULL) {
        return false;
    }

    const uint8_t *ptr = start + strlen(key);
    const uint8_t *end = data + len;
    while (ptr < end && isspace((unsigned char)*ptr)) {
        ptr++;
    }
    if (ptr >= end || *ptr != ':') {
        return false;
    }
    ptr++;
    while (ptr < end && isspace((unsigned char)*ptr)) {
        ptr++;
    }
    if (ptr >= end || *ptr != '"') {
        return false;
    }

    if (!JsonRpcExtractQuotedString(ptr, end, out, out_len)) {
        return false;
    }
    return true;
}

static bool JsonRpcExtractIdValue(const uint8_t *data, size_t len, char *out, size_t out_len)
{
    const uint8_t *start = JsonRpcMemmem(data, len, "\"id\"");
    if (start == NULL) {
        return false;
    }

    const uint8_t *ptr = start + 4;
    const uint8_t *end = data + len;
    while (ptr < end && isspace((unsigned char)*ptr)) {
        ptr++;
    }
    if (ptr >= end || *ptr != ':') {
        return false;
    }
    ptr++;
    while (ptr < end && isspace((unsigned char)*ptr)) {
        ptr++;
    }
    if (ptr >= end) {
        return false;
    }

    if (*ptr == '"') {
        return JsonRpcExtractQuotedString(ptr, end, out, out_len);
    }

    size_t written = 0;
    while (ptr < end) {
        if (*ptr == ',' || *ptr == '}' || *ptr == ']' || isspace((unsigned char)*ptr)) {
            break;
        }
        if (written + 1 < out_len) {
            out[written++] = (char)*ptr;
        }
        ptr++;
    }
    if (written == 0) {
        return false;
    }
    out[MIN(written, out_len - 1)] = '\0';
    return true;
}

static const uint8_t *JsonRpcSkipQuotedString(const uint8_t *ptr, const uint8_t *end)
{
    if (ptr == NULL || ptr >= end || *ptr != '"') {
        return NULL;
    }

    ptr++;
    while (ptr < end) {
        if (*ptr == '\\') {
            ptr++;
            if (ptr < end) {
                ptr++;
            }
            continue;
        }
        if (*ptr == '"') {
            return ptr + 1;
        }
        ptr++;
    }
    return NULL;
}

static const uint8_t *JsonRpcSkipJsonContainer(
        const uint8_t *ptr, const uint8_t *end, const char open_ch, const char close_ch)
{
    if (ptr == NULL || ptr >= end || *ptr != open_ch) {
        return NULL;
    }

    int depth = 0;
    while (ptr < end) {
        if (*ptr == '"') {
            const uint8_t *next = JsonRpcSkipQuotedString(ptr, end);
            if (next == NULL) {
                return NULL;
            }
            ptr = next;
            continue;
        }
        if (*ptr == open_ch) {
            depth++;
        } else if (*ptr == close_ch) {
            depth--;
            if (depth == 0) {
                return ptr + 1;
            }
        }
        ptr++;
    }
    return NULL;
}

static const uint8_t *JsonRpcSkipJsonValue(const uint8_t *ptr, const uint8_t *end)
{
    if (ptr == NULL || ptr >= end) {
        return NULL;
    }

    if (*ptr == '"') {
        return JsonRpcSkipQuotedString(ptr, end);
    }
    if (*ptr == '{') {
        return JsonRpcSkipJsonContainer(ptr, end, '{', '}');
    }
    if (*ptr == '[') {
        return JsonRpcSkipJsonContainer(ptr, end, '[', ']');
    }

    while (ptr < end && !isspace((unsigned char)*ptr) && *ptr != ',' && *ptr != '}' && *ptr != ']') {
        ptr++;
    }
    return ptr;
}

static bool JsonRpcExtractJsonValueLength(
        const uint8_t *data, size_t len, const char *key, uint32_t *out_len)
{
    if (data == NULL || len == 0 || key == NULL || out_len == NULL) {
        return false;
    }

    const uint8_t *start = JsonRpcMemmem(data, len, key);
    if (start == NULL) {
        return false;
    }

    const uint8_t *ptr = start + strlen(key);
    const uint8_t *end = data + len;
    while (ptr < end && isspace((unsigned char)*ptr)) {
        ptr++;
    }
    if (ptr >= end || *ptr != ':') {
        return false;
    }
    ptr++;
    while (ptr < end && isspace((unsigned char)*ptr)) {
        ptr++;
    }
    if (ptr >= end) {
        return false;
    }

    const uint8_t *value_end = JsonRpcSkipJsonValue(ptr, end);
    if (value_end == NULL || value_end <= ptr) {
        return false;
    }

    size_t value_len = (size_t)(value_end - ptr);
    if (value_len > UINT32_MAX) {
        value_len = UINT32_MAX;
    }
    *out_len = (uint32_t)value_len;
    return true;
}

static bool JsonRpcValidateAgentCard(
        const JsonRpcServiceDef *service, const uint8_t *body, uint32_t len, JsonRpcTxData *txmeta)
{
    JsonRpcAgentCardValidatorFn validator = JsonRpcDefaultAgentCardValidator;
    if (service != NULL && service->card_validator != NULL) {
        validator = service->card_validator;
    }
    return validator(body, len, txmeta);
}

static bool JsonRpcParseMessage(const uint8_t *data, size_t len, JsonRpcMessage *msg)
{
    if (data == NULL || len == 0 || msg == NULL) {
        return false;
    }

    memset(msg, 0x00, sizeof(*msg));

    char version[8];
    if (JsonRpcExtractStringValue(data, len, "\"jsonrpc\"", version, sizeof(version))) {
        if (strcasecmp(version, "2.0") == 0) {
            msg->has_jsonrpc = true;
        }
    }

    if (JsonRpcExtractStringValue(data, len, "\"method\"", msg->method, sizeof(msg->method))) {
        msg->has_method = true;
    }
    if (JsonRpcExtractIdValue(data, len, msg->id, sizeof(msg->id))) {
        msg->has_id = true;
    }

    uint32_t value_len = 0;
    if (JsonRpcExtractJsonValueLength(data, len, "\"params\"", &value_len)) {
        msg->has_params = true;
        msg->params_len = value_len;
    }
    if (JsonRpcExtractJsonValueLength(data, len, "\"result\"", &value_len)) {
        msg->has_result = true;
        msg->result_len = value_len;
    }
    if (JsonRpcExtractJsonValueLength(data, len, "\"error\"", &value_len)) {
        msg->has_error = true;
        msg->error_len = value_len;
    }

    return msg->has_jsonrpc;
}

static void JsonRpcInspectRpcRequest(
        Flow *f, JsonRpcFlowState *state, const JsonRpcServiceDef *service, htp_tx_t *tx)
{
    if (f == NULL || state == NULL || service == NULL || tx == NULL) {
        return;
    }

    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud == NULL || htud->request_body.sb == NULL) {
        return;
    }

    const uint8_t *body_data = NULL;
    uint32_t body_len = 0;
    uint64_t body_offset = 0;
    if (StreamingBufferGetData(htud->request_body.sb, &body_data, &body_len, &body_offset) == 0 ||
            body_len == 0) {
        return;
    }

    JsonRpcMessage msg;
    if (!JsonRpcParseMessage(body_data, body_len, &msg)) {
        return;
    }

    if (!msg.has_method) {
        return;
    }

    const JsonRpcServiceDef *active_service = service;
    if (active_service == NULL && state->service_id != JSONRPC_SERVICE_UNKNOWN) {
        active_service = JsonRpcServiceFindById(state->service_id);
    }
    if (active_service == NULL) {
        active_service = JsonRpcDetectServiceByMethod(msg.method);
        if (active_service != NULL) {
            state->service_id = active_service->id;
            if (state->stage < JSONRPC_STAGE_DISCOVERY) {
                state->stage = JSONRPC_STAGE_DISCOVERY;
            }
            if (f != NULL) {
                state->last_seen = f->lastts;
            }
            JsonRpcHostStateUpdate(f, active_service, JSONRPC_STAGE_DISCOVERY);
        }
    }
    if (active_service == NULL || active_service->method_match == NULL ||
            !active_service->method_match(msg.method)) {
        return;
    }

    JsonRpcTxData *txmeta = JsonRpcTxDataGetMutable(tx);
    if (txmeta == NULL) {
        return;
    }
    JsonRpcCaptureHttpHints(tx, txmeta);

    if (active_service->id == JSONRPC_SERVICE_MCP &&
            !JsonRpcMcpHttpHintsSatisfied(state, txmeta)) {
        return;
    }

    bool is_init = false;
    if (active_service->method_is_init != NULL) {
        is_init = active_service->method_is_init(msg.method);
    } else if (state->stage < JSONRPC_STAGE_INIT) {
        is_init = true;
    }
    const bool is_stream = (active_service->method_is_stream != NULL &&
            active_service->method_is_stream(msg.method));

    JsonRpcStage target_stage;
    if (is_stream) {
        target_stage = JSONRPC_STAGE_STREAM;
    } else if (is_init) {
        target_stage = JSONRPC_STAGE_INIT;
    } else {
        target_stage = JSONRPC_STAGE_RPC;
    }

    if (state->stage > target_stage) {
        JsonRpcEmitAnomalyEvent(tx, active_service->id);
    }
    JsonRpcStagePromote(f, state, active_service, target_stage);
    JsonRpcEmitStageEvent(tx, target_stage, active_service->id);

    txmeta->service_id = active_service->id;
    txmeta->rpc_request = true;
    txmeta->rpc_ready = true;
    txmeta->rpc_logged = false;
    txmeta->rpc_is_init = is_init;
    txmeta->rpc_stage = target_stage;
    txmeta->rpc_size = body_len;
    txmeta->rpc_params_len = msg.has_params ? msg.params_len : 0;
    if (msg.has_method) {
        strlcpy(txmeta->rpc_method, msg.method, sizeof(txmeta->rpc_method));
    }
    if (msg.has_id) {
        strlcpy(txmeta->rpc_id, msg.id, sizeof(txmeta->rpc_id));
    }
    if (is_stream) {
        txmeta->stream_upgrade = true;
        txmeta->stream_ready = true;
        txmeta->stream_logged = false;
        txmeta->stream_stage = JSONRPC_STAGE_STREAM;
        if (txmeta->stream_type[0] == '\0') {
            strlcpy(txmeta->stream_type, "sse", sizeof(txmeta->stream_type));
        }
    }
}

static void JsonRpcInspectRpcResponse(
        Flow *f, JsonRpcFlowState *state, const JsonRpcServiceDef *service, htp_tx_t *tx)
{
    if (f == NULL || state == NULL || service == NULL || tx == NULL) {
        return;
    }
    (void)service;

    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud == NULL || htud->jsonrpc_tx == NULL || htud->response_body.sb == NULL) {
        return;
    }

    JsonRpcTxData *txmeta = htud->jsonrpc_tx;
    if (!txmeta->rpc_request || txmeta->rpc_response_ready) {
        return;
    }
    txmeta->service_id = service->id;

    const uint8_t *body_data = NULL;
    uint32_t body_len = 0;
    uint64_t body_offset = 0;
    if (StreamingBufferGetData(htud->response_body.sb, &body_data, &body_len, &body_offset) == 0 ||
            body_len == 0) {
        return;
    }

    JsonRpcMessage msg;
    if (!JsonRpcParseMessage(body_data, body_len, &msg)) {
        return;
    }

    if (!msg.has_result && !msg.has_error) {
        return;
    }

    txmeta->rpc_response = true;
    txmeta->rpc_response_ready = true;
    txmeta->rpc_response_logged = false;
    txmeta->rpc_response_error = msg.has_error;
    txmeta->rpc_result_size = body_len;
    txmeta->rpc_stage = MAX(txmeta->rpc_stage, state->stage);

    txmeta->rpc_id_match = false;
    if (msg.has_id && txmeta->rpc_id[0] != '\0') {
        if (strcmp(msg.id, txmeta->rpc_id) == 0) {
            txmeta->rpc_id_match = true;
        }
    }
}

static JsonRpcFlowState *JsonRpcFlowStateAllocIfNeeded(Flow *f)
{
    if (f == NULL || jsonrpc_flow_storage_id.id < 0) {
        return NULL;
    }

    JsonRpcFlowState *state = FlowGetStorageById(f, jsonrpc_flow_storage_id);
    if (state != NULL) {
        return state;
    }

    state = FlowAllocStorageById(f, jsonrpc_flow_storage_id);
    if (state != NULL) {
        memset(state, 0x00, sizeof(*state));
        state->stage = JSONRPC_STAGE_NONE;
        state->service_id = JSONRPC_SERVICE_UNKNOWN;
        state->host_cached = false;
        JsonRpcHostStateMaybeSeedFlow(f, state);
    }
    return state;
}

JsonRpcFlowState *JsonRpcFlowStateGet(Flow *f)
{
    if (f == NULL || jsonrpc_flow_storage_id.id < 0) {
        return NULL;
    }
    return FlowGetStorageById(f, jsonrpc_flow_storage_id);
}

void JsonRpcServiceRegister(const JsonRpcServiceDef *def)
{
    if (def == NULL || def->id == JSONRPC_SERVICE_UNKNOWN) {
        SCLogWarning("attempted to register invalid JSON-RPC service");
        return;
    }
    if (def->method_match == NULL) {
        SCLogWarning("jsonrpc service '%s' missing method matcher", def->name ? def->name : "unknown");
        return;
    }

    for (size_t i = 0; i < jsonrpc_service_cnt; i++) {
        if (jsonrpc_services[i].def != NULL &&
                jsonrpc_services[i].def->id == def->id) {
            SCLogWarning("JSON-RPC service id %u already registered", def->id);
            return;
        }
    }

    if (jsonrpc_service_cnt >= JSONRPC_MAX_SERVICES) {
        SCLogWarning("JSON-RPC service registry is full");
        return;
    }

    jsonrpc_services[jsonrpc_service_cnt++].def = def;
    SCLogInfo("registered JSON-RPC service '%s' (id=%u)", def->name, def->id);
}

static void JsonRpcRegisterBuiltinServices(void)
{
    if (jsonrpc_config.a2a_enabled) {
        JsonRpcRegisterA2AService();
    }
    if (jsonrpc_config.mcp_enabled) {
        JsonRpcRegisterMcpService();
    }
}

void JsonRpcInit(void)
{
    if (jsonrpc_initialized) {
        return;
    }

    JsonRpcLoadConfig();
    JsonRpcRegisterFlowStorage();
    JsonRpcRegisterHostStorage();
    if (JsonRpcAnyServiceEnabled()) {
        JsonRpcRegisterBuiltinServices();
    }
    if (jsonrpc_service_cnt > 0) {
        AppLayerHtpEnableRequestBodyCallback();
        AppLayerHtpEnableResponseBodyCallback();
    } else {
        jsonrpc_initialized = true;
        return;
    }

    jsonrpc_initialized = true;
}

static void JsonRpcHandleDiscovery(Flow *f, JsonRpcFlowState *state,
        const JsonRpcServiceDef *service, htp_tx_t *tx)
{
    if (state == NULL || service == NULL) {
        return;
    }

    JsonRpcTxData *txmeta = JsonRpcTxDataGetMutable(tx);
    if (txmeta != NULL) {
        txmeta->agent_card_request = true;
        txmeta->service_id = service->id;
    }

    if (state->stage > JSONRPC_STAGE_DISCOVERY) {
        JsonRpcEmitAnomalyEvent(tx, service->id);
    }

    state->service_id = service->id;
    JsonRpcStagePromote(f, state, service, JSONRPC_STAGE_DISCOVERY);
    if (f != NULL) {
        state->last_seen = f->lastts;
    }
    JsonRpcStatsIncrementCard(service->id);
    JsonRpcEmitStageEvent(tx, JSONRPC_STAGE_DISCOVERY, service->id);
}

void JsonRpcOnHttpResponseComplete(Flow *f, htp_tx_t *tx)
{
    if (!jsonrpc_initialized || !JsonRpcAnyServiceEnabled() || f == NULL || tx == NULL) {
        return;
    }

    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud == NULL || htud->jsonrpc_tx == NULL) {
        return;
    }

    JsonRpcTxData *txmeta = htud->jsonrpc_tx;

    JsonRpcFlowState *state = JsonRpcFlowStateGet(f);
    uint8_t service_id = JSONRPC_SERVICE_UNKNOWN;
    if (state != NULL && state->service_id != JSONRPC_SERVICE_UNKNOWN) {
        service_id = state->service_id;
    } else if (txmeta->service_id != JSONRPC_SERVICE_UNKNOWN) {
        service_id = txmeta->service_id;
    }

    const JsonRpcServiceDef *service = JsonRpcServiceLookup(service_id);
    if (service != NULL && txmeta->service_id == JSONRPC_SERVICE_UNKNOWN) {
        txmeta->service_id = service->id;
    }

    if (txmeta->agent_card_request && !txmeta->agent_card_ready) {
        const HtpBody *body = &htud->response_body;
        if (body != NULL && body->sb != NULL) {
            const uint8_t *body_data = NULL;
            uint32_t body_len = 0;
            uint64_t body_offset = 0;
            if (StreamingBufferGetData(body->sb, &body_data, &body_len, &body_offset) != 0 &&
                    body_len > 0 && JsonRpcValidateAgentCard(service, body_data, body_len, txmeta)) {
                uint8_t digest[SC_SHA256_LEN];
                if (SCSha256HashBuffer(body_data, body_len, digest, sizeof(digest))) {
                    PrintHexString(
                            txmeta->card_hash_hex, sizeof(txmeta->card_hash_hex), digest, sizeof(digest));
                    txmeta->card_size = body_len;
                    txmeta->agent_card_ready = true;
                    txmeta->agent_card_valid = true;
                }
            }
        }
    }

    if (state != NULL && service != NULL) {
        JsonRpcInspectRpcResponse(f, state, service, tx);
    }
}

void JsonRpcOnHttpRequestComplete(Flow *f, htp_tx_t *tx)
{
    if (!jsonrpc_initialized || !JsonRpcAnyServiceEnabled() || f == NULL || tx == NULL) {
        return;
    }

    const bool is_get = JsonRpcIsGetMethod(tx);
    const bool is_post = (tx->request_method_number == HTP_M_POST);

    if (!is_get && !is_post) {
        return;
    }

    JsonRpcFlowState *state = JsonRpcFlowStateAllocIfNeeded(f);
    if (state == NULL) {
        return;
    }

    JsonRpcTxData *txmeta = JsonRpcTxDataGetMutable(tx);
    if (txmeta != NULL) {
        JsonRpcCaptureHttpHints(tx, txmeta);
    }

    const JsonRpcServiceDef *service = NULL;

    if (is_get && tx->parsed_uri != NULL && tx->parsed_uri->path != NULL) {
        const JsonRpcServiceDef *matched = JsonRpcMatchDiscoveryByPath(tx->parsed_uri->path);
        if (matched != NULL) {
            state->service_id = matched->id;
            JsonRpcHandleDiscovery(f, state, matched, tx);
            service = matched;
        }
    }

    if (service == NULL && state->service_id != JSONRPC_SERVICE_UNKNOWN) {
        service = JsonRpcServiceFindById(state->service_id);
    }
    if (service == NULL && is_post && txmeta != NULL &&
            JsonRpcHttpHintsSuggestMcp(&txmeta->http)) {
        service = JsonRpcServiceFindById(JSONRPC_SERVICE_MCP);
        if (service != NULL) {
            state->service_id = service->id;
        }
    }

    if (service != NULL) {
        JsonRpcMaybeDetectStreamUpgrade(f, state, service, tx);
    }

    if (!is_post) {
        return;
    }

    JsonRpcInspectRpcRequest(f, state, service, tx);
}

const JsonRpcTxData *JsonRpcGetTxData(const htp_tx_t *tx)
{
    if (tx == NULL) {
        return NULL;
    }
    const HtpTxUserData *htud = (const HtpTxUserData *)htp_tx_get_user_data((htp_tx_t *)tx);
    if (htud == NULL) {
        return NULL;
    }
    return htud->jsonrpc_tx;
}

void JsonRpcTxDataMarkCardLogged(htp_tx_t *tx)
{
    if (tx == NULL) {
        return;
    }
    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud == NULL || htud->jsonrpc_tx == NULL) {
        return;
    }
    htud->jsonrpc_tx->agent_card_logged = true;
}

void JsonRpcTxDataMarkRpcLogged(htp_tx_t *tx)
{
    if (tx == NULL) {
        return;
    }
    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud == NULL || htud->jsonrpc_tx == NULL) {
        return;
    }
    htud->jsonrpc_tx->rpc_logged = true;
}

void JsonRpcTxDataMarkRpcResultLogged(htp_tx_t *tx)
{
    if (tx == NULL) {
        return;
    }
    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud == NULL || htud->jsonrpc_tx == NULL) {
        return;
    }
    htud->jsonrpc_tx->rpc_response_logged = true;
}

void JsonRpcTxDataMarkStreamLogged(htp_tx_t *tx)
{
    if (tx == NULL) {
        return;
    }
    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud == NULL || htud->jsonrpc_tx == NULL) {
        return;
    }
    htud->jsonrpc_tx->stream_logged = true;
}

#ifdef UNITTESTS
static void JsonRpcTestEnsureServicesRegistered(void)
{
    static bool registered = false;
    if (registered) {
        return;
    }
    JsonRpcRegisterA2AService();
    JsonRpcRegisterMcpService();
    registered = true;
}

JsonRpcServiceId JsonRpcTestDiscoveryLookup(const char *path)
{
    JsonRpcTestEnsureServicesRegistered();
    if (path == NULL) {
        return JSONRPC_SERVICE_UNKNOWN;
    }

    bstr *bpath = bstr_dup_c(path);
    if (bpath == NULL) {
        return JSONRPC_SERVICE_UNKNOWN;
    }
    const JsonRpcServiceDef *def = JsonRpcMatchDiscoveryByPath(bpath);
    bstr_free(bpath);
    if (def == NULL) {
        return JSONRPC_SERVICE_UNKNOWN;
    }
    return (JsonRpcServiceId)def->id;
}

bool JsonRpcTestParseMessage(const char *json, JsonRpcTestMessage *msg)
{
    if (json == NULL) {
        return false;
    }

    JsonRpcMessage internal;
    const bool ok =
            JsonRpcParseMessage((const uint8_t *)json, strlen(json), &internal);
    if (ok && msg != NULL) {
        msg->has_jsonrpc = internal.has_jsonrpc;
        msg->has_method = internal.has_method;
        msg->has_id = internal.has_id;
        strlcpy(msg->method, internal.method, sizeof(msg->method));
        strlcpy(msg->id, internal.id, sizeof(msg->id));
        msg->has_params = internal.has_params;
        msg->params_len = internal.params_len;
        msg->has_result = internal.has_result;
        msg->has_error = internal.has_error;
    }
    return ok;
}

bool JsonRpcTestMcpHttpHintsEvaluate(
        bool cached_service, bool path_contains_mcp, bool has_mcp_header, bool content_type_json)
{
    JsonRpcFlowState state;
    memset(&state, 0x00, sizeof(state));
    JsonRpcFlowState *state_ptr = NULL;
    if (cached_service) {
        state.service_id = JSONRPC_SERVICE_MCP;
        state.stage = JSONRPC_STAGE_DISCOVERY;
        state_ptr = &state;
    }

    JsonRpcTxData txmeta;
    memset(&txmeta, 0x00, sizeof(txmeta));
    txmeta.http.path_contains_mcp = path_contains_mcp;
    txmeta.http.content_type_is_json = content_type_json;
    txmeta.http.has_mcp_session_id = has_mcp_header;
    txmeta.http.has_mcp_protocol_version = has_mcp_header;
    return JsonRpcMcpHttpHintsSatisfied(state_ptr, &txmeta);
}

void AppLayerJsonRpcRegisterTests(void);
#include "tests/app-layer-jsonrpc.c"

#endif /* UNITTESTS */
