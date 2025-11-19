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

#include "output.h"
#include "output-json.h"
#include "output-json-ai.h"

#include "app-layer-htp.h"
#include "app-layer-parser.h"
#include "app-layer-jsonrpc.h"
#include "app-layer-agui-sse.h"

static void JsonRpcAppendHttpMetadata(
        JsonBuilder *jb, const htp_tx_t *tx, const char *scheme_header)
{
    if (tx == NULL) {
        return;
    }

    if (tx->request_hostname != NULL) {
        jb_set_string_from_bytes(
                jb, "host", bstr_ptr(tx->request_hostname), bstr_len(tx->request_hostname));
    }
    if (tx->request_uri != NULL) {
        jb_set_string_from_bytes(jb, "uri", bstr_ptr(tx->request_uri), bstr_len(tx->request_uri));
    }

    if (tx->response_status_number != -1) {
        jb_set_int(jb, "http_status", tx->response_status_number);
    }

    if (scheme_header != NULL && scheme_header[0] != '\0') {
        jb_set_string(jb, ":scheme", scheme_header);
    }
}

static const JsonRpcServiceDef *JsonRpcGetServiceFromTx(const JsonRpcTxData *txmeta)
{
    if (txmeta == NULL) {
        return NULL;
    }
    return JsonRpcServiceLookup(txmeta->service_id);
}

static const char *JsonRpcResolveEventType(
        const JsonRpcTxData *txmeta, const JsonRpcServiceDef **out_service)
{
    const JsonRpcServiceDef *service = JsonRpcGetServiceFromTx(txmeta);
    if (out_service != NULL) {
        *out_service = service;
    }
    if (service != NULL && service->event_type != NULL) {
        return service->event_type;
    }
    return "jsonrpc";
}

static const char *JsonRpcResolveScheme(const JsonRpcServiceDef *service)
{
    if (service != NULL && service->event_type != NULL) {
        return service->event_type;
    }
    return NULL;
}

static const char *JsonRpcDetermineScheme(htp_tx_t *tx, const JsonRpcServiceDef *service)
{
    const char *scheme = HtpTxGetScheme(tx);
    if (scheme != NULL && scheme[0] != '\0') {
        return scheme;
    }
    return JsonRpcResolveScheme(service);
}

static bool JsonRpcEmitCardEvent(
        ThreadVars *tv, OutputJsonThreadCtx *thread, const Packet *p, Flow *f, htp_tx_t *tx,
        const JsonRpcTxData *txmeta)
{
    (void)tv;
    (void)f;

    const JsonRpcServiceDef *service = NULL;
    const char *event_type = JsonRpcResolveEventType(txmeta, &service);
    const char *service_name =
            (service != NULL && service->name != NULL) ? service->name : "unknown";

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, event_type, NULL, thread->ctx);
    if (unlikely(jb == NULL)) {
        return false;
    }

    jb_set_string(jb, "event_type", event_type);
    jb_open_object(jb, event_type);
    jb_set_string(jb, "service", service_name);
    jb_set_string(jb, "event", "agent_card_discovery");
    jb_set_string(jb, "stage", JsonRpcStageToString(JSONRPC_STAGE_DISCOVERY));
    JsonRpcAppendHttpMetadata(jb, tx, JsonRpcDetermineScheme(tx, service));

    if (txmeta->card_hash_hex[0] != '\0') {
        jb_open_object(jb, "card");
        jb_set_string(jb, "hash_sha256", txmeta->card_hash_hex);
        jb_set_int(jb, "size", txmeta->card_size);
        jb_close(jb);
    }

    jb_close(jb);

    OutputJsonBuilderBuffer(jb, thread);
    jb_free(jb);
    JsonRpcTxDataMarkCardLogged(tx);
    return true;
}

static bool JsonRpcEmitRpcEvent(
        ThreadVars *tv, OutputJsonThreadCtx *thread, const Packet *p, Flow *f, htp_tx_t *tx,
        const JsonRpcTxData *txmeta)
{
    (void)tv;
    (void)f;

    const JsonRpcServiceDef *service = NULL;
    const char *event_type = JsonRpcResolveEventType(txmeta, &service);
    const char *service_name =
            (service != NULL && service->name != NULL) ? service->name : "unknown";

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, event_type, NULL, thread->ctx);
    if (unlikely(jb == NULL)) {
        return false;
    }

    jb_set_string(jb, "event_type", event_type);
    jb_open_object(jb, event_type);
    jb_set_string(jb, "service", service_name);
    jb_set_string(jb, "event", "rpc_call");
    jb_set_string(jb, "stage", JsonRpcStageToString(txmeta->rpc_stage));
    JsonRpcAppendHttpMetadata(jb, tx, JsonRpcDetermineScheme(tx, service));

    jb_open_object(jb, "rpc");
    if (txmeta->rpc_method[0] != '\0') {
        jb_set_string(jb, "method", txmeta->rpc_method);
    }
    if (txmeta->rpc_id[0] != '\0') {
        jb_set_string(jb, "id", txmeta->rpc_id);
    }
    if (txmeta->rpc_size > 0) {
        jb_set_int(jb, "size", txmeta->rpc_size);
    }
    if (txmeta->rpc_params_len > 0) {
        jb_set_int(jb, "params_len", txmeta->rpc_params_len);
    }
    jb_close(jb);

    jb_close(jb);

    OutputJsonBuilderBuffer(jb, thread);
    jb_free(jb);
    JsonRpcTxDataMarkRpcLogged(tx);
    return true;
}

static bool JsonRpcEmitRpcResultEvent(
        ThreadVars *tv, OutputJsonThreadCtx *thread, const Packet *p, Flow *f, htp_tx_t *tx,
        const JsonRpcTxData *txmeta)
{
    (void)tv;
    (void)f;

    const JsonRpcServiceDef *service = NULL;
    const char *event_type = JsonRpcResolveEventType(txmeta, &service);
    const char *service_name =
            (service != NULL && service->name != NULL) ? service->name : "unknown";

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, event_type, NULL, thread->ctx);
    if (unlikely(jb == NULL)) {
        return false;
    }

    jb_set_string(jb, "event_type", event_type);
    jb_open_object(jb, event_type);
    jb_set_string(jb, "service", service_name);
    jb_set_string(jb, "event", "rpc_result");
    jb_set_string(jb, "stage", JsonRpcStageToString(txmeta->rpc_stage));
    JsonRpcAppendHttpMetadata(jb, tx, JsonRpcDetermineScheme(tx, service));

    jb_open_object(jb, "rpc");
    if (txmeta->rpc_method[0] != '\0') {
        jb_set_string(jb, "method", txmeta->rpc_method);
    }
    if (txmeta->rpc_id[0] != '\0') {
        jb_set_string(jb, "id", txmeta->rpc_id);
    }
    if (txmeta->rpc_result_size > 0) {
        jb_set_int(jb, "size", txmeta->rpc_result_size);
    }
    jb_set_bool(jb, "match", txmeta->rpc_id_match);
    jb_set_string(jb, "outcome", txmeta->rpc_response_error ? "error" : "result");
    jb_close(jb);

    jb_close(jb);

    OutputJsonBuilderBuffer(jb, thread);
    jb_free(jb);
    JsonRpcTxDataMarkRpcResultLogged(tx);
    return true;
}

static bool JsonRpcEmitStreamEvent(
        ThreadVars *tv, OutputJsonThreadCtx *thread, const Packet *p, Flow *f, htp_tx_t *tx,
        const JsonRpcTxData *txmeta)
{
    (void)tv;
    (void)f;

    const JsonRpcServiceDef *service = NULL;
    const char *event_type = JsonRpcResolveEventType(txmeta, &service);
    const char *service_name =
            (service != NULL && service->name != NULL) ? service->name : "unknown";

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, event_type, NULL, thread->ctx);
    if (unlikely(jb == NULL)) {
        return false;
    }

    jb_set_string(jb, "event_type", event_type);
    jb_open_object(jb, event_type);
    jb_set_string(jb, "service", service_name);
    jb_set_string(jb, "event", "stream_upgrade");
    jb_set_string(jb, "stage", JsonRpcStageToString(txmeta->stream_stage));
    JsonRpcAppendHttpMetadata(jb, tx, JsonRpcDetermineScheme(tx, service));

    if (txmeta->stream_type[0] != '\0') {
        jb_open_object(jb, "stream");
        jb_set_string(jb, "type", txmeta->stream_type);
        jb_close(jb);
    }

    jb_close(jb);

    OutputJsonBuilderBuffer(jb, thread);
    jb_free(jb);
    JsonRpcTxDataMarkStreamLogged(tx);
    return true;
}

static bool AguiSseEmitEvent(
        ThreadVars *tv, OutputJsonThreadCtx *thread, const Packet *p, Flow *f, htp_tx_t *tx)
{
    (void)tv;
    (void)f;

    const AguiSseTxData *ssemeta = AguiSseGetTxData(tx);
    if (ssemeta == NULL || !ssemeta->response_is_sse || !ssemeta->agui_confirmed ||
            ssemeta->event_logged) {
        return false;
    }

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "agui", NULL, thread->ctx);
    if (unlikely(jb == NULL)) {
        return false;
    }

    jb_set_string(jb, "event_type", "agui");
    jb_open_object(jb, "agui");
    jb_set_string(jb, "event", "sse_stream");
    jb_set_string(jb, "stage", "stream");
    JsonRpcAppendHttpMetadata(jb, tx, "ag-ui");

    jb_open_object(jb, "stream");
    jb_set_int(jb, "event_count", (int64_t)ssemeta->event_count);
    jb_set_int(jb, "bytes", (int64_t)ssemeta->payload_bytes);
    if (ssemeta->last_event_type[0] != '\0') {
        jb_set_string(jb, "last_event_type", ssemeta->last_event_type);
    }
    if (ssemeta->json_parsed > 0 || ssemeta->json_failed > 0) {
        jb_open_object(jb, "json");
        jb_set_int(jb, "parsed", (int64_t)ssemeta->json_parsed);
        jb_set_int(jb, "failed", (int64_t)ssemeta->json_failed);
        jb_close(jb);
    }
    jb_close(jb);

    jb_close(jb);

    OutputJsonBuilderBuffer(jb, thread);
    jb_free(jb);
    AguiSseTxDataMarkLogged(tx);
    return true;
}

static int JsonRpcLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
        void *state, void *txptr, uint64_t tx_id)
{
    (void)state;
    (void)tx_id;

    OutputJsonThreadCtx *thread = thread_data;
    htp_tx_t *tx = txptr;

    const JsonRpcTxData *txmeta = JsonRpcGetTxData(tx);
    if (txmeta != NULL) {
        if (txmeta->agent_card_ready && !txmeta->agent_card_logged) {
            JsonRpcEmitCardEvent(tv, thread, p, f, tx, txmeta);
        }

        if (txmeta->rpc_ready && !txmeta->rpc_logged) {
            JsonRpcEmitRpcEvent(tv, thread, p, f, tx, txmeta);
        }

        if (txmeta->rpc_response_ready && !txmeta->rpc_response_logged) {
            JsonRpcEmitRpcResultEvent(tv, thread, p, f, tx, txmeta);
        }

        if (txmeta->stream_ready && !txmeta->stream_logged) {
            JsonRpcEmitStreamEvent(tv, thread, p, f, tx, txmeta);
        }
    }

    AguiSseEmitEvent(tv, thread, p, f, tx);

    return TM_ECODE_OK;
}

static OutputInitResult JsonRpcEventLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_HTTP1);
    return OutputJsonLogInitSub(conf, parent_ctx);
}

void JsonRpcLogRegister(void)
{
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonRpcEventsLog", "eve-log.jsonrpc",
            JsonRpcEventLogInitSub, ALPROTO_HTTP1, JsonRpcLogger, JsonLogThreadInit,
            JsonLogThreadDeinit, NULL);
}
