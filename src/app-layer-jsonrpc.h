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

#ifndef __APP_LAYER_JSONRPC_H__
#define __APP_LAYER_JSONRPC_H__

#include "flow.h"
#include "util-file.h"

struct htp_tx_t;

typedef enum JsonRpcStage_ {
    JSONRPC_STAGE_NONE = 0,
    JSONRPC_STAGE_DISCOVERY,
    JSONRPC_STAGE_INIT,
    JSONRPC_STAGE_RPC,
    JSONRPC_STAGE_STREAM,
} JsonRpcStage;

typedef enum JsonRpcServiceId_ {
    JSONRPC_SERVICE_UNKNOWN = 0,
    JSONRPC_SERVICE_A2A = 1,
    JSONRPC_SERVICE_MCP = 2,
    JSONRPC_SERVICE_MAX = 32,
} JsonRpcServiceId;

struct JsonRpcTxData_;

typedef bool (*JsonRpcMethodMatchFn)(const char *method);
typedef bool (*JsonRpcAgentCardValidatorFn)(
        const uint8_t *body, uint32_t len, struct JsonRpcTxData_ *txmeta);

typedef struct JsonRpcServiceDef_ {
    uint8_t id;
    const char *name;
    const char *event_type;
    const char *const *discovery_paths;
    size_t discovery_path_cnt;
    JsonRpcMethodMatchFn method_match;
    JsonRpcMethodMatchFn method_is_init;
    JsonRpcMethodMatchFn method_is_stream;
    JsonRpcAgentCardValidatorFn card_validator;
    bool supports_stream;
} JsonRpcServiceDef;

typedef struct JsonRpcHttpHints_ {
    bool path_contains_mcp;
    bool has_mcp_session_id;
    bool has_mcp_protocol_version;
    bool content_type_is_json;
    bool accept_event_stream;
} JsonRpcHttpHints;

typedef struct JsonRpcFlowState_ {
    uint8_t service_id;
    uint8_t stage;
    bool host_cached;
    bool flow_accounted;
    SCTime_t last_seen;
} JsonRpcFlowState;

typedef struct JsonRpcTxData_ {
    uint8_t service_id;
    bool agent_card_request;
    bool agent_card_ready;
    bool agent_card_logged;
    bool agent_card_valid;
    char card_hash_hex[(SC_SHA256_LEN * 2) + 1];
    uint32_t card_size;

    bool rpc_request;
    bool rpc_ready;
    bool rpc_logged;
    bool rpc_is_init;
    JsonRpcStage rpc_stage;
    char rpc_method[64];
    char rpc_id[40];
    uint32_t rpc_size;
    uint32_t rpc_params_len;

    bool rpc_response;
    bool rpc_response_ready;
    bool rpc_response_logged;
    bool rpc_response_error;
    bool rpc_id_match;
    uint32_t rpc_result_size;

    bool stream_upgrade;
    bool stream_ready;
    bool stream_logged;
    JsonRpcStage stream_stage;
    char stream_type[16];

    JsonRpcHttpHints http;
} JsonRpcTxData;

void JsonRpcInit(void);
void JsonRpcServiceRegister(const JsonRpcServiceDef *def);
void JsonRpcOnHttpRequestComplete(Flow *f, struct htp_tx_t *tx);
void JsonRpcOnHttpResponseComplete(Flow *f, struct htp_tx_t *tx);
JsonRpcFlowState *JsonRpcFlowStateGet(Flow *f);
const JsonRpcTxData *JsonRpcGetTxData(const struct htp_tx_t *tx);
void JsonRpcTxDataMarkCardLogged(struct htp_tx_t *tx);
void JsonRpcTxDataMarkRpcLogged(struct htp_tx_t *tx);
void JsonRpcTxDataMarkRpcResultLogged(struct htp_tx_t *tx);
void JsonRpcTxDataMarkStreamLogged(struct htp_tx_t *tx);
const JsonRpcServiceDef *JsonRpcServiceLookup(uint8_t service_id);
const char *JsonRpcStageToString(JsonRpcStage stage);

#ifdef UNITTESTS
typedef struct JsonRpcTestMessage_ {
    bool has_jsonrpc;
    bool has_method;
    char method[64];
    bool has_id;
    char id[40];
    bool has_params;
    uint32_t params_len;
    bool has_result;
    bool has_error;
} JsonRpcTestMessage;

bool JsonRpcTestParseMessage(const char *json, JsonRpcTestMessage *msg);
bool JsonRpcTestMethodLooksLikeA2A(const char *method);
bool JsonRpcTestMethodIsInit(const char *method);
bool JsonRpcTestMethodIsStreamA2A(const char *method);
bool JsonRpcTestMethodLooksLikeMcp(const char *method);
bool JsonRpcTestMethodIsInitMcp(const char *method);
JsonRpcServiceId JsonRpcTestDiscoveryLookup(const char *path);
bool JsonRpcTestValidateAgentCard(const char *json);
bool JsonRpcTestValidateMcpManifest(const char *json);
bool JsonRpcTestMcpHttpHintsEvaluate(
        bool cached_service, bool path_contains_mcp, bool has_mcp_header, bool content_type_json);
void AppLayerJsonRpcRegisterTests(void);
#endif

#endif /* __APP_LAYER_JSONRPC_H__ */
