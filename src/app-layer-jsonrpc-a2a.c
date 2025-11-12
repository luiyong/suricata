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
#include "app-layer-jsonrpc-internal.h"

#include <string.h>
#include <strings.h>

typedef struct JsonRpcA2AMethodDef_ {
    const char *name;
    bool is_init;
    bool is_stream;
} JsonRpcA2AMethodDef;

static const JsonRpcA2AMethodDef jsonrpc_a2a_methods[] = {
    { "agent/getAuthenticatedExtendedCard", true, false },
    { "agent/authenticatedExtendedCard", true, false },
    { "message/send", false, false },
    { "message/stream", false, true },
    { "tasks/get", false, false },
    { "tasks/cancel", false, false },
    { "tasks/resubscribe", false, true },
    { "tasks/pushNotificationConfig/set", false, false },
    { "tasks/pushNotificationConfig/get", false, false },
    { "tasks/pushNotificationConfig/list", false, false },
    { "tasks/pushNotificationConfig/delete", false, false },
};

static const JsonRpcA2AMethodDef *JsonRpcLookupA2AMethod(const char *method)
{
    if (method == NULL || method[0] == '\0') {
        return NULL;
    }

    for (size_t i = 0; i < ARRAY_SIZE(jsonrpc_a2a_methods); i++) {
        if (strcmp(method, jsonrpc_a2a_methods[i].name) == 0) {
            return &jsonrpc_a2a_methods[i];
        }
    }
    return NULL;
}

static bool JsonRpcMethodLooksLikeA2A(const char *method)
{
    return (JsonRpcLookupA2AMethod(method) != NULL);
}

static bool JsonRpcMethodIsInitA2A(const char *method)
{
    const JsonRpcA2AMethodDef *def = JsonRpcLookupA2AMethod(method);
    return (def != NULL && def->is_init);
}

static bool JsonRpcMethodIsStreamA2A(const char *method)
{
    const JsonRpcA2AMethodDef *def = JsonRpcLookupA2AMethod(method);
    return (def != NULL && def->is_stream);
}

bool JsonRpcDefaultAgentCardValidator(
        const uint8_t *body, uint32_t len, JsonRpcTxData *txmeta)
{
    (void)txmeta;

    if (body == NULL || len == 0) {
        return false;
    }

    const bool has_name = (JsonRpcMemmem(body, len, "\"name\"") != NULL);
    const bool has_version = (JsonRpcMemmem(body, len, "\"version\"") != NULL);
    const bool has_capabilities = (JsonRpcMemmem(body, len, "\"capabilities\"") != NULL);
    const bool has_url = (JsonRpcMemmem(body, len, "\"url\"") != NULL);
    const bool has_description = (JsonRpcMemmem(body, len, "\"description\"") != NULL);
    const bool has_auth = (JsonRpcMemmem(body, len, "\"authentication\"") != NULL);

    if (!has_name || !has_version || !has_capabilities) {
        return false;
    }

    size_t aux_hits = 0;
    if (has_url) {
        aux_hits++;
    }
    if (has_description) {
        aux_hits++;
    }
    if (has_auth) {
        aux_hits++;
    }

    return (aux_hits > 0);
}

void JsonRpcRegisterA2AService(void)
{
    static const char *const a2a_paths[] = {
        "/.well-known/agent.json",
        "/.well-known/agent-card.json",
        "/agent/authenticatedExtendedCard",
    };
    static const JsonRpcServiceDef a2a_def = {
        .id = JSONRPC_SERVICE_A2A,
        .name = "a2a",
        .event_type = "a2a",
        .discovery_paths = a2a_paths,
        .discovery_path_cnt = ARRAY_SIZE(a2a_paths),
        .method_match = JsonRpcMethodLooksLikeA2A,
        .method_is_init = JsonRpcMethodIsInitA2A,
        .method_is_stream = JsonRpcMethodIsStreamA2A,
        .card_validator = JsonRpcDefaultAgentCardValidator,
        .supports_stream = true,
    };

    JsonRpcServiceRegister(&a2a_def);
}

#ifdef UNITTESTS

bool JsonRpcTestMethodLooksLikeA2A(const char *method)
{
    return JsonRpcMethodLooksLikeA2A(method);
}

bool JsonRpcTestMethodIsInit(const char *method)
{
    return JsonRpcMethodIsInitA2A(method);
}

bool JsonRpcTestMethodIsStreamA2A(const char *method)
{
    return JsonRpcMethodIsStreamA2A(method);
}

bool JsonRpcTestValidateAgentCard(const char *json)
{
    if (json == NULL) {
        return false;
    }
    return JsonRpcDefaultAgentCardValidator(
            (const uint8_t *)json, (uint32_t)strlen(json), NULL);
}

#endif /* UNITTESTS */
