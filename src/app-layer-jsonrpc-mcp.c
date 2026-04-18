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

static bool JsonRpcMethodLooksLikeMcp(const char *method)
{
    if (method == NULL || method[0] == '\0') {
        return false;
    }

    static const char *const prefixes[] = {
        "capabilities/",
        "resources/",
        "prompts/",
        "tools/",
        "sampling/",
        "completion/",
        "logging/",
        "roots/",
        "elicitation/",
        "notifications/",
        "session/",
        "handshake/",
        "mcp/",
        NULL,
    };

    for (size_t i = 0; prefixes[i] != NULL; i++) {
        size_t prefix_len = strlen(prefixes[i]);
        if (strncmp(method, prefixes[i], prefix_len) == 0) {
            return true;
        }
    }

    if (strcmp(method, "initialize") == 0 || strcmp(method, "ping") == 0) {
        return true;
    }

    return false;
}

static bool JsonRpcMethodIsInitMcp(const char *method)
{
    if (method == NULL) {
        return false;
    }

    static const char *const init_methods[] = {
        "initialize",
        "capabilities/",
        "resources/list",
        "prompts/list",
        "tools/list",
        "session/create",
        "handshake/",
        "roots/list",
        NULL,
    };

    for (size_t i = 0; init_methods[i] != NULL; i++) {
        size_t prefix_len = strlen(init_methods[i]);
        if (strncmp(method, init_methods[i], prefix_len) == 0) {
            return true;
        }
    }
    return false;
}

static bool JsonRpcMcpManifestLooksValid(const uint8_t *body, uint32_t len, JsonRpcTxData *txmeta)
{
    (void)txmeta;

    if (body == NULL || len == 0) {
        return false;
    }

    const bool has_version = (JsonRpcMemmem(body, len, "\"mcp_version\"") != NULL) ||
                             (JsonRpcMemmem(body, len, "\"mcpVersion\"") != NULL);
    const bool has_capabilities = (JsonRpcMemmem(body, len, "\"capabilities\"") != NULL);
    const bool has_tools = (JsonRpcMemmem(body, len, "\"tools\"") != NULL);
    const bool has_resources = (JsonRpcMemmem(body, len, "\"resources\"") != NULL);

    return has_version && (has_capabilities || has_tools || has_resources);
}

void JsonRpcRegisterMcpService(void)
{
    static const JsonRpcServiceDef mcp_def = {
        .id = JSONRPC_SERVICE_MCP,
        .name = "mcp",
        .event_type = "mcp",
        .discovery_paths = NULL,
        .discovery_path_cnt = 0,
        .method_match = JsonRpcMethodLooksLikeMcp,
        .method_is_init = JsonRpcMethodIsInitMcp,
        .card_validator = JsonRpcMcpManifestLooksValid,
        .supports_stream = true,
    };

    JsonRpcServiceRegister(&mcp_def);
}

#ifdef UNITTESTS

bool JsonRpcTestMethodLooksLikeMcp(const char *method)
{
    return JsonRpcMethodLooksLikeMcp(method);
}

bool JsonRpcTestMethodIsInitMcp(const char *method)
{
    return JsonRpcMethodIsInitMcp(method);
}

bool JsonRpcTestValidateMcpManifest(const char *json)
{
    if (json == NULL) {
        return false;
    }
    return JsonRpcMcpManifestLooksValid((const uint8_t *)json, (uint32_t)strlen(json), NULL);
}

#endif /* UNITTESTS */
