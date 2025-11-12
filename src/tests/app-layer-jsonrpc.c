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

#include "../app-layer-jsonrpc.h"
#include "../util-unittest.h"

static int JsonRpcParseMessageTest01(void)
{
    static const char json[] =
            "{\"jsonrpc\":\"2.0\",\"method\":\"workflow/init\",\"id\":\"abc123\"}";

    JsonRpcTestMessage msg;
    FAIL_IF_NOT(JsonRpcTestParseMessage(json, &msg));
    FAIL_IF_NOT(msg.has_jsonrpc);
    FAIL_IF_NOT(msg.has_method);
    FAIL_IF_NOT(msg.has_id);
    FAIL_IF(strcmp(msg.method, "workflow/init") != 0);
    FAIL_IF(strcmp(msg.id, "abc123") != 0);
    PASS;
}

static int JsonRpcParseMessageTest02(void)
{
    static const char json[] = "{\"jsonrpc\":\"1.0\",\"method\":\"message/send\"}";

    JsonRpcTestMessage msg;
    FAIL_IF(JsonRpcTestParseMessage(json, &msg));
    PASS;
}

static int JsonRpcParseMessageTest03(void)
{
    static const char json[] =
            "{\"jsonrpc\":\"2.0\",\"method\":\"message/send\",\"params\":{\"foo\":1,\"bar\":2}}";

    JsonRpcTestMessage msg;
    FAIL_IF_NOT(JsonRpcTestParseMessage(json, &msg));
    FAIL_IF_NOT(msg.has_params);
    FAIL_IF(msg.params_len == 0);
    PASS;
}

static int JsonRpcParseResponseTest01(void)
{
    static const char json[] =
            "{\"jsonrpc\":\"2.0\",\"id\":42,\"result\":{\"status\":\"ok\",\"items\":[1,2]}}";

    JsonRpcTestMessage msg;
    FAIL_IF_NOT(JsonRpcTestParseMessage(json, &msg));
    FAIL_IF(msg.has_method);
    FAIL_IF_NOT(msg.has_id);
    FAIL_IF_NOT(msg.has_result);
    PASS;
}

static int JsonRpcA2AMethodClassificationTest(void)
{
    FAIL_IF_NOT(JsonRpcTestMethodLooksLikeA2A("message/send"));
    FAIL_IF(JsonRpcTestMethodLooksLikeA2A("heartbeat"));
    FAIL_IF_NOT(JsonRpcTestMethodIsInit("agent/getAuthenticatedExtendedCard"));
    FAIL_IF_NOT(JsonRpcTestMethodIsInit("agent/authenticatedExtendedCard"));
    FAIL_IF(JsonRpcTestMethodIsInit("message/send"));
    FAIL_IF_NOT(JsonRpcTestMethodLooksLikeA2A("message/stream"));
    FAIL_IF_NOT(JsonRpcTestMethodLooksLikeA2A("tasks/get"));
    FAIL_IF(JsonRpcTestMethodLooksLikeA2A("tasks/list"));
    FAIL_IF(JsonRpcTestMethodLooksLikeA2A("workflow/init"));
    FAIL_IF(JsonRpcTestMethodLooksLikeMcp("tasks/get"));
    PASS;
}

static int JsonRpcA2AStreamingMethodTest(void)
{
    FAIL_IF_NOT(JsonRpcTestMethodIsStreamA2A("message/stream"));
    FAIL_IF_NOT(JsonRpcTestMethodIsStreamA2A("tasks/resubscribe"));
    FAIL_IF(JsonRpcTestMethodIsStreamA2A("message/send"));
    FAIL_IF(JsonRpcTestMethodIsStreamA2A("events/subscribe"));
    PASS;
}

static int JsonRpcMcpMethodClassificationTest(void)
{
    FAIL_IF_NOT(JsonRpcTestMethodLooksLikeMcp("capabilities/list"));
    FAIL_IF_NOT(JsonRpcTestMethodLooksLikeMcp("resources/read"));
    FAIL_IF_NOT(JsonRpcTestMethodLooksLikeMcp("completion/complete"));
    FAIL_IF_NOT(JsonRpcTestMethodLooksLikeMcp("logging/setLevel"));
    FAIL_IF_NOT(JsonRpcTestMethodLooksLikeMcp("roots/list"));
    FAIL_IF_NOT(JsonRpcTestMethodLooksLikeMcp("elicitation/create"));
    FAIL_IF_NOT(JsonRpcTestMethodLooksLikeMcp("tools/list"));
    FAIL_IF_NOT(JsonRpcTestMethodLooksLikeMcp("session/create"));
    FAIL_IF_NOT(JsonRpcTestMethodIsInitMcp("resources/list"));
    FAIL_IF_NOT(JsonRpcTestMethodIsInitMcp("roots/list"));
    FAIL_IF(JsonRpcTestMethodIsInitMcp("tools/call"));
    FAIL_IF(JsonRpcTestMethodLooksLikeA2A("capabilities/list"));
    PASS;
}

static int JsonRpcDiscoveryPathMatchTest(void)
{
    FAIL_IF_NOT(JsonRpcTestDiscoveryLookup("/.well-known/agent.json") == JSONRPC_SERVICE_A2A);
    FAIL_IF_NOT(JsonRpcTestDiscoveryLookup("/.well-known/agent-card.json") == JSONRPC_SERVICE_A2A);
    FAIL_IF_NOT(JsonRpcTestDiscoveryLookup("/unknown") == JSONRPC_SERVICE_UNKNOWN);
    FAIL_IF_NOT(JsonRpcTestDiscoveryLookup("/.well-known/mcp.json") == JSONRPC_SERVICE_UNKNOWN);
    PASS;
}

static int JsonRpcAgentCardValidatorTest(void)
{
    static const char valid_card[] =
            "{\"name\":\"WeatherAgent\",\"version\":\"1.0\",\"capabilities\":[{\"endpoint\""
            ":\"/api\"}],\"description\":\"demo\",\"authentication\":{\"schemes\":[\"bearer\"]}}";
    static const char invalid_card[] =
            "{\"version\":\"1.0\",\"capabilities\":[],\"description\":\"missing name\"}";

    FAIL_IF_NOT(JsonRpcTestValidateAgentCard(valid_card));
    FAIL_IF(JsonRpcTestValidateAgentCard(invalid_card));
    PASS;
}

static int JsonRpcMcpManifestValidatorTest(void)
{
    static const char valid_manifest[] =
            "{\"mcp_version\":\"1.1\",\"capabilities\":{\"tools\":{\"call\":true}},"
            "\"tools\":[{\"name\":\"run\"}],\"resources\":[{\"name\":\"logs\"}]}";
    static const char invalid_manifest[] =
            "{\"name\":\"not-mcp\",\"description\":\"missing version\"}";

    FAIL_IF_NOT(JsonRpcTestValidateMcpManifest(valid_manifest));
    FAIL_IF(JsonRpcTestValidateMcpManifest(invalid_manifest));
    PASS;
}

static int JsonRpcMcpHttpHintsTest(void)
{
    FAIL_IF_NOT(JsonRpcTestMcpHttpHintsEvaluate(true, false, false, false));
    FAIL_IF_NOT(JsonRpcTestMcpHttpHintsEvaluate(false, true, false, true));
    FAIL_IF_NOT(JsonRpcTestMcpHttpHintsEvaluate(false, false, true, false));
    FAIL_IF(JsonRpcTestMcpHttpHintsEvaluate(false, false, false, true));
    PASS;
}

void AppLayerJsonRpcRegisterTests(void)
{
    UtRegisterTest("JsonRpcParseMessageTest01", JsonRpcParseMessageTest01);
    UtRegisterTest("JsonRpcParseMessageTest02", JsonRpcParseMessageTest02);
    UtRegisterTest("JsonRpcParseMessageTest03", JsonRpcParseMessageTest03);
    UtRegisterTest("JsonRpcParseResponseTest01", JsonRpcParseResponseTest01);
    UtRegisterTest("JsonRpcA2AMethodClassificationTest", JsonRpcA2AMethodClassificationTest);
    UtRegisterTest("JsonRpcA2AStreamingMethodTest", JsonRpcA2AStreamingMethodTest);
    UtRegisterTest("JsonRpcMcpMethodClassificationTest", JsonRpcMcpMethodClassificationTest);
    UtRegisterTest("JsonRpcDiscoveryPathMatchTest", JsonRpcDiscoveryPathMatchTest);
    UtRegisterTest("JsonRpcAgentCardValidatorTest", JsonRpcAgentCardValidatorTest);
    UtRegisterTest("JsonRpcMcpManifestValidatorTest", JsonRpcMcpManifestValidatorTest);
    UtRegisterTest("JsonRpcMcpHttpHintsTest", JsonRpcMcpHttpHintsTest);
}
