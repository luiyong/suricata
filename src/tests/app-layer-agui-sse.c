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

#include <string.h>

#include "../app-layer-agui-sse.h"
#include "../util-unittest.h"

static int AguiSseParseSampleTest(void)
{
    static const char payload[] =
            "data: {\"type\":\"TEXT_MESSAGE_START\",\"message_id\":\"123\"}\n\n"
            "data: {\"type\":\"RUN_FINISHED\",\"run_id\":\"abc\"}\n\n";

    uint32_t count = 0;
    char last_type[32];

    FAIL_IF(!AguiSseTestParseSample(payload, &count, last_type, sizeof(last_type)));
    FAIL_IF(count != 2);
    FAIL_IF(strcmp(last_type, "RUN_FINISHED") != 0);
    PASS;
}

static int AguiSseRunAgentInputPositiveTest(void)
{
    static const char body[] =
            "{"
            "\"threadId\":\"thread-123\","
            "\"runId\":\"run-456\","
            "\"messages\":["
            "  {\"id\":\"m1\",\"role\":\"user\",\"content\":\"hello\"},"
            "  {\"id\":\"m2\",\"role\":\"assistant\",\"content\":\"hi\"}"
            "]"
            "}";

    FAIL_IF(!AguiSseTestBodyLooksLikeRunAgentInput(body));
    PASS;
}

static int AguiSseRunAgentInputNegativeTest(void)
{
    static const char body[] =
            "{"
            "\"method\":\"a2a.stream\","
            "\"params\":{\"conversation_id\":\"conv\",\"messages\":[{\"role\":\"user\"}]}"
            "}";

    FAIL_IF(AguiSseTestBodyLooksLikeRunAgentInput(body));
    PASS;
}

static int AguiSseMultipartParseTest(void)
{
    static const char boundary[] = "copilotkit-boundary";
    static const char body[] =
            "--copilotkit-boundary\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            "{\"incremental\":[{\"items\":[{\"type\":\"TEXT_MESSAGE_START\"}]}]}\r\n"
            "\r\n"
            "--copilotkit-boundary\r\n"
            "Content-Type: application/json\r\n"
            "\r\n"
            "{\"incremental\":[{\"items\":[{\"type\":\"RUN_FINISHED\"}]}]}\r\n"
            "\r\n"
            "--copilotkit-boundary--\r\n";

    uint32_t count = 0;
    char last_type[32];

    FAIL_IF(!AguiSseTestParseMultipartSample(boundary, body, &count, last_type, sizeof(last_type)));
    FAIL_IF(count != 2);
    FAIL_IF(strcmp(last_type, "RUN_FINISHED") != 0);
    PASS;
}

void AppLayerAguiSseRegisterTests(void)
{
    UtRegisterTest("AguiSseParseSampleTest", AguiSseParseSampleTest);
    UtRegisterTest("AguiSseRunAgentInputPositiveTest", AguiSseRunAgentInputPositiveTest);
    UtRegisterTest("AguiSseRunAgentInputNegativeTest", AguiSseRunAgentInputNegativeTest);
    UtRegisterTest("AguiSseMultipartParseTest", AguiSseMultipartParseTest);
}
