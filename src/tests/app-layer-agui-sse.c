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
            "data: {\"type\":\"text-message-start\",\"message_id\":\"123\"}\n\n"
            "data: {\"type\":\"run_finished\",\"run_id\":\"abc\"}\n\n";

    uint32_t count = 0;
    char last_type[32];

    FAIL_IF(!AguiSseTestParseSample(payload, &count, last_type, sizeof(last_type)));
    FAIL_IF(count != 2);
    FAIL_IF(strcmp(last_type, "run_finished") != 0);
    PASS;
}

void AppLayerAguiSseRegisterTests(void)
{
    UtRegisterTest("AguiSseParseSampleTest", AguiSseParseSampleTest);
}
