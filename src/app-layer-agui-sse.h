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

#ifndef __APP_LAYER_AGUI_SSE_H__
#define __APP_LAYER_AGUI_SSE_H__

#include "suricata-common.h"
#include "flow.h"

struct htp_tx_t;

typedef struct AguiSseTxData_ {
    bool request_wants_sse;
    bool request_accepts_proto;
    bool request_content_type_json;
    bool request_has_run_input;
    bool response_is_sse;
    bool response_is_proto;
    bool response_has_valid_events;
    bool event_logged;
    bool agui_confirmed;
    bool scheme_applied;
    uint32_t event_count;
    uint32_t json_parsed;
    uint32_t json_failed;
    uint32_t payload_bytes;
    char last_event_type[32];
} AguiSseTxData;

void AguiSseInit(void);
void AguiSseOnHttpRequestComplete(Flow *f, struct htp_tx_t *tx);
void AguiSseOnHttpResponseComplete(Flow *f, struct htp_tx_t *tx);
const AguiSseTxData *AguiSseGetTxData(const struct htp_tx_t *tx);
void AguiSseTxDataMarkLogged(struct htp_tx_t *tx);

#ifdef UNITTESTS
void AppLayerAguiSseRegisterTests(void);
bool AguiSseTestParseSample(
        const char *payload, uint32_t *out_count, char *last_type, size_t last_type_len);
bool AguiSseTestBodyLooksLikeRunAgentInput(const char *body);
#endif

#endif /* __APP_LAYER_AGUI_SSE_H__ */
