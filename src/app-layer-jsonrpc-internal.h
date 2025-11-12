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

#ifndef __APP_LAYER_JSONRPC_INTERNAL_H__
#define __APP_LAYER_JSONRPC_INTERNAL_H__

#include "app-layer-jsonrpc.h"

const uint8_t *JsonRpcMemmem(
        const uint8_t *haystack, size_t haystack_len, const char *needle);

bool JsonRpcDefaultAgentCardValidator(
        const uint8_t *body, uint32_t len, JsonRpcTxData *txmeta);

void JsonRpcRegisterA2AService(void);
void JsonRpcRegisterMcpService(void);
void JsonRpcRegisterGlobalCounters(void);

#endif /* __APP_LAYER_JSONRPC_INTERNAL_H__ */
