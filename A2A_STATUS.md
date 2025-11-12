# JSON-RPC/A2A 集成进展

## 已完成

1. **JSON-RPC 基础管线**
   - `src/app-layer-jsonrpc*.c/h` 构建了 Flow/Tx 状态、阶段统计、Agent Card 验证等通用逻辑，可识别 A2A、MCP 并输出 `event_type`.
2. **HTTP 解析与检测联动**
   - `src/app-layer-htp.{c,h}` 注册 JSON-RPC 钩子并生成 `HTTP_DECODER_EVENT_A2A_*`，`src/detect-app-layer-event.c` 可用 `app-layer-event` 匹配阶段/异常。
3. **EVE 输出与配置**
   - `src/output-json-ai.{c,h}` + `src/output.c` 添加 `jsonrpc` 日志类型，`suricata.yaml(.in)` 默认启用 `eve-log.types: jsonrpc` 及 `app-layer.protocols.ai-{a2a,mcp}` / `app-layer.protocols.ag-ui-sse`。
4. **单元测试**
   - `src/tests/app-layer-jsonrpc.c` 覆盖 A2A/MCP/AG-UI 方法分类、流式判定与（临时）发现路径，确保 CI 可检测解析回归。
5. **A2A 方法匹配收紧**
   - `src/app-layer-jsonrpc-a2a.c` 改用 a2a-python 规范的白名单 + 阶段描述，`src/tests/app-layer-jsonrpc.c` 增加合法/非法示例，避免与普通 JSON-RPC/MCP 混淆。
6. **MCP HTTP 线索集成**
   - `src/app-layer-jsonrpc.c` 捕获请求路径/头部，只有在命中 `mcp-session-id`/`mcp-protocol-version`、`/mcp` 路径或 SSE 受理等线索时才会进入 MCP 方法判定。`src/tests/app-layer-jsonrpc.c` 新增 HTTP 线索单测验证 Heuristic，确保不依赖虚构的发现端点。
7. **AG-UI SSE 独立解析**
   - `src/app-layer-agui-sse.{c,h}` + `src/output-json-ai.c` 新增 SSE 解析/日志通路，`app-layer-jsonrpc-agui.c` 被移除，`suricata.yaml(.in)` 改为 `app-layer.protocols.ag-ui-sse`。HTTP 响应中 `text/event-stream` 的事件会按计数/最近类型输出 `event_type: agui`。

## 后续任务

1. **MCP HTTP 线索可配置化**
   - 当前 heuristics 固定于 `mcp-session-id`/`mcp-protocol-version` 以及 `/mcp` 路径，需要在 `suricata.yaml(.in)` 提供自定义 header/path/content-type 白名单，以适配不同实现。
   - `src/app-layer-jsonrpc.c` 新增配置解析逻辑，`src/tests/app-layer-jsonrpc.c` 补充覆盖，确保配置化线索可控。
2. **AG-UI SSE 事件细化**
   - 当前日志仅输出事件计数 / 最近类型，需要深入解析 `data:` JSON（Run/ToolCall/State 事件）并将关键信息写入 EVE，以便告警/检测器使用。
   - 补充针对畸形 SSE 的鲁棒性（超长事件、截断等）及更多单测样本。
3. **AG-UI Proto 流支持**
   - Python/TS SDK 均允许 `Accept: application/vnd.ag-ui.event+proto` 并以 length-prefixed Proto 帧承载事件；目前 `src/app-layer-agui-sse.c` 仅识别 JSON SSE，既不会检测此类流，也不会输出日志。
   - 需要扩展请求/响应判定、解析管线与 EVE 输出，至少记录 Proto 流是否出现以及事件计数，长期应解码 Proto 事件类型。

> 注：以上事项同步到此文件，方便后续迭代追踪。
