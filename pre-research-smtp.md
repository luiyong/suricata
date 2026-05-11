---
title: SMTP协议预研说明书
protocol: SMTP
status: partially-verified
created: 2026-05-11
updated: 2026-05-11
owner: Agent
evidence_level_summary: observed-in-code, inferred
sample_assets: none
---

## 1. 预研概述

### 1.1 背景
当前系统需要深入理解和验证 Suricata 中针对 SMTP 协议的处理能力。SMTP (Simple Mail Transfer Protocol) 协议作为一种常见的应用层协议，通常用于电子邮件传输，工作于 TCP 协议之上。

### 1.2 名词解释
* **SMTP (Simple Mail Transfer Protocol)**: 简单邮件传输协议，用于发送电子邮件。
* **MIME (Multipurpose Internet Mail Extensions)**: 多用途互联网邮件扩展，用于支持非 ASCII 字符文本及多媒体附件。
* **STARTTLS**: SMTP 协议的扩展，通过未加密连接发起请求以升级为加密连接。
* **BDAT**: 块数据传输命令，用于支持大块邮件数据的高效传输。

### 1.3 协议作用说明
SMTP 主要用于在邮件服务器之间发送和中继邮件消息。该协议通常工作在 TCP 端口 25, 587, 或 465（针对 SMTPS）。

## 2. 预研任务说明

### 2.1 功能目标
验证系统支持 SMTP 命令识别、邮件元数据提取、附件/文件解析以及通过 MIME 的内容检查，并且能正确映射为相关的 EVE 日志、事件。

### 2.2 非目标或性能目标
目前阶段不验证多 GB 级别邮件的处理性能，主要聚焦在功能实现的分析与基本状态机解析逻辑。

## 3. 预研过程

### 3.1 协议原理
SMTP 以命令和响应的方式工作，包含初始建立连接、握手（HELO/EHLO）、认证、传输邮件发件人（MAIL FROM）和收件人（RCPT TO）、传输邮件内容数据（DATA/BDAT）和终止连接（QUIT）等阶段。

### 3.2 协议版本与差异
Suricata 代码目前支持基础的 SMTP 命令解析（RFC 5321/2821 等）以及部分扩展如 BDAT (CHUNKING) 等。对于 TLS 加密可以通过 STARTTLS 升级。

### 3.3 协议状态机与交互流程
在 `src/app-layer-smtp.c` 中，Suricata 维护了 SMTP parser 的状态。
主要状态如下（标记为 `observed-in-code`）：
* `SMTP_PARSER_STATE_COMMAND_DATA_MODE` (0x01)
* `SMTP_PARSER_STATE_FIRST_REPLY_SEEN` (0x04)
* `SMTP_PARSER_STATE_PARSING_MULTILINE_REPLY` (0x08)
* `SMTP_PARSER_STATE_PIPELINING_SERVER` (0x10)

支持的重要命令包括：
* `STARTTLS` (1)
* `DATA` (2)
* `BDAT` (3)
* `DATA_MODE` (4)
* `OTHER_CMD` (5)
* `RSET` (6)

### 3.4 关键字段解析规则
* **helo/ehlo**: 提取首次遇到的 HELO/EHLO 命令后的参数，提供到 `smtp.helo` 字段。
* **mail_from**: 从 `MAIL FROM:` 提取发起邮箱。支持包含选项的 RFC 1870 大小扩展，映射为 `smtp.mail_from`。
* **rcpt_to**: 提取 `RCPT TO:` 中接收者的邮箱，可能重复多个，放入 `smtp.rcpt_to` 列表（`observed-in-code`，通过粘性缓冲区和 multi buffer）。
* **MIME 数据**: 支持通过 `rust/src/mime/smtp.rs` 解析 Header（提取 Subject, 转换为 MD5 输出为 `subject_md5`）、Body（支持 `body_md5` 计算）等，并支持解码 Base64/Quoted-Printable 格式，以及文件提取。（`observed-in-code`）。

### 3.5 编码、特殊字符、结束标记、二进制对象或大负载对象处理
在 `suricata.yaml` 配置中：
* `content-limit` (默认 100000)
* `content-inspect-min-size` (32768)
* `content-inspect-window` (4096)
* MIME 边界过长将触发事件 `smtp.mime_long_boundary`。
对于大对象的传输使用 `BDAT` 命令，若长度超过配置（例如 chunk size mismatch）将触发 `BDAT_CHUNK_LEN_EXCEEDED` 异常 (`observed-in-code`)。

### 3.6 加密、封装或升级切换机制
* 若接收到 `STARTTLS` 的协商并失败或者拒绝，可能触发 `tls_rejected` 等事件。升级为 TLS 之后，SMTP 的纯文本解析将挂起或转交到 TLS 相关的检索引擎中。

### 3.7 主流客户端/服务端兼容性验证
`待验证`。当前没有具体 PCAP 和真实环境的数据做全面回归。

### 3.8 当前代码/上游代码现状与源码路径分析
当前代码已具备高度集成的 SMTP 支持：
* 状态机： `src/app-layer-smtp.c`, `src/app-layer-smtp.h`
* 协议检测与日志： `src/detect-smtp.c`, `src/output-json-smtp.c`
* Rust MIME 解析： `rust/src/mime/smtp.rs`, `rust/src/mime/smtp_log.rs`
* 报警事件支持： `rules/smtp-events.rules`

### 3.9 原始报文、解析结果、日志结果映射
* **报文输入**： `EHLO localhost\r\n`
* **解析**： `SMTPParseCommandHELO` 获取内容为 `localhost`
* **日志输出**： 映射到 Eve log 的 `smtp.helo`。
（`inferred` / `observed-in-code`）

## 4. 测试与验证

### 4.1 测试矩阵
必须覆盖以下方面（`待验证`）：
1. 正常交互（EHLO -> MAIL FROM -> RCPT TO -> DATA -> QUIT）
2. 协议错误或非法输入（如：错误的返回码对应，触发 `invalid_reply`）
3. 缺字段/空字段/重复字段（触发 `duplicate_fields` 等）
4. 多值字段（多次 `RCPT TO`）
5. 大对象/大报文/大文件（超长 MIME 行、超长边界：`mime_long_line`, `mime_long_boundary`）
6. 加密与升级加密（`STARTTLS` 被拒绝时触发 `tls_rejected`）

### 4.2 已验证样本与待补样本
* **已验证**：无，当前依赖源码分析。
* **待补样本**：包含基础纯文本通信样本、STARTTLS 加密通信样本、带巨型 BDAT 附件样本、存在非标准 MIME 编码方式的样本。

### 4.3 pcap/样本资产清单
* 尚未收集

### 4.4 性能与容量验证
`待验证`。相关配置支持 `max-tx` （限制多事务的内存占用），默认为 256。

## 5. 预研结果

### 5.1 当前支持能力
系统通过 C 和 Rust 混合架构具备全面和深度的 SMTP 应用层解析能力，可解析常见命令，提取邮件元信息（发件人、收件人、主题），验证 MD5 校验和，从 MIME 层提取附件等。此外还支持大量的异常事件触发供防御规则使用。

### 5.2 缺失能力
对于加密前和解密后的流量映射管理，仅从源码分析来看需配合 TLS parser 使用。部分特殊的 MIME 编码如果超出规范可能导致直接丢弃或中断。

### 5.3 风险与边界
* 内存耗尽风险：长连接、海量小事务（可通过 `max-tx` 缓解）以及巨量垃圾文件传输。
* 状态机去同步：如果出现非标准流水线命令或多路混叠（Pipelined Sequence），可能会导致命令与回应不匹配。

### 5.4 建议实现路径
针对新特性的增加，建议在 `src/app-layer-smtp.c` 扩展特定命令，并在 `src/output-json-smtp.c` 丰富相应 EVE 记录字段；对于复杂业务拆包建议在 `rust/src/mime/smtp.rs` 下操作。

## 6. 结论与建议

### 6.1 是否建议立项
* 目前 Suricata 中已有成熟方案支持 SMTP。如果在该基础上做增强或特定字段的抽取，可直接基于现有基础立项。（`verified`）

### 6.2 建议范围
* 优化现有 Rust 解析器以增强大文件流式解包处理，补充缺少边界测试的用例集。

### 6.3 后续 design / plan / implement 的输入清单
* `src/app-layer-smtp.c` 的状态机图表。
* 新的邮件测试 Pcap 样本集收集规范与覆盖率要求。
* 基于 EVE json 新字段的 schema 变更提案。
