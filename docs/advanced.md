# SecLaw 进阶文档

本文档包含 SecLaw 的内部工作原理和技术细节。如果你只需要安装和使用 SecLaw，请参阅 [README](../README.md)。

## 审计流程

```
用户消息
  |
  +- 意图追踪（before_prompt_build 钩子）
  |   └─ 提取用户目标、发送者标签、消息来源
  |
  +- Override 检测（trustedSenderLabels）
  |   └─ 受信任发送者发 /pin<PIN> -> 激活覆盖
  |
工具调用 (before_tool_call, 优先级 9999)
  |
  +- 1. 检查活跃 Override（本轮内同一工具名）
  |     └─ 有 -> 立即放行，跳过所有审计
  |
  +- 2. 检查异步审计的危险标记
  |     └─ 有 -> 阻断 + 生成 Override PIN
  |
  └─ 3. 规则引擎分类 -> GREEN / YELLOW / RED
        |
        +- GREEN -> 放行（静默）
        |
        +- YELLOW -> 放行
        |     └─ 工具执行后 -> 入队异步审计
        |         └─ DANGER -> 设置危险标记（阻断下一次调用）
        |
        └─ RED -> 同步 LLM 审计
              +- SAFE -> 放行
              └─ DANGER -> 阻断 + Override PIN + 按钮
```

## 意图上下文

SecLaw 持续追踪 Agent 的行为意图，为 LLM 审计提供上下文。每次审计时收集以下数据：

```typescript
interface IntentContext {
  userGoal: string;           // 用户最近一条消息（去除元数据后的原始指令）
  senderLabel?: string;       // 发送者标签（如 "openclaw-control-ui"）
  channelId?: string;         // 消息渠道（telegram、discord、whatsapp 等）
  trigger?: string;           // 触发方式（user、heartbeat、cron、memory）
  agentId?: string;           // Agent 标识
  messageProvider?: string;   // 消息提供者
  stepIndex: number;          // 当前轮次内的工具调用计数
  turnNumber: number;         // 用户消息轮次计数
  recentToolCalls: Array<{    // 最近 N 次工具调用历史（默认 3 次）
    toolName: string;
    params: Record<string, unknown>;
    outcome: "success" | "error" | "blocked";
  }>;
}
```

这些上下文被格式化后注入 LLM 审计提示词。对于受信任发送者，审计从"意图对齐"角度判断操作是否符合用户目标；对于非受信任发送者，审计从安全视角出发，关注数据泄露、凭据窃取、未授权访问等风险。

信任判定在 LLM 调用**之前**完成（基于 `senderLabel` 是否在 `trustedSenderLabels` 列表中）。

## 规则引擎

规则定义在 YAML 文件中，按优先级从高到低排序，第一个匹配的规则生效：

- **默认规则**（`rules/default.yaml`）：28+ 条内置规则
- **平台规则**：`rules/unix.yaml`（Linux/macOS）、`rules/windows.yaml`（Windows），按 `os.platform()` 自动加载
- **自定义规则**：`.openclaw/seclaw-rules.yaml` 或通过 Dashboard Rules 标签页管理

### 优先级分层

| 范围 | 等级 | 描述 |
|------|------|------|
| 9000-10000 | RED | 灾难性操作（`rm -rf /`、管道注入、凭据窃取） |
| 8000 | RED | 始终需审计的工具（`fs_delete`、`sessions_spawn`） |
| 7000-7500 | GREEN/YELLOW | 已知安全模式（git、npm -> GREEN；工作空间内删除 -> YELLOW） |
| 6000-6500 | RED | 参数级危险（危险命令、敏感文件、SSRF） |
| 5000-5500 | GREEN | 始终安全的工具（`read`、`web_search`、`memory_*`） |
| 4000-4500 | YELLOW | 参数级普通（非危险命令、非敏感路径） |

高优先级的 GREEN 规则（7000+）会覆盖低优先级的 RED 规则（6000+），确保 `git status` 和 `npm install` 不会被过度分类。

### 自定义规则示例

```yaml
- id: CUSTOM-001
  name: Block terraform destroy
  tool: [exec, bash]
  tier: RED
  priority: 9000
  reason: "Terraform destroy requires manual review"
  detection:
    selection:
      command|re: "terraform\\s+destroy"
    condition: selection
```

完整的规则语法参考：[规则引擎文档](rule-engine.md)

## Override 机制

当工具调用被阻断时：

1. **生成 PIN** — 6 位数字 PIN（`crypto.randomInt`）
2. **展示方式** —
   - 受信任发送者：显示 `/pin<PIN>` 指令 + 内联按钮（Telegram 键盘、Slack 按钮等）
   - 非受信任发送者：仅提示需要受信任操作员批准，不显示 PIN
3. **确认操作** — 发送者回复 `/pin<PIN>`（文字或按钮回调）
4. **生效范围** — 当前轮次内有效，覆盖同一 `toolName` 的所有调用

## 超时与失败策略

| 策略 | 行为 |
|------|------|
| `fail_closed` | LLM 超时/故障 -> 阻断（安全优先） |
| `fail_open` | LLM 超时/故障 -> 放行（可用性优先） |

服务错误（429 限流、5xx 等）与安全发现区分处理：服务错误不生成 Override PIN，而是要求 Agent 停止执行并通知用户。

## 日志系统

- **控制台日志**：默认 debug 级别。GREEN 完全静默，YELLOW 产生 1 行调试输出，RED 产生约 10 行详细输出
- **JSONL 文件**：结构化事件日志（`seclaw-audit.jsonl`），记录分类、规则匹配、LLM 审计、阻断/放行等事件，每条携带 `toolCallId` 关联同一次调用

## API 端点

Dashboard 提供 REST API，可供外部系统集成：

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/auth` | 密码登录（设置 HttpOnly cookie） |
| GET | `/api/logs` | 审计日志（支持 `limit`、`tier`、`eventType`、`toolName` 查询） |
| GET | `/api/logs/stream` | SSE 实时日志推送 |
| GET | `/api/tool-calls` | 聚合的工具调用记录 |
| GET | `/api/tool-calls/stream` | SSE 实时工具调用更新 |
| GET | `/api/config` | 当前配置（`apiKey`、`password` 脱敏） |
| PUT | `/api/config` | 更新运行时配置 |
| GET | `/api/health` | 健康检查 |
| GET | `/api/health/scan` | 安全扫描（8 域 29 项检查，A-F 评分） |
| POST | `/api/health/harden` | 执行加固操作（参数：`action`、`mode`） |
| GET | `/api/health/report` | 安全评估报告（Markdown 格式） |
| GET | `/api/rules` | 已编译的规则列表（含 `sourceFile`） |
| GET | `/api/rules/files/meta` | 规则文件元数据（含平台激活状态） |
| GET | `/api/rules/files` | 规则文件列表 |
| GET | `/api/rules/file` | 获取单个规则文件内容 |
| PUT | `/api/rules/file` | 更新规则文件 |
| POST | `/api/rules/file/parse` | 解析 YAML 内容 |
| GET | `/api/rules/file/download` | 下载规则文件 |
| POST | `/api/rules/test` | 测试工具调用的规则匹配结果 |
| GET | `/api/models` | 可用模型列表 |
| POST | `/api/models/test` | 测试模型可用性（延迟探测） |
| GET | `/api/sender-labels` | 已知发送者标签 |
| POST | `/api/sender-labels/refresh` | 扫描日志发现新标签 |
