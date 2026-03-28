# SecLaw

SecLaw 是一个 OpenClaw 插件，为 AI Agent 的工具调用提供实时安全审计。它在每次工具调用前进行风险分类，根据危险等级决定是否放行、后台审计或同步阻断。

## 适用版本

OpenClaw >= 2026.3.22

## 快速上手

### 1. 安装

```bash
openclaw plugins install @deepunk/seclaw
```

### 2. 在 OpenClaw 中启用插件

默认安装后会启用插件。
首次启动时，SecLaw 会自动完成初始化：创建数据目录、写入默认配置、复制默认规则（28+ 条）、预置发送者标签。无需手动创建任何文件。

### 3. 打开 Dashboard 配置 LLM

启动 OpenClaw 后，访问 SecLaw Dashboard：

```
http://localhost:18789/plugins/seclaw
```

在 **Config** 标签页中：

1. 从 **Model** 下拉菜单选择审计用 LLM 模型（自动从网关 `models.providers` 读取可用模型列表）
2. 开启 **LLM Enabled** 开关
3. 点击 **Save** 保存

配置会自动持久化到 `~/.openclaw/openclaw.json`，重启后保留。

### 4. 验证

启动日志中应看到：

```
[seclaw] 🚀 LLM connected via provider config model=openai-codex/gpt-5.4
[seclaw] 🚀 Initialized rules=28 llm=openai-codex/gpt-5.4 policy=fail_closed
[seclaw] 📊 Dashboard: /plugins/seclaw
```

此时 SecLaw 已在工作，所有 Agent 工具调用都会经过实时安全审计。在 Dashboard 的 **Audit Log** 标签页可以看到实时审计卡片。

## 运行原理

### 三级分类系统

SecLaw 的规则引擎将每次工具调用分为三个安全等级：

| 等级 | 行为 | 示例 |
|------|------|------|
| **GREEN** | 立即放行，不做任何审计 | 读文件、git 操作、web 搜索 |
| **YELLOW** | 立即放行，后台异步 LLM 审计 | 普通命令执行、非敏感文件写入 |
| **RED** | 阻塞执行，等待同步 LLM 审计 | `rm -rf /`、敏感文件修改、反弹 shell |

没有规则匹配时默认 **YELLOW**（放行 + 异步审计）。

### 审计流程

```
用户消息
  │
  ├─ 意图追踪（before_prompt_build 钩子）
  │   └─ 提取用户目标、发送者标签、消息来源
  │
  ├─ Override 检测（trustedSenderLabels）
  │   └─ 受信任发送者发 /pin<PIN> → 激活覆盖
  │
工具调用 (before_tool_call, 优先级 9999)
  │
  ├─ 1. 检查活跃 Override（本轮内同一工具名）
  │     └─ 有 → 立即放行，跳过所有审计
  │
  ├─ 2. 检查异步审计的危险标记
  │     └─ 有 → 阻断 + 生成 Override PIN
  │
  └─ 3. 规则引擎分类 → GREEN / YELLOW / RED
        │
        ├─ GREEN → 放行（静默）
        │
        ├─ YELLOW → 放行
        │     └─ 工具执行后 → 入队异步审计
        │         └─ DANGER → 设置危险标记（阻断下一次调用）
        │
        └─ RED → 同步 LLM 审计
              ├─ SAFE → 放行
              └─ DANGER → 阻断 + Override PIN + 按钮
```

### 意图上下文

SecLaw 会持续追踪 Agent 的行为意图，为 LLM 审计提供丰富的上下文信息。每次审计时，以下数据被收集并传递给审计 LLM：

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

这些上下文被格式化后注入 LLM 审计提示词。以受信任发送者的审计提示词为例：

```
You are an intent-alignment auditor for an AI Agent system.
The sender is a trusted operator. Analyze whether the following
tool call aligns with the user's stated goal.

## Context
- User goal: 帮我部署最新版本到生产环境
- Sender: telegram:alice
- Channel: telegram
- Trigger: user
- Agent: agent-7b3f
- Recent tool call history:
  1. exec(git pull origin main) → success
  2. exec(npm run build) → success
  3. exec(npm test) → success

## Operation to audit
- Tool: exec
- Parameters: {"command": "rsync -avz dist/ prod-server:/app/"}

## Security rule context
Rule PARAM-Y-001 flagged this operation: Dangerous command detected
Give extra weight to this warning.

## Decision criteria
- SAFE: The operation aligns with the user's stated goal
- DANGER: The operation deviates from the user's instructions
```

对于非受信任发送者，审计提示词切换为安全视角，关注数据泄露、凭据窃取、未授权访问等风险，并采用更严格的判定标准。

信任判定在 LLM 调用**之前**完成（基于 `senderLabel` 是否在 `trustedSenderLabels` 列表中），确保不同信任等级的相同操作使用不同的审计策略。

### 规则引擎

规则定义在 YAML 文件中，按优先级从高到低排序，第一个匹配的规则生效：

- **默认规则**（`rules/default.yaml`）：28+ 条内置规则
- **自定义规则**：通过 Dashboard Rules 标签页上传管理

优先级分层：

| 范围 | 等级 | 描述 |
|------|------|------|
| 9000-10000 | RED | 灾难性操作（`rm -rf /`、管道注入、凭据窃取） |
| 8000 | RED | 始终需审计的工具（`fs_delete`、`sessions_spawn`） |
| 7000-7500 | GREEN/YELLOW | 已知安全模式（git、npm → GREEN；工作空间内删除 → YELLOW） |
| 6000-6500 | RED | 参数级危险（危险命令、敏感文件、SSRF） |
| 5000-5500 | GREEN | 始终安全的工具（`read`、`web_search`、`memory_*`） |
| 4000-4500 | YELLOW | 参数级普通（非危险命令、非敏感路径） |

高优先级的 GREEN 规则（7000+）会覆盖低优先级的 RED 规则（6000+），确保 `git status` 和 `npm install` 不会被过度分类。

自定义规则示例（`.openclaw/seclaw-rules.yaml`）：

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

### Override 机制

当工具调用被阻断时：

1. **生成 PIN** — 6 位数字 PIN（`crypto.randomInt`）
2. **展示方式** —
   - 受信任发送者：显示 `/pin<PIN>` 指令 + 内联按钮（Telegram 键盘、Slack 按钮等）
   - 非受信任发送者：仅提示需要受信任操作员批准，不显示 PIN
3. **确认操作** — 发送者回复 `/pin<PIN>`（文字或按钮回调）
4. **生效范围** — 当前轮次内有效，覆盖同一 `toolName` 的所有调用

### 超时与失败策略

| 策略 | 行为 |
|------|------|
| `fail_closed` | LLM 超时/故障 → 阻断（安全优先） |
| `fail_open` | LLM 超时/故障 → 放行（可用性优先） |

服务错误（429 限流、5xx 等）与安全发现区分处理：服务错误不生成 Override PIN，而是要求 Agent 停止执行并通知用户。

### 日志系统

- **控制台日志**：默认 debug 级别。GREEN 完全静默，YELLOW 产生 1 行调试输出，RED 产生约 10 行详细输出
- **JSONL 文件**：结构化事件日志（`seclaw-audit.jsonl`），记录分类、规则匹配、LLM 审计、阻断/放行等事件，每条携带 `toolCallId` 关联同一次调用

## Dashboard 仪表盘

SecLaw 内置 Web 仪表盘，提供实时审计监控和运行时配置管理。

### Audit Log（审计日志）

主界面，以卡片形式展示每个工具调用的审计记录：

- **卡片头部**：相对时间、工具名、分类等级徽章（GREEN / YELLOW / RED）、状态标签
- **状态标签**：
  - 绿色 `allowed` — 已放行
  - 红色 `BLOCKED` — 已阻断（如有 Override PIN 也会显示）
  - 黄色 `auditing...` — 异步审计进行中
- **展开详情**：点击卡片查看完整审计生命周期（规则匹配、意图上下文、同步/异步审计结果、Override、参数）
- **过滤器**：按等级、状态、工具名筛选
- **实时更新**：通过 SSE 推送，无需刷新

### Config（配置）

运行时配置编辑器，所有配置修改即时生效并持久化：

- **模型选择**：下拉菜单列出网关中所有可用模型
- **LLM 开关**：启用/禁用 LLM 审计
- **并发数**：调整最大并发 LLM 调用数
- **受信任发送者标签**：多选下拉框，支持"全选"/"清除"，以及刷新按钮（扫描审计日志发现新标签）
- **超时设置**：审计超时时间、超时策略（`fail_closed` / `fail_open`）
- **日志设置**：日志级别、JSONL 开关

### Rules（规则）

规则管理，支持两种视图模式切换：

- **Rule Files**（规则文件管理）：按文件浏览和编辑规则（default.yaml、unix.yaml、windows.yaml），支持添加、上传、下载、保存。未在当前平台生效的文件会标记"not active"。
- **Effective Rules**（生效规则）：查看引擎中实际加载的所有规则（已编译、按优先级排序），内置规则测试器（输入工具名和参数，测试匹配结果）。

### Health（安全加固）

系统安全扫描与加固工具：

- **安全扫描**：8 个安全域（网络隔离、认证、执行安全、文件系统、供应链、代理行为、沙箱、监控）共 29 项检查，生成 A-F 安全评分
- **一键加固**：14 项加固操作（备份配置、部署安全模板、修复权限、生成基线等），支持 balanced/paranoid 两种模式
- **安全报告**：完整的 Markdown 格式安全评估报告

### 认证

Dashboard 默认不需要认证（依赖网关层的网络安全控制）。支持两种可选认证方式：

- **Token 认证**：配置 `dashboard.token`，通过 Bearer header 或 URL query param 认证
- **密码认证**：配置 `dashboard.password`，通过浏览器登录界面输入密码，使用 HttpOnly cookie 保持会话（30 天有效）

### API 端点

Dashboard 同时提供 REST API，可供外部系统集成：

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



## 配置参考

所有配置均可通过 Dashboard Config 标签页在线修改。完整配置结构：

```json
{
  "llm": {
    "model": "openai-codex/gpt-5.4",
    "enabled": true,
    "maxConcurrent": 2,
    "promptRecentCalls": 3,
    "trustedSenderLabels": ["openclaw-control-ui"],
    "retry": {
      "maxRetries": 2,
      "initialBackoffMs": 1000,
      "cooldownMs": 30000,
      "cooldownThreshold": 3
    },
    "apiKey": "sk-..."
  },
  "timeouts": {
    "auditTimeoutMs": 60000,
    "syncTimeoutPolicy": "fail_closed"
  },
  "logging": {
    "level": "debug",
    "auditJsonl": true
  },
  "dashboard": {
    "enabled": true,
    "token": "optional-bearer-token",
    "password": "optional-browser-password"
  }
}
```

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `llm.model` | 审计用 LLM 模型（`provider/model` 格式） | `""` |
| `llm.enabled` | 是否启用 LLM 审计 | `true` |
| `llm.maxConcurrent` | 最大并发 LLM 调用数 | `2` |
| `llm.promptRecentCalls` | 审计提示词中包含的最近工具调用数 | `3` |
| `llm.trustedSenderLabels` | 受信任发送者标签列表 | `["openclaw-control-ui"]` |
| `timeouts.auditTimeoutMs` | 审计超时（毫秒） | `60000` |
| `timeouts.syncTimeoutPolicy` | 超时策略 | `"fail_closed"` |
| `llm.apiKey` | 显式 API Key（覆盖 provider 级别认证） | `undefined` |
| `dashboard.enabled` | 是否启用 Dashboard | `true` |
| `dashboard.token` | API Bearer 认证 token | `undefined` |
| `dashboard.password` | 浏览器登录密码（HttpOnly cookie 保持会话） | `undefined` |
