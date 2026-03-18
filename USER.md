# SecLaw 用户指南

SecLaw 是一个 OpenClaw 插件，为 AI Agent 的工具调用提供实时安全审计。它在每次工具调用前进行风险分类，根据危险等级决定是否放行、后台审计或同步阻断。

## 1. 安装与配置

### 前置要求

- Node.js >= 18
- 已安装并运行的 OpenClaw 网关
- 一个可用的 LLM 审计端点（OpenAI 兼容格式）

### 安装步骤

**第一步：获取项目并安装依赖**

```bash
cd extensions/seclaw
npm install
npm run build
```

构建产物输出到 `dist/` 目录。

**第二步：在 OpenClaw 网关中注册插件**

在 OpenClaw 的配置文件 `openclaw.json` 中添加 SecLaw 插件：

```json
{
  "plugins": {
    "entries": {
      "seclaw": {
        "enabled": true,
        "config": {
          "llm": {
            "model": "your-provider/your-model",
            "enabled": true
          }
        }
      }
    }
  }
}
```

**第三步：配置 LLM 审计模型**

SecLaw 使用 Provider 模式（`provider/model`）：

使用 `provider/model` 格式，自动从 OpenClaw 网关的 `models.providers` 配置中解析端点和密钥：

```json
{
  "llm": {
    "model": "myapi/gpt-4o"
  }
}
```

前提是 `openclaw.json` 中已配置对应 provider：

```json
{
  "models": {
    "providers": {
      "myapi": {
        "baseUrl": "https://api.openai.com/v1",
        "apiKey": "sk-...",
        "models": [
          { "id": "gpt-4o", "name": "GPT-4o" }
        ]
      }
    }
  }
}
```

**第四步：（可选）自定义规则**

在工作空间目录下创建 `.openclaw/seclaw-rules.yaml` 添加自定义规则：

```yaml
- id: CUSTOM-001
  name: Block terraform destroy
  toolMatch: [exec, bash]
  conditions:
    - type: command_matches
      pattern: "terraform\\s+destroy"
  tier: RED
  reason: "Terraform destroy requires manual review"
  priority: 9000
```

**第五步：验证安装**

启动 OpenClaw 后，日志中应看到类似输出：

```
[seclaw] 🚀 LLM connected via provider config model=myapi/gpt-4o
[seclaw] 🚀 Initialized rules=28 llm=myapi/gpt-4o policy=fail_closed
[seclaw] 📊 Dashboard: http://0.0.0.0:19198
```

### 完整配置参考

```json
{
  "llm": {
    "model": "myapi/gpt-4o",
    "enabled": true,
    "maxConcurrent": 2,
    "promptRecentCalls": 3,
    "trustedSenderLabels": ["openclaw-control-ui"],
    "retry": {
      "maxRetries": 2,
      "initialBackoffMs": 1000,
      "cooldownMs": 30000,
      "cooldownThreshold": 3
    }
  },
  "timeouts": {
    "syncAuditMs": 30000,
    "asyncAuditMs": 30000,
    "syncTimeoutPolicy": "fail_closed"
  },
  "logging": {
    "level": "debug",
    "auditJsonl": true
  },
  "dashboard": {
    "enabled": true,
    "port": 19198,
    "host": "0.0.0.0"
  }
}
```

| 配置项 | 说明 | 默认值 |
|--------|------|--------|
| `llm.model` | 审计用 LLM 模型（`provider/model` 或纯模型名） | `""` |
| `llm.enabled` | 是否启用 LLM 审计 | `true` |
| `llm.maxConcurrent` | 最大并发 LLM 调用数 | `2` |
| `llm.trustedSenderLabels` | 受信任发送者标签列表 | `["openclaw-control-ui"]` |
| `timeouts.syncAuditMs` | 同步审计超时（毫秒） | `30000` |
| `timeouts.asyncAuditMs` | 异步审计超时（毫秒） | `30000` |
| `timeouts.syncTimeoutPolicy` | 超时策略：`fail_closed`（阻断）或 `fail_open`（放行） | `fail_closed` |
| `logging.level` | 日志级别：`debug` / `info` / `warn` / `error` | `debug` |
| `logging.auditJsonl` | 是否写入 JSONL 审计日志 | `true` |
| `dashboard.enabled` | 是否启用 Web 仪表盘 | `true` |
| `dashboard.port` | 仪表盘端口 | `19198` |
| `dashboard.host` | 仪表盘监听地址 | `0.0.0.0` |

## 2. Dashboard 仪表盘

SecLaw 内置了一个 Web 仪表盘，提供实时审计监控和运行时配置管理。启动后访问：

```
http://127.0.0.1:19198
```

### 界面概览

仪表盘是一个深色主题的单页应用（SPA），包含 4 个标签页：

#### Audit Log（审计日志）

主界面，以卡片形式展示每个工具调用的审计记录：

- **卡片头部**：显示相对时间、工具名、分类等级徽章（🟢 GREEN / 🟡 YELLOW / 🔴 RED）和状态标签
- **状态标签**：
  - 绿色 `allowed` — 工具调用已放行
  - 红色 `BLOCKED` — 工具调用被阻断（如有 Override PIN 也会显示）
  - 黄色 `auditing...` — 异步审计进行中（带旋转动画）
  - 紫色 `OVERRIDDEN` — 被阻断后经受信任操作员确认放行
- **展开详情**：点击卡片可查看完整审计生命周期，包括规则匹配、意图上下文、同步/异步审计结果、Override 信息、请求参数等
- **过滤器**：支持按分类等级（GREEN / YELLOW / RED）、状态（All / Allowed / Blocked / Overridden / Pending）、工具名筛选
- **实时更新**：通过 SSE（Server-Sent Events）推送，卡片在审计进展时原地更新，无需刷新页面

#### Config（配置）

运行时配置编辑器，支持在线修改以下设置：

- **模型选择**：下拉菜单列出网关中所有可用模型（从 `/api/models` 获取）
- **LLM 开关**：启用/禁用 LLM 审计
- **并发数**：调整 `maxConcurrent`
- **受信任发送者标签**：多选下拉框，支持"全选"/"清除"，以及刷新按钮（扫描审计日志发现新标签）
- **超时设置**：同步/异步审计超时、超时策略
- **日志设置**：日志级别、JSONL 开关
- **仪表盘设置**（只读）：端口/地址/开关，修改需重启生效

> 配置变更会直接写入 `~/.openclaw/openclaw.json` 的 `plugins.entries.seclaw.config`。`llm.apiKey` 与 `llm.endpoint` 已废弃并移除。

#### Health（健康检查）

显示 SecLaw 运行状态。访问 `/api/health` 返回 `{ "status": "running" }`。

#### Rules（规则）

列出当前加载的所有安全规则，包含规则 ID、名称、匹配工具、条件、分类等级和优先级。

### API 端点

仪表盘同时提供 REST API，可供外部系统集成：

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/logs` | 获取审计日志（支持 `limit`、`tier`、`eventType`、`toolName` 查询参数） |
| GET | `/api/logs/stream` | SSE 实时日志推送 |
| GET | `/api/tool-calls` | 获取聚合的工具调用记录 |
| GET | `/api/tool-calls/stream` | SSE 实时工具调用更新 |
| GET | `/api/config` | 获取当前配置（`apiKey` 脱敏为 `"***"`） |
| PUT | `/api/config` | 更新运行时配置 |
| GET | `/api/health` | 健康检查 |
| GET | `/api/rules` | 获取已加载的规则列表 |
| GET | `/api/models` | 获取可用模型列表 |

## 3. 运行原理

### 三级分类系统

SecLaw 的核心是一个规则引擎，将每次工具调用分为三个安全等级：

| 等级 | 行为 | 示例 |
|------|------|------|
| **GREEN** | 立即放行，不做任何审计 | 读文件、git 操作、web 搜索 |
| **YELLOW** | 立即放行，在后台异步进行 LLM 审计 | 普通命令执行、非敏感文件写入 |
| **RED** | 阻塞执行，等待同步 LLM 审计完成 | `rm -rf /`、敏感文件修改、反弹 shell |

如果没有规则匹配，默认为 **YELLOW**（放行 + 异步审计）。

### 工具调用审计流程

```
用户消息
  │
  ├─ 意图追踪（通过 before_prompt_build 钩子）
  │   └─ 提取用户目标、发送者标签、消息来源
  │
  ├─ Override 检测（如配置了 trustedSenderLabels）
  │   └─ 受信任发送者发 /pin<PIN> → 激活覆盖
  │
工具调用 (before_tool_call, 优先级 9999)
  │
  ├─ 1. 检查是否有活跃的 Override（本轮内同一工具名）
  │     └─ 有 → 立即放行，跳过所有审计
  │
  ├─ 2. 检查异步审计的危险标记
  │     └─ 有 → 阻断 + 生成 Override PIN
  │
  └─ 3. 规则引擎分类 → GREEN / YELLOW / RED
        │
        ├─ GREEN → 放行（静默，无日志）
        │
        ├─ YELLOW → 放行
        │     └─ 工具执行后 → 入队异步审计
        │         └─ LLM 判定 DANGER → 设置危险标记（阻断下一次调用）
        │
        └─ RED → 同步 LLM 审计
              ├─ SAFE → 放行
              └─ DANGER → 阻断 + Override PIN + 按钮
```

### 规则引擎

规则定义在 YAML 文件中，按优先级从高到低排序，第一个匹配的规则生效：

- **默认规则**（`rules/default.yaml`）：28+ 条内置规则，覆盖常见危险模式
- **工作空间规则**（`.openclaw/seclaw-rules.yaml`）：项目级自定义规则
- **额外规则**（`config.rules.extra`）：通过配置传入的规则

优先级分层：

| 范围 | 等级 | 描述 |
|------|------|------|
| 9000-10000 | RED | 灾难性操作（`rm -rf /`、管道注入、凭据窃取） |
| 8000 | RED | 始终需审计的工具（`fs_delete`、`sessions_spawn`） |
| 7000-7500 | GREEN/YELLOW | 已知安全模式（git、npm → GREEN；工作空间内删除 → YELLOW） |
| 6000-6500 | RED | 参数级危险（危险命令、敏感文件、SSRF） |
| 5000-5500 | GREEN | 始终安全的工具（`read`、`web_search`、`memory_*`） |
| 4000-4500 | YELLOW | 参数级普通（非危险命令、非敏感路径） |

关键设计：高优先级的 GREEN 规则（7000+）会覆盖低优先级的 RED 规则（6000+），确保 `git status` 和 `npm install` 不会被过度分类。

### LLM 审计

当工具调用被分类为 RED 时，SecLaw 构建一个审计提示发送给 LLM，包含：

- 用户目标（截断至 500 字符）
- 发送者标签及信任策略
- 最近的工具调用历史
- 当前操作详情（工具名、参数）
- 触发规则的上下文（规则 ID 和原因）

LLM 返回 `SAFE`（放行）或 `DANGER`（阻断）判定。

审计结果使用 SHA-256 指纹缓存，5 分钟 TTL 内相同请求不重复调用 LLM。

### Override 机制

当工具调用被阻断时：

1. **生成 PIN**：SecLaw 生成一个 6 位数字 PIN（`crypto.randomInt`）
2. **展示方式**：
   - **受信任发送者**：`blockReason` 中显示 `/pin<PIN>` 指令，并附带 `buttons` 字段（渲染为 Telegram 内联键盘、Slack 按钮等）
   - **非受信任发送者**：仅提示"此操作需要受信任操作员批准"，不显示 PIN 和按钮
3. **确认操作**：受信任发送者回复 `/pin<PIN>`（文字输入或点击按钮回调）
4. **生效范围**：Override 在**当前轮次**内有效（直到下一条用户消息），覆盖同一 `toolName` 的所有调用

### 超时与失败策略

| 策略 | 行为 |
|------|------|
| `fail_closed` | LLM 超时/故障 → 阻断（安全优先） |
| `fail_open` | LLM 超时/故障 → 放行（可用性优先） |

服务错误（429 限流、5xx 等）与安全发现区分处理：服务错误不生成 Override PIN（覆盖服务故障无意义），而是要求 Agent 停止执行并通知用户。

### 日志系统

SecLaw 提供两种日志输出：

- **控制台日志**：受 `logging.level` 控制，GREEN 调用完全静默，YELLOW 产生 1 行调试输出，RED 产生约 10 行详细输出
- **JSONL 文件**：结构化事件日志（`seclaw-audit.jsonl`），记录分类、规则匹配、LLM 审计、阻断/放行等全部事件，每条事件携带 `toolCallId` 关联同一次调用
