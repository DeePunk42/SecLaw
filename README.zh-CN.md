# SecLaw

[OpenClaw](https://github.com/nicepkg/openclaw) AI Agent 实时安全审计层。每次工具调用都会在执行前被分类和审计。

[![npm](https://img.shields.io/npm/v/@deepunk/seclaw)](https://www.npmjs.com/package/@deepunk/seclaw)

[English](README.md)

## 工作原理

```
工具调用 ──> 规则引擎 ──> LLM 审计 ──> 放行 / 拦截
                |
          GREEN: 立即放行，不做审计
          YELLOW: 立即放行，后台异步审计
          RED: 阻断，等待实时审计确认安全
```

SecLaw 的规则引擎将每次工具调用分为三个等级。GREEN 操作（读文件、git status）静默通过。YELLOW 操作（普通命令）立即放行但后台审计——如果审计发现危险，下一次调用会被拦截。RED 操作（破坏性命令、凭据访问）被阻断，直到实时 LLM 审计确认安全。

技术细节参见[进阶文档](docs/advanced.md)。

## 适用版本

OpenClaw >= 2026.3.22

## 快速上手

### 1. 安装

```bash
openclaw plugins install @deepunk/seclaw
```

### 2. 启用

插件在首次安装后自动启用。SecLaw 会自动完成初始化：创建数据目录、写入默认配置、复制默认规则（28+ 条）、预置发送者标签。无需手动创建任何文件。

### 3. 打开 Dashboard

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
[seclaw] LLM connected via provider config model=openai-codex/gpt-5.4
[seclaw] Initialized rules=28 llm=openai-codex/gpt-5.4 policy=fail_closed
[seclaw] Dashboard: /plugins/seclaw
```

此时 SecLaw 已在工作。所有 Agent 工具调用都会经过实时安全审计。在 **Audit Log** 标签页可以看到实时审计卡片。

## Dashboard 仪表盘

SecLaw 内置 Web 仪表盘，包含四个标签页：

| 标签页 | 功能 |
|--------|------|
| **Audit Log** | 实时工具调用监控，带等级徽章（GREEN/YELLOW/RED）、状态标签、可展开详情和过滤器。通过 SSE 实时更新。 |
| **Config** | 运行时配置——模型选择、LLM 开关、受信任发送者标签、超时设置。修改即时生效。 |
| **Rules** | 查看和编辑 YAML 规则文件，上传自定义规则，内置规则测试器。 |
| **Health** | 安全扫描（8 个域、29+ 项检查、A-F 评分）和一键加固（balanced / paranoid 模式）。 |

### 认证（可选）

Dashboard 默认不需要认证（依赖网关层的网络安全控制）。支持两种可选认证方式：

- **Token 认证**：配置 `dashboard.token`，通过 Bearer header 或 URL query param 认证
- **密码认证**：配置 `dashboard.password`，通过浏览器登录界面输入密码，使用 HttpOnly cookie 保持会话（30 天有效）

## 配置

所有设置均可在 Dashboard **Config** 标签页中编辑，存储在 `~/.openclaw/openclaw.json` 的 `seclaw` 插件配置下。

### 受信任发送者标签

多用户场景下最重要的配置。

`llm.trustedSenderLabels` 控制哪些消息发送者可以覆盖被拦截的操作。当 RED 工具调用被阻断时，SecLaw 生成一个 6 位数字 PIN。只有标签在此列表中的发送者才能使用 `/pin<PIN>` 命令解除拦截。

**默认值：** `["openclaw-control-ui"]`（OpenClaw Web UI）

**配置方式：**

- **Dashboard**：Config 标签页 > Trusted Sender Labels 多选下拉框。点击刷新按钮可从审计日志中发现新标签。
- **配置文件**：编辑 `~/.openclaw/openclaw.json`：

```json
{
  "plugins": {
    "seclaw": {
      "llm": {
        "trustedSenderLabels": ["openclaw-control-ui", "telegram:alice", "discord:admin-bot"]
      }
    }
  }
}
```

**Override 流程：**

1. Agent 尝试危险操作 -> SecLaw 拦截
2. 向受信任发送者展示 6 位 PIN（在 Telegram/Slack/Discord 上显示内联按钮）
3. 受信任发送者回复 `/pin123456`（或点击按钮）
4. 该工具名在当前轮次内解除拦截

非受信任发送者只能看到"需要操作员批准"——PIN 不会向他们展示。

### 所有配置项

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| `llm.model` | `""` | 审计用 LLM 模型（`provider/model` 格式） |
| `llm.enabled` | `true` | 是否启用 LLM 审计 |
| `llm.maxConcurrent` | `2` | 最大并发 LLM 调用数 |
| `llm.promptRecentCalls` | `3` | 审计提示词中包含的最近工具调用数 |
| `llm.trustedSenderLabels` | `["openclaw-control-ui"]` | 允许覆盖拦截的发送者列表 |
| `llm.apiKey` | — | 显式 API Key（覆盖 provider 级别认证） |
| `timeouts.auditTimeoutMs` | `60000` | 审计超时（毫秒） |
| `timeouts.syncTimeoutPolicy` | `"fail_closed"` | `fail_closed` = 超时拦截；`fail_open` = 超时放行 |
| `dashboard.enabled` | `true` | 是否启用 Dashboard |
| `dashboard.token` | — | API Bearer 认证 token |
| `dashboard.password` | — | 浏览器登录密码 |

## 了解更多

- [进阶文档](docs/advanced.md) — 审计流程、意图上下文、Override 机制、超时策略、日志系统、API 端点
- [规则引擎参考](docs/rule-engine.md) — 规则语法、字段修饰符、检测条件、自定义规则示例
