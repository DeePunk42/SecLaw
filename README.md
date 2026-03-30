# SecLaw

Real-time security audit layer for [OpenClaw](https://github.com/nicepkg/openclaw) AI agents. Every tool call is classified and audited before execution.

[![npm](https://img.shields.io/npm/v/@deepunk/seclaw)](https://www.npmjs.com/package/@deepunk/seclaw)

[中文文档](README.zh-CN.md)

## How It Works

```
Tool Call ──> Rule Engine ──> LLM Audit ──> Allow / Block
                 |
          GREEN: allow immediately, no audit
          YELLOW: allow immediately, audit in background
          RED: block until audit confirms safe
```

SecLaw's rule engine classifies every tool call into three tiers. GREEN operations (file reads, git status) pass through silently. YELLOW operations (normal commands) are allowed but audited asynchronously — if the audit finds danger, the next call is blocked. RED operations (destructive commands, credential access) are blocked until a real-time LLM audit confirms they are safe.

For technical details, see [Advanced Documentation](docs/advanced.md).

## Requirements

OpenClaw >= 2026.3.22

## Quick Start

### 1. Install

```bash
openclaw plugins install @deepunk/seclaw
```

### 2. Enable

The plugin is enabled automatically on first install. SecLaw will create its data directory, write default config, copy default rules (28+), and preset sender labels — no manual setup needed.

### 3. Open Dashboard

After starting OpenClaw, open the SecLaw Dashboard:

```
http://localhost:18789/plugins/seclaw
```

In the **Config** tab:

1. Select an LLM model from the **Model** dropdown (auto-populated from your gateway's `models.providers`)
2. Turn on **LLM Enabled**
3. Click **Save**

Configuration is persisted to `~/.openclaw/openclaw.json` and survives restarts.

### 4. Verify

You should see in the startup logs:

```
[seclaw] LLM connected via provider config model=openai-codex/gpt-5.4
[seclaw] Initialized rules=28 llm=openai-codex/gpt-5.4 policy=fail_closed
[seclaw] Dashboard: /plugins/seclaw
```

SecLaw is now active. All agent tool calls are audited in real time. Open the **Audit Log** tab to see live audit cards.

## Dashboard

SecLaw includes a built-in web dashboard with four tabs:

| Tab | What it does |
|-----|-------------|
| **Audit Log** | Real-time tool call monitoring with tier badges (GREEN/YELLOW/RED), status labels, expandable details, and filters. Live updates via SSE. |
| **Config** | Runtime configuration — model selection, LLM toggle, trusted sender labels, timeout settings. Changes take effect immediately. |
| **Rules** | View and edit YAML rule files, upload custom rules, test rule matching with the built-in tester. |
| **Health** | Security scanner (8 domains, 29+ checks, A-F grading) and one-click hardening in balanced or paranoid mode. |

### Authentication (optional)

The dashboard is open by default (relies on gateway-level network security). Two optional auth methods:

- **Token**: Set `dashboard.token` — authenticate via Bearer header or URL query param
- **Password**: Set `dashboard.password` — browser login with HttpOnly cookie (30-day session)

## Configuration

All settings can be edited in the Dashboard **Config** tab. They are stored in `~/.openclaw/openclaw.json` under the `seclaw` plugin key.

### Trusted Sender Labels

The most important configuration for multi-user setups.

`llm.trustedSenderLabels` controls which message senders are allowed to override blocked operations. When a RED tool call is blocked, SecLaw generates a 6-digit PIN. Only senders whose label appears in this list can use the `/pin<PIN>` command to unblock it.

**Default:** `["openclaw-control-ui"]` (the OpenClaw web UI)

**How to configure:**

- **Dashboard**: Config tab > Trusted Sender Labels multi-select dropdown. Use the refresh button to discover new labels from audit logs.
- **Config file**: Edit `~/.openclaw/openclaw.json`:

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

**Override flow:**

1. Agent tries a dangerous operation -> SecLaw blocks it
2. A 6-digit PIN is shown to trusted senders (with inline buttons on Telegram/Slack/Discord)
3. Trusted sender replies `/pin123456` (or taps the button)
4. Operation is unblocked for that tool name within the current turn

Non-trusted senders only see "requires operator approval" — the PIN is not revealed to them.

### All Options

| Option | Default | Description |
|--------|---------|-------------|
| `llm.model` | `""` | LLM model for auditing (`provider/model` format) |
| `llm.enabled` | `true` | Enable/disable LLM auditing |
| `llm.maxConcurrent` | `2` | Max concurrent LLM audit calls |
| `llm.promptRecentCalls` | `3` | Number of recent tool calls included in audit prompt |
| `llm.trustedSenderLabels` | `["openclaw-control-ui"]` | Senders allowed to override blocked calls |
| `llm.apiKey` | — | Explicit API key (overrides provider-level auth) |
| `timeouts.auditTimeoutMs` | `60000` | Audit timeout in milliseconds |
| `timeouts.syncTimeoutPolicy` | `"fail_closed"` | `fail_closed` = block on timeout; `fail_open` = allow on timeout |
| `dashboard.enabled` | `true` | Enable the web dashboard |
| `dashboard.token` | — | Bearer token for API authentication |
| `dashboard.password` | — | Password for browser login |

## Learn More

- [Advanced Documentation](docs/advanced.md) — Audit flow internals, intent context, override mechanism, timeout policies, logging, API endpoints
- [Rule Engine Reference](docs/rule-engine.md) — Rule syntax, field modifiers, detection conditions, custom rule examples
