# SecAgent Architecture

## Overview

SecAgent is a real-time security audit layer for AI Agent tool calls in OpenClaw. It implements a **unified rule engine** that classifies every tool call into one of two tiers:

- **GREEN** — Allow execution immediately, run async LLM audit in background
- **YELLOW** — Run synchronous LLM audit before execution

**Default behavior: no matching rule → GREEN (allow + async audit).**

## Architecture Flow

```
User Message
  │
  ├─ Intent tracking (via before_prompt_build hook)
  │   └─ Updates userGoal / channelId / trigger / agentId / messageProvider
  │
  ├─ Override detection (if trustedSenderLabels configured)
  │   └─ SEC_OVERRIDE:<pin> from trusted sender → activate override
  │
Tool Call (before_tool_call)
  │
  ├─ Active override check (turn-scoped, same toolName)
  │   └─ If active → ALLOW immediately, skip all audit
  │
  ├─ Danger flag check (from previous async audit)
  │   └─ If set → BLOCK + register override PIN
  │
  └─ Rule Engine: classify(toolName, params, intentCtx, wsPath) → GREEN / YELLOW
      │
      ├─ GREEN → Allow execution (silent)
      │   └─ afterToolCall → Async audit queue (skipped for override-approved calls)
      │       └─ Re-classify → If YELLOW → LLM audit
      │           └─ DANGER → Set danger flag (blocks next call)
      │
      └─ YELLOW → Synchronous LLM audit (with rule context)
          ├─ SAFE → Allow execution
          └─ DANGER → BLOCK + register override PIN + emit SSE event
```

## Module Structure

```
index.ts                    Plugin entry point, hook registration, source extraction
src/
  config.ts                 Type definitions, configuration schema, defaults
  rule-engine.ts            Unified rule engine (YAML rules → GREEN/YELLOW)
  llm-auditor.ts            LLM audit: prompt construction, API call, response parsing
  async-audit-queue.ts      Background audit queue with deduplication
  audit-log.ts              Console + JSONL logging, log level filtering
  intent-context.ts         Intent accumulator (userGoal, message source, tool calls)
  session-state.ts          Per-session state manager (danger flags, audit cache, override state)
  interrupt.ts              Danger flag management, override SSE events, interrupt mechanism
  patterns/                 Command/URL/path analysis utilities
rules/
  default.yaml              28 built-in security rules
```

## Rule Engine

### How It Works

1. Rules are loaded from YAML files and sorted by priority (descending)
2. For each tool call, rules are evaluated in priority order
3. First matching rule wins — returns `{ tier, ruleId, reason }`
4. If no rule matches, default is `{ tier: "GREEN" }`

### Rule Structure

```yaml
- id: CAT-001                    # Unique rule identifier
  name: Catastrophic delete       # Human-readable name
  toolMatch: [exec, bash]         # Tools this rule applies to (or ["*"] for all)
  conditions:                     # ALL conditions must match (AND logic)
    - type: command_matches
      pattern: "rm\\s+.*-rf\\s+/"
  tier: YELLOW                    # GREEN or YELLOW
  reason: "Recursive delete"      # Passed to LLM as context
  priority: 10000                 # Higher = evaluated first
```

### Condition Types

| Type | Description | Parameters |
|------|-------------|------------|
| `command_matches` | Regex match on command string | `pattern` |
| `command_starts_with` | Command starts with prefix | `prefix` |
| `pipe_to_shell` | Command pipes to sh/bash/zsh | `value: true/false` |
| `has_dynamic_expansion` | Contains $() or backticks | `value: true/false` |
| `is_yellow_command` | Primary command is in dangerous set | `value: true/false` |
| `reads_sensitive_files` | Command reads secrets/keys/env | `value: true/false` |
| `is_sensitive_write_path` | Path targets .ssh/.env/etc | `value: true/false` |
| `path_in_workspace` | All paths within workspace dir | `value: true/false` |
| `path_matches` | Regex match on file path | `pattern` |
| `url_is_internal` | URL targets private/internal IP | `value: true/false` |
| `url_is_metadata` | URL targets cloud metadata endpoint | `value: true/false` |
| `url_is_credential` | URL path suggests credential access | `value: true/false` |

### Priority Tiers

| Range | Tier | Description |
|-------|------|-------------|
| 9000-10000 | YELLOW | Catastrophic patterns (rm -rf /, pipe-to-shell, credential theft) |
| 8000 | YELLOW | Always-YELLOW tools (fs_delete, sessions_spawn, gateway) |
| 7000-7500 | GREEN | Known-safe patterns (git, npm, docker safe ops, workspace rm) |
| 6000-6500 | YELLOW | Parameter-level YELLOW (dangerous commands, sensitive files, SSRF) |
| 5000-5500 | GREEN | Always-GREEN tools (read, web_search, memory_*) |
| 4000-4500 | GREEN | Parameter-level GREEN (non-dangerous commands, safe paths) |
| 0 | GREEN | Default fallback — no rule matched |

**Key design principle:** GREEN safe patterns (7000+) override parameter-level YELLOW (6000+), ensuring `git status` and `npm install` are not over-classified. Catastrophic YELLOW (9000+) always wins.

## Intent Context

SecAgent tracks agent intent per session to provide LLM auditors with context about what the agent is doing and why.

### Data Model

```typescript
interface IntentContext {
  userGoal: string;           // Latest user message (metadata stripped)
  senderLabel?: string;       // Sender label extracted from message metadata
  channelId?: string;         // Message channel (telegram, discord, whatsapp, ...)
  trigger?: string;           // Trigger type (user, heartbeat, cron, memory)
  agentId?: string;           // Agent identifier
  messageProvider?: string;   // Message provider
  stepIndex: number;          // Tool call counter
  turnNumber: number;         // User message counter
  recentToolCalls: Array<{ toolName, params, outcome }>;  // Ring buffer (max 10)
}
```

### User Message Parsing

`parseUserMessage(raw)` strips OpenClaw-injected metadata blocks from the raw user message:
- **Conversation info** block — stripped entirely
- **Sender** block — stripped, and `label` field extracted into `senderLabel`

This ensures `userGoal` contains only the user's actual instruction, reducing LLM audit prompt size.

### Population via OpenClaw Hooks

| Hook | Data Source | What It Populates |
|------|------------|-------------------|
| `before_prompt_build` | `event.prompt` (user input), `ctx` (agent context) | `userGoal` — current user message; `channelId`, `trigger`, `agentId`, `messageProvider` — from hook context |
| `after_tool_call` | `event.toolName`, `event.params`, `event.error` | `stepIndex`, `recentToolCalls` |
| `session_start` / `before_reset` / `before_compaction` | — | Reset all intent state |

`before_prompt_build` is the primary intent source. It fires before every LLM call and provides the user prompt, full `messages[]` array, plus source information (`channelId`, `trigger`, `agentId`, `messageProvider`) in context.

## Trusted Sender Override

When a tool call is blocked (sync DANGER, async danger flag, or fail_closed policy), a 6-digit decimal PIN is generated and included in the `blockReason`. Trusted senders can reply `SEC_OVERRIDE:<pin>` to unblock the operation.

### Flow

1. **Block** — `beforeToolCall` returns `{ block: true, blockReason }` with PIN in the hint
2. **SSE event** — `emitOverrideAvailable()` fires `override_available` event for button-capable platforms (Telegram inline buttons, etc.)
3. **User confirms** — Sends `SEC_OVERRIDE:<pin>` (text or button callback)
4. **Detection** — `onUserMessage()` checks `senderLabel ∈ trustedSenderLabels` + PIN validity → activates override
5. **Allow** — Next `beforeToolCall` finds active override → allows without audit

### Turn-scoped override

The override stays active for the **entire turn** (until the next `onUserMessage`). This handles multi-tool-call scenarios where the LLM retries with different params after the first attempt errors. All calls of the matching `toolName` within the same turn are covered. Cleanup happens via `clearTurnOverride()` at the start of each new turn.

### Security properties

- PIN is `crypto.randomInt(0, 1_000_000)` — 6-digit decimal, ~1M possibilities
- `senderLabel` is injected by the gateway, not controllable by the LLM
- `paramsFingerprint` (SHA-256) is stored for audit trail but NOT enforced on match (LLM may modify params on retry)
- Override-approved calls skip async audit to prevent re-flagging the same operation

### State management (session-state.ts)

- `pendingOverrides: Map<pin, PendingOverride>` — registered on block
- `activeOverridePin: string | null` — set when trusted sender confirms
- `lastCallOverridden: boolean` — set by `consumeActiveOverride()`, consumed by `afterToolCall` to skip async enqueue

## LLM Audit

### Prompt Template

The LLM audit prompt includes:
- User goal (truncated to 500 chars) and sender label
- Recent tool call history (last N, default 3; configurable via `llm.promptRecentCalls`)
- Operation details (tool name, compact JSON parameters truncated to 500 chars)
- **Rule context** (when triggered by a named rule)
- **Sender trust policy** — tells the LLM which `senderLabel` values are trusted (configurable via `llm.trustedSenderLabels`, default `["openclaw-control-ui"]`). Operations from untrusted senders receive stricter scrutiny for destructive or sensitive actions

### Rule Context Injection

When a rule triggers YELLOW classification, its `ruleId` and `reason` are passed to the LLM:

```
## Security rule context
Rule CAT-001 flagged this operation: Recursive delete targeting system directory
Give extra weight to this warning.
```

### Fingerprint Caching

Each audit request is fingerprinted via SHA-256 of `{ toolName, params, userGoal }`. Identical requests within a 5-minute TTL return the cached decision without calling the LLM.

### Concurrency Control

`llm.maxConcurrent` limits simultaneous LLM calls. When at capacity, the timeout policy determines the fallback decision.

### Timeout & Failure Policies

| Policy | Behavior |
|--------|----------|
| `fail_closed` | LLM timeout/failure → DANGER (block) |
| `fail_open` | LLM timeout/failure → SAFE (allow) |

## Async Audit Queue

After every tool call (`afterToolCall`), the operation is enqueued for background audit:

1. **Deduplication**: fingerprint-based, skips already-queued identical operations
2. **Re-classification**: runs `ruleEngine.classify()` again
3. **GREEN → skip**: no further audit needed
4. **YELLOW → LLM audit**: runs with `asyncAuditMs` timeout
5. **DANGER → interrupt**: sets per-session danger flag, emits `security` event

The danger flag blocks **all subsequent tool calls** for that session until the session is reset.

## Logging

### Console Output

Controlled by `logging.level` (`debug` | `info` | `warn` | `error`):

| Level | What is logged |
|-------|---------------|
| debug | `danger flag: none`, `GREEN exec(git status) — async audit`, intent context dump (YELLOW path only), `LLM audit: skipped (disabled)`, intent extraction source |
| info | `YELLOW exec(rm -rf /) — sync audit`, `BLOCKED exec [sync] — reason`, `ALLOW exec — LLM audit → SAFE`, initialization messages |
| warn | `danger flag FOUND — blocking all subsequent calls` |
| error | `DANGER exec [async] rule=CAT-001 — reason` |

A GREEN tool call produces **1 line** of debug output (the classification). A YELLOW tool call with LLM audit produces **~10 lines** of debug output (classification + intent context dump + final decision).

### JSONL File

When `logging.auditJsonl: true`, structured events are written to `sec-agent-audit.jsonl`:

| Event Type | Trigger |
|------------|---------|
| `tool_classified` | Every tool call classification + intent context (YELLOW path) |
| `rule_matched` | When a named rule matches |
| `llm_audit` | LLM audit result |
| `tool_blocked` | Tool call blocked |
| `tool_allowed` | Tool call allowed (YELLOW path only) |
| `danger_detected` | Async audit found danger |
| `override_used` | Trusted sender override consumed |

## LLM Gateway Connection

In production, SecAgent connects to the gateway's OpenAI-compatible endpoint:

```typescript
// Created during register() if llm.endpoint is configured
fetch(endpoint, {
  method: "POST",
  headers: { "Content-Type": "application/json", "Authorization": `Bearer ${apiKey}` },
  body: JSON.stringify({ model, messages, max_tokens }),
});
```

The response is parsed from OpenAI format: `data.choices[0].message.content`.

## Configuration

```json
{
  "llm": {
    "model": "gpt-5",
    "enabled": true,
    "maxConcurrent": 2,
    "promptRecentCalls": 3,
    "trustedSenderLabels": ["openclaw-control-ui"],
    "endpoint": "http://127.0.0.1:3000/v1/chat/completions",
    "apiKey": "sk-..."
  },
  "timeouts": {
    "syncAuditMs": 10000,
    "asyncAuditMs": 30000,
    "syncTimeoutPolicy": "fail_closed"
  },
  "logging": {
    "level": "debug",
    "auditJsonl": true
  },
  "rules": {
    "extra": []
  }
}
```

## Default Rules

| ID | Tier | Priority | Description |
|----|------|----------|-------------|
| CAT-001 | YELLOW | 10000 | Catastrophic recursive delete (rm -rf /) |
| CAT-002 | YELLOW | 10000 | Force remove root (--no-preserve-root) |
| CAT-003 | YELLOW | 9500 | Pipe download to shell |
| CAT-004 | YELLOW | 9500 | Data exfiltration via curl/wget |
| CAT-005 | YELLOW | 9200 | Overwrite SSH config |
| CAT-006 | YELLOW | 9100 | Overwrite shell profile |
| CAT-007 | YELLOW | 9800 | Disk format/wipe |
| CAT-008 | YELLOW | 9000 | Cron/at job creation |
| TOOL-Y-001..005 | YELLOW | 8000 | Always-YELLOW tools (fs_delete, fs_move, sessions_spawn, sessions_send, gateway) |
| SAFE-001 | GREEN | 7500 | Workspace-scoped delete |
| SAFE-002 | GREEN | 7200 | Git operations |
| SAFE-003 | GREEN | 7200 | Package manager operations |
| SAFE-004 | GREEN | 7100 | Docker safe operations |
| PARAM-Y-001 | YELLOW | 6500 | Dangerous command detected |
| PARAM-Y-002 | YELLOW | 6400 | Reads sensitive files |
| PARAM-Y-003 | YELLOW | 6300 | Sensitive file write path |
| PARAM-Y-004..006 | YELLOW | 6100-6200 | SSRF / metadata / credential URLs |
| TOOL-G-001..003 | GREEN | 5500 | Always-GREEN tools (read, web_search, memory_*) |
| PARAM-G-001 | GREEN | 4500 | Non-dangerous exec command |
| PARAM-G-002 | GREEN | 4000 | Non-sensitive file write |
| PARAM-G-003 | GREEN | 4000 | External URL fetch |

## Writing Custom Rules

Add rules to `.openclaw/sec-agent-rules.yaml` in your workspace:

```yaml
# Block terraform destroy
- id: CUSTOM-001
  name: Block terraform destroy
  toolMatch: [exec, bash]
  conditions:
    - type: command_matches
      pattern: "terraform\\s+destroy"
  tier: YELLOW
  reason: "Terraform destroy requires manual review"
  priority: 9000

# Allow specific internal API
- id: CUSTOM-002
  name: Allow internal API
  toolMatch: [web_fetch]
  conditions:
    - type: command_matches
      pattern: "http://internal-api\\.company\\.com"
  tier: GREEN
  reason: "Trusted internal API"
  priority: 7000
```

Or via plugin config `rules.extra` array.

## OpenClaw Plugin Integration

SecAgent registers as an OpenClaw plugin via `register(api)`. All hooks use the typed lifecycle system `api.on()`. The `api.emitAgentEvent` function (if provided) is wired to `setEmitAgentEvent()` during `register()` to enable SSE events (override buttons, danger notifications).

### Registered Hooks

| Hook | Priority | Purpose |
|------|----------|---------|
| `before_tool_call` | 9999 | Core: rule classification + LLM audit gate |
| `after_tool_call` | 100 | Core: record tool outcome, enqueue async audit |
| `before_prompt_build` | — | Intent: extract `userGoal` from prompt, message source from context |
| `session_start` | — | Lifecycle: reset session state |
| `before_reset` | — | Lifecycle: reset session state |
| `before_compaction` | — | Lifecycle: reset session state |

### Hook Context Types

```typescript
// before_tool_call / after_tool_call
PluginHookToolContext {
  agentId?, sessionKey?, sessionId?, runId?, toolName, toolCallId?
}
// ⚠ No messages, no conversation context

// before_prompt_build
PluginHookBeforePromptBuildEvent { prompt, messages[] }
PluginHookAgentContext { agentId?, sessionKey?, sessionId?, workspaceDir?, trigger?, channelId? }
// ✅ Full session messages + sessionKey

// llm_output
PluginHookAgentContext { agentId?, sessionKey?, ... }
```

### Startup Logging

On initialization, SecAgent logs (info level):
- LLM connection status (endpoint, model)
- Rule count, timeout policy
