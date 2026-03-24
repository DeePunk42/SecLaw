# SecLaw Architecture

## Overview

SecLaw is a real-time security audit layer for AI Agent tool calls in OpenClaw. It implements a **unified rule engine** that classifies every tool call into one of three tiers:

- **GREEN** — Allow execution immediately, no audit at all
- **YELLOW** — Allow execution immediately, run async LLM audit in background
- **RED** — Run synchronous LLM audit before execution

**Default behavior: no matching rule → YELLOW (allow + async audit).**

## Architecture Flow

```
User Message
  │
  ├─ Intent tracking (via before_prompt_build hook)
  │   └─ Updates userGoal / channelId / trigger / agentId / messageProvider
  │
  ├─ Override detection (if trustedSenderLabels configured)
  │   └─ /pin<pin> from trusted sender → activate override
  │
Tool Call (before_tool_call)
  │
  ├─ Active override check (turn-scoped, same toolName)
  │   └─ If active → ALLOW immediately, skip all audit
  │
  ├─ Danger flag check (from previous async audit)
  │   └─ If set → BLOCK + register override PIN
  │
  └─ Rule Engine: classify(toolName, params, intentCtx, wsPath) → GREEN / YELLOW / RED
      │
      ├─ GREEN → Allow execution (silent, no audit)
      │
      ├─ YELLOW → Allow execution
      │   └─ afterToolCall → Async audit queue (skipped for override-approved calls)
      │       └─ Re-classify → If not GREEN → LLM audit
      │           └─ DANGER → Set danger flag (blocks next call)
      │
      └─ RED → Determine sender trust → Synchronous LLM audit
          │
          ├─ Trusted sender → Intent-alignment prompt
          │   ├─ SAFE → Allow execution
          │   └─ DANGER → BLOCK + override PIN
          │
          └─ Untrusted sender → Security-safety prompt
              ├─ SAFE → Allow execution
              └─ DANGER → BLOCK (no override, no PIN)
```

## Module Structure

```
index.ts                    Plugin entry point, hook registration, provider resolution,
                            config persistence, runtime config update.
                            getDirname() resolves the package root: when running
                            from dist/, it ascends one level so rules/ and other
                            assets are found. bootstrapManagedRules() also has a
                            fallback to check ../rules/ if pluginDir/rules/ is missing.
src/
  config.ts                 Type definitions (SigmaRule, CompiledRule, MatchContext, Platform, etc.)
  rule-engine.ts            Sigma-style rule engine: loads/compiles/indexes rules, classify()
  detection-compiler.ts     Compiles detection blocks: selection matching, field modifiers,
                            condition expressions (AND/OR/NOT, 1 of sel_*, all of sel_*)
  rule-resolver.ts          YAML parsing → list/macro expansion → SigmaRule[]
  rule-index.ts             Tool + platform indexing for fast candidate selection
  field-registry.ts         FieldRegistry: resolves dotted field paths (cmd.primary, url.host, etc.)
  llm-auditor.ts            LLM audit: prompt construction, API call, response parsing
  async-audit-queue.ts      Background audit queue with deduplication
  audit-log.ts              Console + JSONL logging, log level filtering, subscriber pattern
  intent-context.ts         Intent accumulator (userGoal, message source, tool calls)
  session-state.ts          Per-session state manager (danger flags, audit cache, override state)
  interrupt.ts              Danger flag management, interrupt mechanism
  patterns/
    command-patterns.ts     splitCommandChain() + extractPrimaryCommand() + decomposeCommand()
    path-patterns.ts        decomposePath() + isPathInWorkspace()
    url-patterns.ts         decomposeURL() + isPrivateIP()
  dashboard/
    server.ts               Gateway route handler + standalone server lifecycle
    api.ts                  REST API + SSE endpoint handlers
    html.ts                 Embedded SPA frontend (dark theme, 4 tabs)
    sender-labels.ts        Sender label registry (scan JSONL logs, persist to JSON)
rules/
  default.yaml              Cross-platform rules (tools, URLs, file writes)
  unix.yaml                 Linux/macOS rules (exec commands, shell patterns)
  windows.yaml              Windows rules (cmd.exe, PowerShell patterns)
```

## Rule Engine (Sigma-Style)

### Design Principles

- **Engine does field extraction and pattern matching; security judgments live in rules**
- **`tool` is the primary routing field** (OpenClaw tool names: exec, write, web_fetch, etc.)
- **`command` refers only to exec tool's shell command content**
- Computed fields provide "raw decomposition" and "RFC-level facts" only
- Two exceptions kept as computed fields: `url.isPrivateIP` (RFC 1918 fact) and `file.inWorkspace` (runtime-dependent)

### Compilation Pipeline

```
YAML Files (default.yaml + unix.yaml / windows.yaml)
  ↓ RuleResolver
  ↓   ├ Parse lists: → Map<string, string[]>
  ↓   ├ Expand $list:name in tool arrays
  ↓   └ Normalize SigmaRule[]
  ↓
SigmaRule[]
  ↓ DetectionCompiler
  ↓   ├ Parse selection field|modifier → matcher functions
  ↓   ├ Parse condition expressions → boolean combinators
  ↓   └ Pre-compile regexes (handles (?i) → case-insensitive flag)
  ↓
CompiledRule[]
  ↓ RuleIndex
  ↓   ├ Index by tool name
  ↓   └ Filter by platform
  ↓
Ready for classify()
```

### Rule Structure (Sigma-Style)

```yaml
lists:
  dangerous_cmds: [mkfs, dd, nc, ncat, netcat, eval]
  safe_cmds: [git, npm, yarn, pnpm, bun]

rules:
  - id: CAT-RM-SYSTEM
    name: Recursive delete system directories
    tool: [exec, bash]              # OpenClaw tool names
    platform: [linux, macos]        # Optional platform filter
    tier: RED
    priority: 10000
    reason: "Recursive delete targeting system directory"
    tags: [destructive, data_loss]
    detection:
      selection:
        command|re: "rm\\s+.*-rf\\s+/"
      condition: selection
```

### Detection Syntax

**Selection** — field:value mappings (multiple fields = AND):
```yaml
detection:
  sel_rm:
    command|re: "rm\\s+-rf"     # regex match
    file.inWorkspace: false      # boolean match
  condition: sel_rm
```

**Field Modifiers**: `|re` (regex), `|contains`, `|startswith`, `|endswith`, `|all`

**Array field matching** (`cmd.all`, `cmd.segments`): any element match = true

**Condition expressions**: `and`, `or`, `not`, parentheses, `1 of sel_*`, `all of sel_*`

### Field System

**Raw Param Fields**: `command`, `path`, `url`, `action`, `host`, `elevated`, `content`, `query`

**Command Decomposition** (`cmd.*`, exec tool only):
- `cmd.primary` — first command, skipping wrappers
- `cmd.all` — all commands in chain (split by `|`, `&&`, `||`, `;`)
- `cmd.segments` — full raw segments

**File Decomposition** (`file.*`):
- `file.dir`, `file.name`, `file.ext`
- `file.inWorkspace` — runtime computed

**URL Decomposition** (`url.*`):
- `url.host`, `url.port`, `url.path`, `url.scheme`
- `url.isPrivateIP` — RFC 1918 fact

**Extension fields**: `ext.*` for future features (e.g., script detection)

### Multi-File Rule Loading

Rules are loaded from multiple YAML files and merged:
1. **Active rule file** (default: `default.yaml`) — cross-platform shared rules
2. **Platform-specific file** — `unix.yaml` on Linux/macOS, `windows.yaml` on Windows

Platform detection uses `os.platform()` → `linux`, `macos`, or `windows`.

### Priority Tiers

| Range | Tier | Description |
|-------|------|-------------|
| 9000-10000 | RED | Catastrophic patterns (rm -rf /, pipe-to-shell, credential theft) |
| 8000-8500 | RED | Always-RED tools, elevated exec |
| 7000-7500 | GREEN/YELLOW | Known-safe patterns (git, npm → GREEN; workspace rm, docker → YELLOW) |
| 6000-6500 | RED | Parameter-level RED (dangerous commands, sensitive files, SSRF) |
| 5000-5500 | GREEN | Always-GREEN tools (read, web_search, memory_*) |
| 4000-4500 | YELLOW | Parameter-level YELLOW (non-dangerous commands, safe paths) |
| 0 | YELLOW | Default fallback — no rule matched |

**Key design principle:** GREEN safe patterns (7000+) override parameter-level RED (6000+), ensuring `git status` and `npm install` are not over-classified. Catastrophic RED (9000+) always wins.

## Intent Context

SecLaw tracks agent intent per session to provide LLM auditors with context about what the agent is doing and why.

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

When a tool call is blocked (sync DANGER, async danger flag, or fail_closed policy), a 6-digit decimal PIN is generated and included in the `blockReason`. Trusted senders can reply `/pin<pin>` to unblock the operation.

### Trust Determination

Trust is resolved by `isSenderTrusted()` based on `senderLabel`:

| senderLabel | Condition | Trust | Rationale |
|-------------|-----------|-------|-----------|
| `null` / `undefined` | No Sender metadata block | **Trusted** | Direct operator session, system trigger (cron/heartbeat/memory), or adapter without Sender support — no multi-user channel threat |
| Present | In `trustedSenderLabels` | **Trusted** | Known operator in multi-user channel |
| Present | NOT in `trustedSenderLabels` | **Untrusted** | Unknown user in multi-user channel |

The same logic applies to `/pin` override consumption in `onUserMessage()`: when `senderLabel` is absent, `/pin` commands are accepted (consistent with trust determination).

### Flow

1. **Block** — `beforeToolCall` returns `{ block: true, blockReason }`. Trust is determined before the LLM call. **Trusted**: `registerPendingOverride()` is called, PIN is shown in hint. **Untrusted**: no override is registered, no PIN — the block is final
2. **User confirms** — Sends `/pin<pin>` via text input
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

### Trust-Branched Prompts

Sender trust is determined **before** the LLM call (via `isSenderTrusted()` in code — see [Trust Determination](#trust-determination)). Two separate prompt templates are used:

| Sender | Prompt | Focus | DANGER means |
|--------|--------|-------|-------------|
| Trusted (senderLabel absent OR in trustedSenderLabels) | `TRUSTED_AUDIT_PROMPT` ("intent-alignment auditor") | Does this align with the user's goal? | Severe intent deviation + serious potential harm (high bar) |
| Untrusted (senderLabel present but NOT in trustedSenderLabels) | `UNTRUSTED_AUDIT_PROMPT` ("security auditor") | Is this operation safe? | Data loss, credential leakage, unauthorized access |

Both prompts include:
- User goal (truncated to 500 chars) and sender label
- Recent tool call history (last N, default 3; configurable via `llm.promptRecentCalls`)
- Operation details (tool name, compact JSON parameters truncated to 500 chars)
- **Rule context** (when triggered by a named rule)

Trusted prompt guidance explicitly tells the model to default to SAFE for minor mismatch/ambiguity and only output DANGER when severe intent misalignment and serious harm are both present.

The `trusted` flag is also included in the fingerprint cache key, so the same operation with different trust levels produces different cache entries.

### Rule Context Injection

When a rule triggers RED classification, its `ruleId` and `reason` are passed to the LLM:

```
## Security rule context
Rule CAT-001 flagged this operation: Recursive delete targeting system directory
Give extra weight to this warning.
```

### Fingerprint Caching

Each audit request is fingerprinted via SHA-256 of `{ toolName, params, userGoal, trusted }`. Identical requests within a 5-minute TTL return the cached decision without calling the LLM. The `trusted` flag ensures that the same operation with different trust levels gets separate cache entries.

### Concurrency Control

`llm.maxConcurrent` limits simultaneous LLM calls. When at capacity, the timeout policy determines the fallback decision.

### Timeout & Failure Policies

| Policy | Behavior |
|--------|----------|
| `fail_closed` | LLM timeout/failure → DANGER (block) |
| `fail_open` | LLM timeout/failure → SAFE (allow) |

### Error Classification & Retry

LLM errors are classified into categories with different handling strategies:

| Category | HTTP Status | Retryable | Behavior |
|----------|-------------|-----------|----------|
| `rate_limited` | 429 | Yes | Retry with backoff; triggers cooldown after threshold |
| `server_error` | 5xx | Yes | Retry with backoff |
| `auth_error` | 401, 403 | No | Fail immediately |
| `network_error` | DNS/connection | No | Fail immediately |
| `unknown_error` | — | No | Fail immediately (backward compatible with plain `Error`) |

**Retry logic** (in `LLMAuditor.callLLM()`):
1. Check cooldown — if active, return error result immediately (no LLM call)
2. Retry loop (0 to `maxRetries`):
   - Try LLM call → success resets consecutive 429 counter
   - On error: classify → if not retryable, return immediately
   - Rate limited: increment counter; if exceeds `cooldownThreshold`, activate cooldown
   - If not last attempt: sleep with exponential backoff (`initialBackoffMs * 2^attempt`)
3. All retries exhausted → return error result

**Cooldown mechanism**: After `cooldownThreshold` consecutive 429 errors, all LLM calls are skipped for `cooldownMs` (default 30s). This prevents sustained request storms during rate limiting. `isCoolingDown()` and `resetCooldown()` are public for monitoring and testing.

**Error results**: When an error occurs, `LLMAuditResult._errorInfo` is populated with the error category, status code, and message. The `decision` field follows `syncTimeoutPolicy` (DANGER for fail_closed, SAFE for fail_open).

**Service error vs security finding**: `beforeToolCall` checks `_errorInfo` to distinguish service issues from actual LLM security evaluations:
- **Service errors** (rate_limited, auth_error, server_error, network_error): block/allow per `syncTimeoutPolicy`, no override PIN (overriding a service issue is meaningless), clear `[SERVICE UNAVAILABLE]` or `[WARNING]` message asking the agent to stop
- **Security findings** (actual DANGER from LLM): block with override PIN (existing flow)
- **Async audit service errors**: silently skipped — do not set danger flag (prevents false interrupts)

**Configuration** (`llm.retry`):
```json
{
  "maxRetries": 2,
  "initialBackoffMs": 1000,
  "cooldownMs": 30000,
  "cooldownThreshold": 3
}
```

**Gateway integration**: `createGatewayLLMCallFn()` throws `LLMHttpError` (extends `Error`, carries `statusCode` and `retryAfterMs`) instead of plain `Error`. For 429 responses, the `Retry-After` header is parsed and passed through.

## Async Audit Queue

After every tool call (`afterToolCall`), the operation is checked:

1. **GREEN → skip**: no audit at all
2. **YELLOW/RED → enqueue** for background audit
3. **Deduplication**: fingerprint-based, skips already-queued identical operations
4. **Re-classification**: runs `ruleEngine.classify()` again
5. **GREEN → skip**: no further audit needed
6. **YELLOW/RED → LLM audit**: runs with `auditTimeoutMs` timeout
7. **DANGER → interrupt**: sets per-session danger flag, emits `security` event

The danger flag blocks **all subsequent tool calls** for that session until the session is reset.

When this async danger-flag block triggers, the returned `blockReason` uses a dedicated agent-facing message that explicitly instructs the model to stop the current call immediately. Trusted senders still receive the existing override hint with `/pin<pin>` appended in the override section.

## Logging

### Console Output

Controlled by `logging.level` (`debug` | `info` | `warn` | `error`):

| Level | What is logged |
|-------|---------------|
| debug | `🟢 GREEN exec(git status) -- no audit`, `🟡 YELLOW exec(ls) -- deferred to async audit`, intent context dump (RED path only), `LLM audit: skipped (disabled)`, intent extraction source |
| info | `🔴 RED exec(rm -rf /) -- requires sync audit`, `BLOCKED exec [sync] — reason`, `ALLOW exec — LLM audit → SAFE`, initialization messages |
| warn | `danger flag FOUND — blocking all subsequent calls` |
| error | `DANGER exec [async] rule=CAT-001 — reason` |

A GREEN tool call produces **no output** (silent). A YELLOW tool call produces **1 line** of debug output (the classification). A RED tool call with LLM audit produces **~10 lines** of debug output (classification + intent context dump + final decision).

### JSONL File

When `logging.auditJsonl: true`, structured events are written to `seclaw-audit.jsonl`:

| Event Type | Trigger |
|------------|---------|
| `tool_classified` | Every tool call classification |
| `rule_matched` | When a named rule matches |
| `intent_context` | Intent context dump (RED path, debug level) |
| `llm_audit` | LLM audit result (sync or async) |
| `tool_blocked` | Tool call blocked |
| `tool_allowed` | Tool call allowed (RED path only) |
| `async_audit_enqueued` | Tool call enqueued for async audit |
| `async_audit_complete` | Async audit finished |
| `danger_detected` | Async audit found danger |
| `override_used` | Trusted sender override consumed |
| `llm_service_error` | LLM service error (429, 5xx, auth, network) |

All events carry a `toolCallId` field (when available) that links events from the same tool call together. The `toolCallId` comes from OpenClaw's `event.toolCallId` / `ctx.toolCallId`, or is generated via `crypto.randomUUID()` if not provided.

`tool_blocked` also carries `params` and `intentContext` when available. This ensures blocked cards keep full context even for early-stop paths that do not emit `tool_classified` / `intent_context` first (for example danger-flag preemption).

## LLM Gateway Connection

SecLaw uses provider resolution for the LLM audit endpoint:

### Provider Resolution (`provider/model` format)

When `llm.model` contains a slash (e.g. `"myapi/gpt-5.2"`), the provider is resolved from `api.config.models.providers`:

```typescript
resolveProviderEndpoint("myapi/gpt-5.2", api)
→ providers["myapi"].baseUrl + "/chat/completions"
→ { endpoint, apiKey: provider.apiKey, modelId: "gpt-5.2", providerName: "myapi", auth: provider.auth }
```

This is the primary mode in production — models are configured in the gateway's `openclaw.json` and presented in the dashboard model selector.

### Auth Profile Fallback

When a provider is **not** found in `models.providers`, `resolveProviderEndpoint()` falls back to:

1. **Read `auth.profiles`** from `openclaw.json` — find a profile where `provider` matches the requested provider name
2. **Resolve base URL** from `KNOWN_PROVIDER_BASE_URLS` — a static map of well-known OpenAI-compatible providers. Supports prefix matching (e.g. `"openai-codex"` → starts with `"openai"` → `https://api.openai.com/v1`)
3. **Return endpoint** with `auth` set to the profile's `mode` (typically `"oauth"`) and no `apiKey` (dynamic auth via `runtime.modelAuth`)

If the auth profile is found but the provider has no known base URL, resolution returns `null` (same as provider-not-found).

**Known provider URL map:**

| Prefix | Base URL |
|--------|----------|
| `openai` | `https://api.openai.com/v1` |
| `deepseek` | `https://api.deepseek.com` |
| `mistral` | `https://api.mistral.ai/v1` |
| `groq` | `https://api.groq.com/openai/v1` |
| `together` | `https://api.together.xyz/v1` |
| `fireworks` | `https://api.fireworks.ai/inference/v1` |
| `perplexity` | `https://api.perplexity.ai` |
| `xai` | `https://api.x.ai/v1` |

**Precedence:** `models.providers` always takes priority. Auth profile lookup only happens when the provider is absent from `models.providers`.

### Call-time Re-resolution

`createGatewayLLMCallFn()` re-resolves the provider at call time (not just at creation time), so runtime model changes via the dashboard take effect immediately without recreating the call function closure.

### Auth Resolution

Auth is resolved **per-call** inside `createGatewayLLMCallFn()`, with a 4-level priority order:

1. **Explicit `config.llm.apiKey`** — if set in SecLaw plugin config, used directly as `Bearer` token. This is the highest-priority override, bypassing all provider-level auth. The key is never persisted to `openclaw.json` (stripped before writing). Set via dashboard `PUT /api/config` or environment-injected plugin config.
2. **Runtime auth resolution** — `api.runtime?.modelAuth?.resolveApiKeyForProvider({ provider, cfg })` handles all provider-level auth internally: static API keys, auth profiles, OAuth token refresh, file-based secrets (JSON pointer / RFC 6901), and environment variables. SecLaw delegates entirely to the runtime for provider auth resolution. For `oauth`/`token` auth modes, failure or empty result throws `LLMHttpError(401)`.
3. **`SECLAW_API_KEY` env var** — if the runtime resolver is unavailable or returns empty (for non-oauth providers), the `SECLAW_API_KEY` environment variable is used as a last-resort fallback.
4. **No auth available** — if none of the above produces a key, the request proceeds without an `Authorization` header (for local/unauthenticated providers like Ollama).

The `runtime` field on `OpenClawPluginApi` is optional. The gateway populates it when providers are configured:

```typescript
runtime?: {
  modelAuth?: {
    resolveApiKeyForProvider: (params: { provider: string; cfg?: Record<string, unknown> }) =>
      Promise<{ apiKey?: string; source: string; mode: string }>
  }
}
```

Provider config also supports an `auth` field to declare the auth mode:

```typescript
providers: {
  "openai-codex": {
    baseUrl: "https://api.openai.com/v1",
    auth: "oauth",  // "api-key" | "oauth" | "token" | "aws-sdk"
    models: [{ id: "codex-v1", name: "Codex" }]
  }
}
```

### Validation

- `updateConfig()` rejects model changes to OAuth/token providers when `runtime.modelAuth` is not available
- `register()` logs a warning when an OAuth provider has no static key and no runtime auth

### API Surface Payloads

`buildRequestPayload()` constructs the request body based on the resolved API surface:

| API Surface | Payload Fields | Notes |
|---|---|---|
| `openai-completions` | `{ model, messages, max_tokens }` | Standard Chat Completions format |
| `openai-responses` | `{ model, input, max_output_tokens }` | OpenAI Responses API; `instructions` optional, omitted |
| `openai-codex-responses` | `{ model, instructions, input, store, stream }` | Codex API requires `instructions`; `store: false`, `stream: true`; no `max_output_tokens` |

**Codex `instructions` handling**: The Codex backend API (`chatgpt.com/backend-api/codex/responses`) requires an `instructions` field. `buildRequestPayload()` extracts the first `system`-role message from the messages array and uses its content as `instructions`. If no system message is present, a default `"You are a helpful assistant."` is used. System messages are excluded from the `input` array.

**Surface override for SecLaw calls**: `createGatewayLLMCallFn()` overrides the API surface for non-codex providers, forcing them to `/chat/completions` to avoid constraints that SecLaw's simple audit calls cannot satisfy. Codex providers keep their native `/codex/responses` endpoint with `stream: true` in the payload; the SSE response is parsed by `parseSSEResponse()` which accumulates `response.output_text.delta` events and uses `response.completed` as fallback. The override uses `stripApiPath()` to remove any existing API path suffix before appending the target path. Auth resolution (`resolveBearerToken`) still uses the original transport since auth is provider-level, not surface-level.

### HTTP Call

```typescript
fetch(endpoint, {
  method: "POST",
  headers: { "Content-Type": "application/json", "Authorization": `Bearer ${bearerToken}` },
  body: JSON.stringify(buildRequestPayload(transport, params)),
});
```

The response is parsed based on API surface: Codex (`openai-codex-responses`) uses SSE stream parsing via `parseSSEResponse()`, Responses use `output_text` or `output[].content[].text`, Completions use `choices[0].message.content`.

## Config Persistence

Dashboard config changes are persisted directly into `~/.openclaw/openclaw.json` at `plugins.entries.seclaw.config`. `updateConfig()` writes file changes first; runtime config is applied only after successful persistence.

If `plugins.entries.seclaw` is missing, persistence auto-creates it. The deprecated field `llm.endpoint` is rejected. `llm.apiKey` is accepted at runtime but **stripped before persisting** to `openclaw.json` to avoid leaking secrets to disk.

### First-Install Bootstrap

On first install (all config empty), `register()` performs automatic initialization after `init()`:

1. **`varDir` creation** — `init()` calls `fs.mkdirSync(varDir, { recursive: true })` explicitly, rather than relying on the side effect of `bootstrapManagedRules()`. This ensures the directory exists even when `varDir` is overridden.
2. **`sender-labels.json` seeding** — `register()` calls `seedSenderLabels(varDir, config.llm.trustedSenderLabels)` which creates the file with default trusted labels (e.g. `"openclaw-control-ui"`) only if it doesn't already exist.
3. **`openclaw.json` persistence** — `register()` calls `persistConfigToOpenClaw(config)` to write the default config to disk. `persistConfigToOpenClaw()` handles a missing `openclaw.json` by starting from `{}` (ENOENT → empty object), and creates the `~/.openclaw/` directory if needed.
4. **Default rules** — `bootstrapManagedRules()` (called by `init()`) copies `rules/default.yaml` to `~/.openclaw/seclaw/rules/` if not already present.

The bootstrap calls (`seedSenderLabels`, `persistConfigToOpenClaw`) are in `register()` (not `init()`) to keep test isolation clean — tests call `init()` directly and don't want to write to `~/.openclaw/`.

### Module-level State

`index.ts` maintains several module-level variables that outlive individual hook calls:

| Variable | Purpose |
|----------|---------|
| `config` | Active runtime config singleton |
| `gatewayApi` | Gateway API reference (set in `register()`), used by `updateConfig()` for provider validation and llmCallFn recreation |
| `varDir` | Directory for sender label registry |
| `availableModelsProvider` | Lazy function returning model list from gateway providers |

## Configuration

```json
{
  "llm": {
    "model": "gpt-5",
    "enabled": true,
    "maxConcurrent": 2,
    "promptRecentCalls": 3,
    "trustedSenderLabels": ["openclaw-control-ui"],
    "apiKey": "sk-...",
    "retry": {
      "maxRetries": 2,
      "initialBackoffMs": 1000,
      "cooldownMs": 30000,
      "cooldownThreshold": 3
    }
  },
  "timeouts": {
    "auditTimeoutMs": 60000,
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
| CAT-001 | RED | 10000 | Catastrophic recursive delete (rm -rf /) |
| CAT-002 | RED | 10000 | Force remove root (--no-preserve-root) |
| CAT-003 | RED | 9500 | Pipe download to shell |
| CAT-004 | RED | 9500 | Data exfiltration via curl/wget |
| CAT-005 | RED | 9200 | Overwrite SSH config |
| CAT-006 | RED | 9100 | Overwrite shell profile |
| CAT-007 | RED | 9800 | Disk format/wipe |
| CAT-008 | RED | 9000 | Cron/at job creation |
| TOOL-Y-001..005 | RED | 8000 | Always-RED tools (fs_delete, fs_move, sessions_spawn, sessions_send, gateway) |
| SAFE-001 | YELLOW | 7500 | Workspace-scoped delete |
| SAFE-002 | GREEN | 7200 | Git operations |
| SAFE-003 | GREEN | 7200 | Package manager operations |
| SAFE-004 | YELLOW | 7100 | Docker safe operations |
| PARAM-Y-001 | RED | 6500 | Dangerous command detected |
| PARAM-Y-002 | RED | 6400 | Reads sensitive files |
| PARAM-Y-003 | RED | 6300 | Sensitive file write path |
| PARAM-Y-004..006 | RED | 6100-6200 | SSRF / metadata / credential URLs |
| TOOL-G-001..003 | GREEN | 5500 | Always-GREEN tools (read, web_search, memory_*) |
| PARAM-G-001 | YELLOW | 4500 | Non-dangerous exec command |
| PARAM-G-002 | YELLOW | 4000 | Non-sensitive file write |
| PARAM-G-003 | YELLOW | 4000 | External URL fetch |

## Writing Custom Rules

Add rules to `.openclaw/seclaw-rules.yaml` in your workspace:

```yaml
# Block terraform destroy
- id: CUSTOM-001
  name: Block terraform destroy
  toolMatch: [exec, bash]
  conditions:
    - type: command_matches
      pattern: "terraform\\s+destroy"
  tier: RED
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

SecLaw registers as an OpenClaw plugin via `register(api)`. All hooks use the typed lifecycle system `api.on()`. The `api.emitAgentEvent` function (if provided) is wired to `setEmitAgentEvent()` during `register()` to enable SSE events (async danger notifications). Note: `emitAgentEvent` was removed from the OpenClaw plugin API in 3.23; when absent, SSE notifications are safely skipped via null guard.

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

On initialization, SecLaw logs (info level):
- LLM connection status (endpoint, model)
- Rule count, timeout policy
- Dashboard URL (if enabled)

## Dashboard (Web UI)

SecLaw includes a built-in web dashboard for real-time monitoring and configuration.

### Gateway Route Integration

In production (OpenClaw 3.23+), the dashboard is served as a gateway route at `/plugins/seclaw/` using `api.registerHttpRoute()`:

```typescript
api.registerHttpRoute({
  path: "/plugins/seclaw",
  auth: "plugin",
  match: "prefix",
  handler: createDashboardRouteHandler(dashboardDeps, "/plugins/seclaw"),
});
```

`createDashboardRouteHandler(deps, basePath)` is the core request handler:
- Strips `basePath` prefix from incoming URLs (e.g. `/plugins/seclaw/api/logs` → `/api/logs`)
- Routes `/api/*` paths to `handleApiRequest()` (existing API handler, zero changes)
- Serves SPA HTML for all other paths via `getDashboardHtml(basePath)`, which rewrites `fetch('/api/...')` URLs to include the base path
- Returns `Promise<boolean>` for gateway compatibility

When `api.registerHttpRoute` is not available (older gateway), the standalone `http.Server` is used as fallback on port 19198.

### Standalone Server (Testing)

- `startDashboard(config, deps)` — internally uses `createDashboardRouteHandler(deps, "")` with empty basePath
- `stopDashboard()` — gracefully shuts down the server
- `server.unref()` ensures the server doesn't block process exit
- Controlled by `dashboard.enabled` config (default: `true`)

### API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/logs` | Recent audit log entries (query: `limit`, `tier`, `eventType`, `toolName`) |
| GET | `/api/logs/stream` | SSE real-time log stream (same filter params) |
| GET | `/api/tool-calls` | Aggregated ToolCallRecords (query: `limit`, `tier`, `toolName`) |
| GET | `/api/tool-calls/stream` | SSE real-time ToolCallRecord updates |
| GET | `/api/config` | Current config (apiKey masked as `"***"`) |
| PUT | `/api/config` | Update runtime config (endpoint blocked; apiKey accepted) |
| GET | `/api/health` | Health check (`{ status: "running" }`) |
| GET | `/api/rules` | `{ rules, platform }` — compiled rules with detection blocks |
| POST | `/api/rules/test` | Test tool call against rules: `{ toolName, params }` → `RuleResult` |
| GET | `/api/models` | Available models from gateway providers |
| GET | `/api/sender-labels` | Known sender labels (from persisted registry) |
| POST | `/api/sender-labels/refresh` | Scan JSONL audit logs for new sender labels |

### ToolCallRecord Aggregation

Events with the same `toolCallId` are aggregated into a `ToolCallRecord`:

```typescript
interface ToolCallRecord {
  toolCallId: string;
  sessionKey: string;
  toolName: string;
  startedAt: string;
  updatedAt: string;
  tier?: "GREEN" | "YELLOW" | "RED";
  finalStatus: "allowed" | "blocked" | "overridden" | "pending";
  syncAudit?: { decision, reason?, durationMs? };
  asyncAuditStatus?: "enqueued" | "complete";
  asyncAudit?: { decision, reason?, durationMs? };
  dangerDetected?: boolean;
  overridePin?: string;
  overrideUsed?: boolean;
  intentContext?: Record<string, unknown>;
  params?: Record<string, unknown>;
  events: AuditLogEntry[];  // all raw events for this call
}
```

The aggregation happens in `AuditLog.log()` — when an entry has a `toolCallId`, the corresponding `ToolCallRecord` is created or updated. Up to 500 records are kept in memory.

### ToolCallRecord Persistence

ToolCallRecords are persisted to `~/.openclaw/seclaw/logs/tool-calls.jsonl` for history across restarts:

- **Write**: After each `aggregateIntoToolCallRecord()` subscriber notification, the record (without `events[]`) is appended as a JSONL line
- **Load**: On startup, `initToolCallLog()` reads the file, deduplicates by `toolCallId` (last occurrence wins), and hydrates the in-memory map with the last 500 records (events set to `[]`)
- **No API changes**: Existing `getToolCallRecords()` returns the hydrated data transparently

`params` and `intentContext` are populated from both their primary events (`tool_classified`, `intent_context`) and `tool_blocked` fallback fields, so blocked records do not lose detail across different block paths.

### Dashboard Frontend (Grouped Card View)

The dashboard Audit Log tab shows tool calls as **grouped cards** in a 60/40 split layout:

- **Left panel (60%)**: scrollable card list. Each card shows relative time, tool name, tier badge, status label
- **Right panel (40%)**: fixed detail sidebar. Clicking a card highlights it (blue outline) and populates the sidebar with full detail phases (Rule Match, Intent Context, Sync Audit, Async Audit, Override, Params)
- Status labels: green "allowed", red "BLOCKED" (with PIN if override available), yellow "auditing..." with spinner, purple "OVERRIDDEN"
- Danger detection shows a red "DANGER" badge
- **Toolbar**: pill-style toggle buttons replace dropdowns
  - Tier pills: `ALL | GREEN | YELLOW | RED` (colored when active)
  - Status pills: `ALL | Blocked | Danger` (Blocked = `finalStatus === "blocked"`, Danger = `dangerDetected === true`)
  - Pause/Resume toggle + count display
- Cards update in-place via SSE (`/api/tool-calls/stream`), refreshing the sidebar if the selected card was updated

### Rules Tab (Two-Column Layout)

The Rules tab displays all compiled rules (merged from all rule files) in a 60/40 split layout:

- **Collapsible Rule Tester**: input tool name + JSON params → `POST /api/rules/test` → shows matched tier/rule/reason; clicking a matched rule scrolls to it in the list
- **Toolbar**: pill-style tier filter (`ALL | GREEN | YELLOW | RED`), rule count, file selector dropdown, Upload/Download/Save buttons
- **Left panel (60%)**: scrollable rule card list. Each card shows rule ID + tier badge, name, tool list, priority, platform tags
- **Right panel (40%)**: fixed detail sidebar showing full rule info (ID, name, tools, platform, priority, reason, tags, detection YAML)
- `CompiledRule` includes `detection?: DetectionBlock` for dashboard display
- `GET /api/rules` returns `{ rules, platform }` (rules include detection blocks)
- File operations (upload/download/save) use the existing `/api/rules/file/*` endpoints

### Config Editor

The Config tab provides a form-based editor for runtime config. Notable controls:

- **Model selector**: dropdown populated from `/api/models` (gateway providers)
- **trustedSenderLabels**: custom multi-select checkbox dropdown with "Select all" / "Clear" actions and a refresh button that scans audit logs for new sender labels via `/api/sender-labels/refresh`
- **Dashboard settings** (port/host/enabled): read-only, requires restart

### Dashboard Authentication

HTML/SPA pages are freely accessible without authentication. API endpoints (`/api/*`) require a Bearer token when configured.

**Token resolution priority** (in `register()`):
1. `dashboard.token` — explicit config value
2. `OPENCLAW_GATEWAY_TOKEN` environment variable — reuses the gateway token
3. No token → authentication disabled (all API endpoints open)

**Server-side** (`server.ts`):
- `DashboardDeps.getToken` is an optional field — when absent or returning `undefined`, auth is skipped (test-compatible)
- Bearer header (`Authorization: Bearer <token>`) is checked first; query param (`?token=xxx`) is a fallback for SSE `EventSource` (which does not support custom headers)
- Token comparison uses SHA-256 + `crypto.timingSafeEqual` to prevent timing attacks
- Failed auth returns `401 { error: { message: "Unauthorized", type: "unauthorized" } }`

**Client-side** (`html.ts`):
- Global `fetch` interceptor adds `Authorization` header to all `/api/` requests; on 401 response, triggers login overlay
- SSE `EventSource` passes token via `?token=` query parameter
- Token stored in `sessionStorage` (`seclaw_token` key) — survives page refresh within the tab, cleared on tab close
- Startup probe: on load, if no stored token, fetches `/api/health` — 401 triggers login overlay

### SSE Push Mechanism

- `AuditLog.subscribe(fn)` — callback for raw `AuditLogEntry` events
- `AuditLog.subscribeToolCalls(fn)` — callback for `ToolCallRecord` updates
- SSE endpoints send `data: {}` on connection, then `data: {json}` for each update
- 30-second heartbeat prevents connection timeout
- Cleanup on client disconnect via `req.on("close")`

### Runtime Config Update

`PUT /api/config` validates and applies changes to the running config:
- `logging` changes propagate to `auditLog.setLoggingConfig()`
- `timeouts` and `llm` settings update the config singleton and sync to `LLMAuditor.setConfig()`
- `llm.endpoint` is deprecated and rejected; `llm.apiKey` is accepted as an explicit override (stripped before persisting to disk)
- **Provider validation**: model changes in `"provider/model"` format are validated against `gatewayApi.config.models.providers` — unknown providers return 400
- **LLM call function recreation**: when `llm.model` changes, `createGatewayLLMCallFn()` is called again and the new function wired via `llmAuditor.setLLMCallFn()`
- **Enable toggle**: if `llm.enabled` is toggled from false to true, the call function is created on the spot
- **Config persistence**: changes are written to `~/.openclaw/openclaw.json` before runtime state is updated

### Audit Log Ring Buffer

`AuditLog` maintains a 500-entry ring buffer independent of JSONL file output:
- `subscribe(fn)` / `unsubscribe(fn)` — real-time subscriber pattern for raw entries
- `subscribeToolCalls(fn)` / `unsubscribeToolCalls(fn)` — real-time subscriber for aggregated records
- `getRecentEntries(limit?)` — returns buffered entries for initial page load
- `getToolCallRecords(limit?)` — returns aggregated records
- Buffer always active (even when `auditJsonl: false`)
