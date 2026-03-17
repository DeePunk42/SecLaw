# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run build          # TypeScript compilation → dist/
npm run lint           # Type-check without emitting (tsc --noEmit)
npm test               # Run all tests (vitest run)
npm run test:watch     # Watch mode

# Single test file
npx vitest run tests/override.test.ts

# Single test by name
npx vitest run -t "sync DANGER"

# Verification scripts (standalone, not vitest)
npx tsx scripts/verify.ts           # 11 core scenarios
npx tsx scripts/test-dangerous.ts   # 40+ comprehensive scenarios
```

## Architecture

The detailed architecture and design of SecLaw is documented in `ARCHITECTURE.md`. Below is a high-level overview.

SecLaw is an OpenClaw plugin that audits every AI agent tool call in real time. It classifies calls into three tiers:

- **GREEN** — Allow immediately, no audit at all
- **YELLOW** — Allow immediately, enqueue for background async audit
- **RED** — Block until synchronous LLM audit returns SAFE or DANGER
- No matching rule defaults to YELLOW

### Core flow (before_tool_call hook, priority 9999)

1. Check for **active override** (trusted sender confirmed a blocked operation)
2. Check for **danger flag** (set by prior async audit) → block if present
3. **Rule engine** classifies tool call → GREEN (allow, no audit) / YELLOW (allow, async audit) / RED (continue to step 4)
4. **Sync LLM audit** → SAFE (allow) or DANGER (block with override hint)

After tool execution (`after_tool_call`), YELLOW and RED calls are enqueued for async LLM audit. GREEN calls skip async audit entirely. If async audit returns DANGER, a danger flag is set that blocks the next tool call.

### Override mechanism

When a call is blocked, a 6-digit decimal PIN is generated and a `buttons` field is returned alongside `blockReason` for channel-agnostic inline button rendering (Telegram inline keyboard, Slack buttons, etc.). Trusted senders (`config.llm.trustedSenderLabels`) can reply `/pin<pin>` to unblock. The override is **turn-scoped** — it covers all tool calls of the same `toolName` within the same turn (until the next user message).

### Module map

| File | Role |
|------|------|
| `index.ts` | Plugin entry point. Exports `register(api)` for OpenClaw + `init()`/`beforeToolCall()`/`afterToolCall()` for standalone use. |
| `src/config.ts` | All type definitions (`SecLawConfig`, `Rule`, `IntentContext`, `PendingOverride`, etc.) and defaults. |
| `src/rule-engine.ts` | Loads YAML rules, matches tool calls using 12 condition types, returns tier + rule ID. |
| `src/llm-auditor.ts` | Builds audit prompts with intent context, calls LLM, parses SAFE/DANGER response. Fingerprint-based caching. |
| `src/async-audit-queue.ts` | Background queue with deduplication. Re-classifies via rule engine, then LLM audits YELLOW/RED items. |
| `src/session-state.ts` | Singleton `sessionState`. Per-session danger flags, intent context, audit cache, override state. |
| `src/intent-context.ts` | Accumulates user goal, sender label, message source from hook events. Detects `/pin` override commands. |
| `src/interrupt.ts` | Danger flag lifecycle, interrupt mechanism (`triggerInterrupt` for async danger SSE). |
| `src/audit-log.ts` | Console + JSONL structured logging, subscriber pattern + ring buffer. |
| `src/patterns/` | `command-patterns.ts`, `path-patterns.ts`, `url-patterns.ts` — used by rule engine condition matchers. |
| `src/dashboard/server.ts` | HTTP server lifecycle for the web dashboard (port 19198). |
| `src/dashboard/api.ts` | REST API + SSE endpoints (`/api/logs`, `/api/config`, `/api/health`, `/api/rules`). |
| `src/dashboard/html.ts` | Embedded SPA frontend (dark theme, 4 tabs: Audit Log, Config, Health, Rules). |

### Rules

Default rules live in `rules/default.yaml` (28+ rules, priority-ordered). Workspace-specific rules go in `.openclaw/seclaw-rules.yaml`. Extra rules can also be passed via `config.rules.extra`.

Rule IDs follow prefixes: `CAT-` (catastrophic, priority 9000-10000), `TOOL-Y-` (always-RED tools), `SAFE-` (known-safe patterns), `PARAM-Y-` / `PARAM-G-` (parameter-level classification), `TOOL-G-` (always-GREEN tools).

### Plugin registration

`register(api: OpenClawPluginApi)` hooks into: `before_tool_call` (priority 9999), `after_tool_call` (100), `before_prompt_build`, `llm_input`, `session_start`, `before_reset`, `before_compaction`.

The `OpenClawPluginApi` provides: `on()` for hook registration, `logger` for output routing, `pluginConfig` for seclaw settings, `emitAgentEvent` for SSE (async danger notifications only), `config.workspace.dir` for workspace path.

### Dashboard

SecLaw starts a local web dashboard on `http://127.0.0.1:19198` by default (configurable via `dashboard` config). The dashboard provides real-time audit log viewing with SSE push, runtime config editing, and placeholder tabs for health check and rule editing. Controlled by `dashboard.enabled` (default `true`). Uses `node:http` with zero external dependencies. `server.unref()` ensures it doesn't block process exit.

## Workflow rules

- **Git backup**: After each code update, create a git commit to checkpoint progress.
- **Sync ARCHITECTURE.md**: When architecture-relevant changes are made (new modules, flow changes, hook changes, config changes, override mechanism updates, etc.), update `ARCHITECTURE.md` to reflect the current state.

## Key patterns

- **Dual entry paths**: `register(api)` for production (OpenClaw runtime), `init(ctx)` + direct hook calls for testing
- **Session state is a singleton** (`sessionState`): all modules import from `src/session-state.ts`
- **User messages include metadata blocks**: `Sender (untrusted metadata):\n\`\`\`json\n...\n\`\`\`` — parsed by `parseUserMessage()` in `intent-context.ts` to extract `senderLabel`
- **Config schema**: `openclaw.plugin.json` must stay in sync with `SecLawConfig` in `src/config.ts`
- **Tests mock the LLM**: Integration tests pass a `vi.fn()` as `llmCall` to `init()`, controlling SAFE/DANGER responses
