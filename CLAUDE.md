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

The detailed architecture and design of SecLaw is documented in `docs/ARCHITECTURE.md`. Below is a high-level overview.

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

When a call is blocked, a 6-digit decimal PIN is generated and included in the `blockReason` text. Trusted senders (`config.llm.trustedSenderLabels`) can reply `/pin<pin>` to unblock. The override is **turn-scoped** — it covers all tool calls of the same `toolName` within the same turn (until the next user message).

### Module map

| File | Role |
|------|------|
| `index.ts` | Plugin entry point. Exports `register(api)` for OpenClaw + `init()`/`beforeToolCall()`/`afterToolCall()` for standalone use. |
| `src/config.ts` | All type definitions (`SecLawConfig`, `Rule`, `IntentContext`, `PendingOverride`, etc.) and defaults. |
| `src/rule-engine.ts` | Sigma-style rule engine: classify() entry point, delegates to detection-compiler + rule-index. |
| `src/detection-compiler.ts` | Compiles detection blocks: selections, field modifiers, condition expressions (AND/OR/NOT). |
| `src/rule-resolver.ts` | YAML parsing, list/macro expansion → SigmaRule[]. |
| `src/rule-index.ts` | Tool + platform indexing for fast rule candidate selection. |
| `src/field-registry.ts` | Resolves dotted field paths (cmd.*, url.*, file.*). |
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
| `src/dashboard/sender-labels.ts` | Sender label registry (scan JSONL logs, persist to JSON). |
| `src/hardening/` | Security checker (8 domains, 29 checks, A-F scoring) + 14 hardening actions + 3 agent-callable tools (`security_scan`, `security_harden`, `security_report`). |

### Rules

Default rules live in 3 files: `rules/default.yaml` (cross-platform), `rules/unix.yaml` (Linux/macOS), `rules/windows.yaml` (Windows). Platform-specific files are loaded automatically based on `os.platform()`. Workspace-specific rules go in `.openclaw/seclaw-rules.yaml`. Extra rules can also be passed via `config.rules.extra`.

Rule IDs follow prefixes: `CAT-` (catastrophic, priority 9000-10000), `TOOL-Y-` (always-RED tools), `SAFE-` (known-safe patterns), `PARAM-Y-` / `PARAM-G-` (parameter-level classification), `TOOL-G-` (always-GREEN tools).

### Plugin registration

`register(api: OpenClawPluginApi)` hooks into: `before_tool_call` (priority 9999), `after_tool_call` (100), `before_prompt_build`, `llm_input`, `session_start`, `before_reset`, `before_compaction`.

The `OpenClawPluginApi` provides: `on()` for hook registration, `logger` (with `info`/`warn`/`error`/`debug?`, single-string signatures) for output routing, `pluginConfig` for seclaw settings, `config.workspace.dir` for workspace path. `emitAgentEvent` was removed in OpenClaw 3.23; SecLaw handles its absence via null guard.

### Dashboard

SecLaw starts a local web dashboard on `http://127.0.0.1:19198` by default (configurable via `dashboard` config). The dashboard provides real-time audit log viewing with SSE push, runtime config editing, security scanning/hardening (Health tab), and rule file management with inline editing (Rules tab, dual-mode: Rule Files + Effective Rules). Supports optional `dashboard.token` (Bearer auth) and `dashboard.password` (cookie-based browser login); default is open access. Controlled by `dashboard.enabled` (default `true`). Uses `node:http` with zero external dependencies. `server.unref()` ensures it doesn't block process exit.

## Workflow rules

- **Git backup**: After each code update, create a git commit to checkpoint progress.
- **Sync ARCHITECTURE.md**: When architecture-relevant changes are made (new modules, flow changes, hook changes, config changes, override mechanism updates, etc.), update `docs/ARCHITECTURE.md` to reflect the current state.

## Key patterns

- **Dual entry paths**: `register(api)` for production (OpenClaw runtime), `init(ctx)` + direct hook calls for testing
- **Session state is a singleton** (`sessionState`): all modules import from `src/session-state.ts`
- **User messages include metadata blocks**: `Sender (untrusted metadata):\n\`\`\`json\n...\n\`\`\`` — parsed by `parseUserMessage()` in `intent-context.ts` to extract `senderLabel`
- **Config schema**: `openclaw.plugin.json` must stay in sync with `SecLawConfig` in `src/config.ts`
- **Tests mock the LLM**: Integration tests pass a `vi.fn()` as `llmCall` to `init()`, controlling SAFE/DANGER responses
