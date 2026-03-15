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

SecAgent is an OpenClaw plugin that audits every AI agent tool call in real time. It classifies calls into two tiers:

- **GREEN** — Allow immediately, enqueue for background async audit
- **YELLOW** — Block until synchronous LLM audit returns SAFE or DANGER
- No matching rule defaults to GREEN

### Core flow (before_tool_call hook, priority 9999)

1. Check for **active override** (trusted sender confirmed a blocked operation)
2. Check for **danger flag** (set by prior async audit) → block if present
3. **Rule engine** classifies tool call → GREEN (allow) or YELLOW (continue to step 4)
4. **Sync LLM audit** → SAFE (allow) or DANGER (block with override hint)

After tool execution (`after_tool_call`), GREEN calls are enqueued for async LLM audit. If async audit returns DANGER, a danger flag is set that blocks the next tool call.

### Override mechanism

When a call is blocked, a 6-digit decimal PIN is generated. Trusted senders (`config.llm.trustedSenderLabels`) can reply `SEC_OVERRIDE:<pin>` to unblock. The override is **turn-scoped** — it covers all tool calls of the same `toolName` within the same turn (until the next user message). An SSE event (`override_available`) is also emitted for platforms with inline buttons (e.g. Telegram).

### Module map

| File | Role |
|------|------|
| `index.ts` | Plugin entry point. Exports `register(api)` for OpenClaw + `init()`/`beforeToolCall()`/`afterToolCall()` for standalone use. |
| `src/config.ts` | All type definitions (`SecAgentConfig`, `Rule`, `IntentContext`, `PendingOverride`, etc.) and defaults. |
| `src/rule-engine.ts` | Loads YAML rules, matches tool calls using 12 condition types, returns tier + rule ID. |
| `src/llm-auditor.ts` | Builds audit prompts with intent context, calls LLM, parses SAFE/DANGER response. Fingerprint-based caching. |
| `src/async-audit-queue.ts` | Background queue with deduplication. Re-classifies via rule engine, then LLM audits YELLOW items. |
| `src/session-state.ts` | Singleton `sessionState`. Per-session danger flags, intent context, audit cache, override state. |
| `src/intent-context.ts` | Accumulates user goal, sender label, message source from hook events. Detects `SEC_OVERRIDE` commands. |
| `src/interrupt.ts` | Danger flag lifecycle, `emitOverrideAvailable()`, SSE event emission. |
| `src/audit-log.ts` | Console + JSONL structured logging. |
| `src/patterns/` | `command-patterns.ts`, `path-patterns.ts`, `url-patterns.ts` — used by rule engine condition matchers. |

### Rules

Default rules live in `rules/default.yaml` (28+ rules, priority-ordered). Workspace-specific rules go in `.openclaw/sec-agent-rules.yaml`. Extra rules can also be passed via `config.rules.extra`.

Rule IDs follow prefixes: `CAT-` (catastrophic, priority 9000-10000), `TOOL-Y-` (always-YELLOW tools), `SAFE-` (known-safe patterns), `PARAM-Y-` / `PARAM-G-` (parameter-level classification), `TOOL-G-` (always-GREEN tools).

### Plugin registration

`register(api: OpenClawPluginApi)` hooks into: `before_tool_call` (priority 9999), `after_tool_call` (100), `before_prompt_build`, `llm_input`, `session_start`, `before_reset`, `before_compaction`.

The `OpenClawPluginApi` provides: `on()` for hook registration, `logger` for output routing, `pluginConfig` for sec-agent settings, `emitAgentEvent` for SSE, `config.workspace.dir` for workspace path.

## Workflow rules

- **Git backup**: After each code update, create a git commit to checkpoint progress.
- **Sync ARCHITECTURE.md**: When architecture-relevant changes are made (new modules, flow changes, hook changes, config changes, override mechanism updates, etc.), update `ARCHITECTURE.md` to reflect the current state.

## Key patterns

- **Dual entry paths**: `register(api)` for production (OpenClaw runtime), `init(ctx)` + direct hook calls for testing
- **Session state is a singleton** (`sessionState`): all modules import from `src/session-state.ts`
- **User messages include metadata blocks**: `Sender (untrusted metadata):\n\`\`\`json\n...\n\`\`\`` — parsed by `parseUserMessage()` in `intent-context.ts` to extract `senderLabel`
- **Config schema**: `openclaw.plugin.json` must stay in sync with `SecAgentConfig` in `src/config.ts`
- **Tests mock the LLM**: Integration tests pass a `vi.fn()` as `llmCall` to `init()`, controlling SAFE/DANGER responses
