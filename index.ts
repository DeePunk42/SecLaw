/**
 * SecAgent Plugin Entry Point
 *
 * Conforms to OpenClaw plugin API — exports a default object with
 * register(api) that uses api.on() to register hook handlers.
 *
 * Also exports init() / beforeToolCall() / afterToolCall() directly
 * for standalone testing without the full OpenClaw runtime.
 */

import crypto from "crypto";
import * as path from "path";
import { fileURLToPath } from "url";
import type { SecAgentConfig, LLMErrorInfo } from "./src/config.js";
import { loadConfig } from "./src/config.js";
import { RuleEngine } from "./src/rule-engine.js";
import { LLMAuditor, type LLMCallFn } from "./src/llm-auditor.js";
import { AuditLog } from "./src/audit-log.js";
import { AsyncAuditQueue } from "./src/async-audit-queue.js";
import { sessionState } from "./src/session-state.js";
import {
  consumeDangerFlag,
  formatDangerAlert,
  setEmitAgentEvent,
  resetSession,
  type EmitAgentEventFn,
} from "./src/interrupt.js";
import {
  getIntentContext,
  onToolCallComplete,
  onUserMessage,
  updateSource,
} from "./src/intent-context.js";
import { startDashboard, stopDashboard } from "./src/dashboard/server.js";

// ─── Types matching OpenClaw's real plugin system ───

/** OpenClaw PluginHookBeforeToolCallEvent */
export interface PluginHookBeforeToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
  runId?: string;
  toolCallId?: string;
}

/** OpenClaw PluginHookBeforeToolCallResult */
export interface PluginHookBeforeToolCallResult {
  params?: Record<string, unknown>;
  block?: boolean;
  blockReason?: string;
  /** Channel-agnostic button spec. Gateway renders per channel type. */
  buttons?: Array<Array<{ text: string; callback_data: string }>>;
}

/** OpenClaw PluginHookAfterToolCallEvent */
export interface PluginHookAfterToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
  runId?: string;
  toolCallId?: string;
  result?: unknown;
  error?: string;
  durationMs?: number;
}

/** OpenClaw PluginHookToolContext */
export interface PluginHookToolContext {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  runId?: string;
  toolName: string;
  toolCallId?: string;
  // Extended by SecAgent — not in upstream but consumed if present
  workspacePath?: string;
}

/** OpenClaw PluginHookBeforePromptBuildEvent */
export interface PluginHookBeforePromptBuildEvent {
  prompt: string;
  messages: unknown[];
}

/** OpenClaw PluginHookAgentContext (shared by before_prompt_build, llm_input, etc.) */
export interface PluginHookAgentContext {
  agentId?: string;
  sessionKey?: string;
  sessionId?: string;
  workspaceDir?: string;
  messageProvider?: string;
  trigger?: string;
  channelId?: string;
}

/** Minimal subset of OpenClawPluginApi used by SecAgent */
export interface OpenClawPluginApi {
  id: string;
  name: string;
  config: { workspace?: { dir?: string } } & Record<string, unknown>;
  pluginConfig?: Record<string, unknown>;
  logger: {
    info: (...args: unknown[]) => void;
    error: (...args: unknown[]) => void;
    debug?: (...args: unknown[]) => void;
  };
  on: (
    hookName: string,
    handler: (...args: any[]) => any,
    opts?: { priority?: number },
  ) => void;
  resolvePath: (input: string) => string;
  emitAgentEvent?: EmitAgentEventFn;
}

// ─── LLMHttpError ───

export class LLMHttpError extends Error {
  public readonly statusCode: number;
  public readonly retryAfterMs?: number;

  constructor(statusCode: number, statusText: string, retryAfterMs?: number) {
    super(`LLM endpoint returned ${statusCode}: ${statusText}`);
    this.name = "LLMHttpError";
    this.statusCode = statusCode;
    this.retryAfterMs = retryAfterMs;
  }
}

// ─── Plugin State ───

let ruleEngine: RuleEngine;
let llmAuditor: LLMAuditor;
let auditLog: AuditLog;
let asyncQueue: AsyncAuditQueue;
let config: SecAgentConfig;
let workspacePath: string | undefined;

// ─── Override helpers ───

function computeParamsFingerprint(toolName: string, params: Record<string, unknown>): string {
  return crypto.createHash("sha256")
    .update(toolName + ":" + JSON.stringify(params))
    .digest("hex");
}

function generatePin(): string {
  const n = crypto.randomInt(0, 1_000_000);      // 0–999999
  return String(n).padStart(6, "0");              // 6-digit decimal
}

function registerPendingOverride(
  sessionKey: string,
  toolName: string,
  params: Record<string, unknown>,
  toolCallId?: string,
): string {
  const pin = generatePin();
  sessionState.addPendingOverride(sessionKey, {
    pin,
    toolName,
    paramsFingerprint: computeParamsFingerprint(toolName, params),
    timestamp: Date.now(),
    toolCallId,
  });
  return pin;
}

function formatOverrideHint(pin: string): string {
  return [
    "",
    "--- Override ---",
    `If the user confirms this is intentional, they can reply with: SEC_OVERRIDE:${pin}`,
    "Explain the risk to the user and let them decide whether to proceed.",
  ].join("\n");
}

function overrideButtons(pin: string): Array<Array<{ text: string; callback_data: string }>> {
  return [
    [{ text: "⚠️ Confirm Override", callback_data: `SEC_OVERRIDE:${pin}` }],
  ];
}

// ─── Service Error Formatting ───

/** Module-level reference to agent event emitter (for SSE notifications). */
let emitAgentEventFn: EmitAgentEventFn | null = null;

function formatServiceErrorBlock(
  errorInfo: LLMErrorInfo,
  action: "blocked" | "allowed",
): string {
  const categoryLabel = {
    rate_limited: "rate limited",
    auth_error: "authentication error",
    server_error: "server error",
    network_error: "network error",
    unknown_error: "unknown error",
  }[errorInfo.category];
  const statusPart = errorInfo.statusCode ? ` (${errorInfo.statusCode})` : "";

  if (action === "blocked") {
    return [
      `[SecAgent] SERVICE UNAVAILABLE — LLM security audit could not be completed`,
      ``,
      `Error type: ${categoryLabel}${statusPart}`,
      `Details: ${errorInfo.message}`,
      ``,
      `This is NOT a security finding. The operation was BLOCKED because the audit service`,
      `is temporarily unavailable and the fail_closed policy is active.`,
      ``,
      `ACTION REQUIRED: Please STOP all tool execution immediately and inform the user:`,
      `  - The LLM security audit service is temporarily unavailable (${categoryLabel})`,
      `  - Tool calls requiring security audit cannot proceed`,
      `  - Please wait before resuming`,
    ].join("\n");
  }

  return [
    `[SecAgent] WARNING — LLM security audit skipped due to service error`,
    ``,
    `Error type: ${categoryLabel}${statusPart}`,
    `Details: ${errorInfo.message}`,
    ``,
    `The operation was ALLOWED (fail_open policy) but the security audit was NOT performed.`,
    ``,
    `ACTION REQUIRED: Please STOP all tool execution immediately and inform the user:`,
    `  - The LLM security audit service is temporarily unavailable`,
    `  - Subsequent tool calls will proceed WITHOUT security audit`,
    `  - The user should decide whether to continue without audit protection`,
  ].join("\n");
}

// ─── Standalone Init (for testing / direct use) ───

export interface PluginInitContext {
  config?: Partial<SecAgentConfig>;
  workspacePath?: string;
  pluginDir?: string;
  emitAgentEvent?: EmitAgentEventFn;
  llmCall?: LLMCallFn;
}

export function init(ctx: PluginInitContext): void {
  config = loadConfig(ctx.config);
  workspacePath = ctx.workspacePath;

  ruleEngine = new RuleEngine();
  const pluginDir = ctx.pluginDir || getDirname();
  const defaultRulesPath = path.join(pluginDir, "rules", "default.yaml");
  const workspaceRulesPath = ctx.workspacePath
    ? path.join(ctx.workspacePath, ".openclaw", "sec-agent-rules.yaml")
    : undefined;

  ruleEngine.loadRules({
    defaultRulesPath,
    workspaceRulesPath,
    extraRules: config.rules?.extra,
  });

  llmAuditor = new LLMAuditor(config.llm, config.timeouts);
  if (ctx.llmCall) {
    llmAuditor.setLLMCallFn(ctx.llmCall);
  }

  auditLog = new AuditLog(config.logging);
  const logDir = ctx.workspacePath
    ? path.join(ctx.workspacePath, ".openclaw", "logs")
    : path.join(pluginDir, "logs");
  auditLog.init(logDir);

  asyncQueue = new AsyncAuditQueue(ruleEngine, llmAuditor, auditLog, config);

  if (ctx.emitAgentEvent) {
    setEmitAgentEvent(ctx.emitAgentEvent);
    emitAgentEventFn = ctx.emitAgentEvent;
  }

  // Start dashboard if enabled (fire-and-forget, don't block init)
  if (config.dashboard?.enabled) {
    startDashboard(config.dashboard, {
      getConfig: () => config,
      updateConfig,
      getAuditLog: () => auditLog,
      getRuleEngine: () => ruleEngine,
      getAsyncQueue: () => asyncQueue,
    }).catch(() => {
      // Best-effort — dashboard failure shouldn't block the plugin
    });
  }
}

// ─── Runtime Config Update ───

function updateConfig(
  partial: Partial<SecAgentConfig>,
): { ok: boolean; errors?: string[] } {
  const errors: string[] = [];

  // Validate & apply llm changes
  if (partial.llm) {
    if (partial.llm.model !== undefined) {
      if (typeof partial.llm.model !== "string" || partial.llm.model.length === 0) {
        errors.push("llm.model must be a non-empty string");
      }
    }
    if (partial.llm.enabled !== undefined) {
      if (typeof partial.llm.enabled !== "boolean") {
        errors.push("llm.enabled must be a boolean");
      }
    }
    if (partial.llm.maxConcurrent !== undefined) {
      if (typeof partial.llm.maxConcurrent !== "number" || partial.llm.maxConcurrent < 1 || partial.llm.maxConcurrent > 10) {
        errors.push("llm.maxConcurrent must be a number between 1 and 10");
      }
    }
    if (partial.llm.trustedSenderLabels !== undefined) {
      if (!Array.isArray(partial.llm.trustedSenderLabels)) {
        errors.push("llm.trustedSenderLabels must be an array of strings");
      }
    }
  }

  // Validate & apply timeout changes
  if (partial.timeouts) {
    if (partial.timeouts.syncAuditMs !== undefined) {
      if (typeof partial.timeouts.syncAuditMs !== "number" || partial.timeouts.syncAuditMs < 1000 || partial.timeouts.syncAuditMs > 120000) {
        errors.push("timeouts.syncAuditMs must be between 1000 and 120000");
      }
    }
    if (partial.timeouts.asyncAuditMs !== undefined) {
      if (typeof partial.timeouts.asyncAuditMs !== "number" || partial.timeouts.asyncAuditMs < 1000 || partial.timeouts.asyncAuditMs > 120000) {
        errors.push("timeouts.asyncAuditMs must be between 1000 and 120000");
      }
    }
    if (partial.timeouts.syncTimeoutPolicy !== undefined) {
      if (partial.timeouts.syncTimeoutPolicy !== "fail_closed" && partial.timeouts.syncTimeoutPolicy !== "fail_open") {
        errors.push("timeouts.syncTimeoutPolicy must be 'fail_closed' or 'fail_open'");
      }
    }
  }

  // Validate & apply logging changes
  if (partial.logging) {
    if (partial.logging.level !== undefined) {
      if (!["debug", "info", "warn", "error"].includes(partial.logging.level)) {
        errors.push("logging.level must be one of: debug, info, warn, error");
      }
    }
    if (partial.logging.auditJsonl !== undefined) {
      if (typeof partial.logging.auditJsonl !== "boolean") {
        errors.push("logging.auditJsonl must be a boolean");
      }
    }
  }

  if (errors.length > 0) return { ok: false, errors };

  // Apply changes
  if (partial.llm) {
    config.llm = { ...config.llm, ...partial.llm };
  }
  if (partial.timeouts) {
    config.timeouts = { ...config.timeouts, ...partial.timeouts };
  }
  if (partial.logging) {
    config.logging = { ...config.logging, ...partial.logging };
    auditLog.setLoggingConfig(config.logging);
  }

  return { ok: true };
}

// ─── Hook Handlers ───

export async function beforeToolCall(
  event: PluginHookBeforeToolCallEvent,
  ctx: PluginHookToolContext,
): Promise<PluginHookBeforeToolCallResult | undefined> {
  const { toolName, params } = event;
  const sessionKey = ctx.sessionKey ?? "default";
  const wsPath = ctx.workspacePath ?? workspacePath;
  const toolCallId = event.toolCallId ?? ctx.toolCallId ?? crypto.randomUUID();
  sessionState.setLastToolCallId(sessionKey, toolCallId);

  auditLog.logBeforeToolCallStart(sessionKey, toolName, params);

  // 0. Check for active override grant (matches by toolName; fingerprint kept for audit only)
  if (sessionState.consumeActiveOverride(sessionKey, toolName)) {
    auditLog.logOverrideUsed(sessionKey, toolName, toolCallId);
    // Backtrack: also mark the original blocked card as overridden
    const activePin = sessionState.getActiveOverridePin(sessionKey);
    if (activePin) {
      const pending = sessionState.getPendingOverride(sessionKey, activePin);
      if (pending?.toolCallId && pending.toolCallId !== toolCallId) {
        auditLog.logOverrideUsed(sessionKey, toolName, pending.toolCallId);
      }
    }
    consumeDangerFlag(sessionKey);  // clear any lingering danger flag
    return undefined;  // allow
  }

  // 1. Check for danger flag from async audit
  const dangerReport = consumeDangerFlag(sessionKey);
  auditLog.logDangerFlagCheck(sessionKey, !!dangerReport);
  if (dangerReport) {
    const blockReason = formatDangerAlert(dangerReport);
    const pin = registerPendingOverride(sessionKey, toolName, params, toolCallId);
    auditLog.logBlock(sessionKey, toolName, blockReason, "async", toolCallId, pin);
    return {
      block: true,
      blockReason: blockReason + formatOverrideHint(pin),
      buttons: overrideButtons(pin),
    };
  }

  // 2. Classify via unified rule engine
  const intentCtx = getIntentContext(sessionKey);
  const ruleResult = ruleEngine.classify(toolName, params, intentCtx, wsPath);

  if (ruleResult.ruleId) {
    auditLog.logRuleMatch(sessionKey, toolName, ruleResult.ruleId, ruleResult.tier, ruleResult.reason, toolCallId);
  } else {
    auditLog.logNoRuleMatch(sessionKey, toolName);
  }

  auditLog.logClassification(sessionKey, toolName, params, ruleResult.tier, toolCallId);

  // 3. GREEN → allow execution, no audit at all
  if (ruleResult.tier === "GREEN") {
    return undefined;
  }

  // 4. YELLOW → allow execution, afterToolCall will handle async audit
  if (ruleResult.tier === "YELLOW") {
    auditLog.logIntentContext(sessionKey, toolName, intentCtx, config.llm.promptRecentCalls, toolCallId);
    return undefined;
  }

  // 5. RED → synchronous LLM audit with rule context
  if (!config.llm.enabled) {
    // LLM disabled — apply timeout policy
    if (config.timeouts.syncTimeoutPolicy === "fail_closed") {
      const reason = `RED operation blocked: LLM audit disabled (fail_closed policy)`;
      const pin = registerPendingOverride(sessionKey, toolName, params, toolCallId);
      auditLog.logBlock(sessionKey, toolName, reason, "sync", toolCallId, pin);
      return {
        block: true,
        blockReason: `[SecAgent] ${reason}` + formatOverrideHint(pin),
        buttons: overrideButtons(pin),
      };
    }
    auditLog.logLLMSkipped(sessionKey, toolName);
    auditLog.logAllow(sessionKey, toolName, "LLM disabled, RED → pass-through (fail_open)", toolCallId);
    return undefined;
  }

  auditLog.logLLMAuditStart(sessionKey, toolName);
  auditLog.logIntentContext(sessionKey, toolName, intentCtx, config.llm.promptRecentCalls, toolCallId);
  const startTime = Date.now();
  const ruleContext = ruleResult.ruleId
    ? { ruleId: ruleResult.ruleId, reason: ruleResult.reason }
    : undefined;
  const llmResult = await llmAuditor.auditWithTimeout(
    {
      toolName,
      params,
      intentContext: intentCtx,
      sessionKey,
    },
    undefined,
    ruleContext,
  );
  const durationMs = Date.now() - startTime;

  auditLog.logLLMAudit(sessionKey, toolName, llmResult.decision, llmResult.reason, durationMs, toolCallId);
  auditLog.logLLMAuditDetail(sessionKey, toolName, llmResult, durationMs);

  // Service error: not a security finding — handle separately
  if (llmResult._errorInfo && llmResult._errorInfo.category !== "unknown_error") {
    const errorInfo = llmResult._errorInfo;
    auditLog.logLLMServiceError(sessionKey, toolName, errorInfo, toolCallId);
    const shouldBlock = llmResult.decision === "DANGER"; // determined by syncTimeoutPolicy

    // SSE notification for dashboard
    if (emitAgentEventFn) {
      emitAgentEventFn({
        stream: "security",
        data: {
          type: "llm_service_error",
          sessionKey,
          toolName,
          errorCategory: errorInfo.category,
          blocked: shouldBlock,
          timestamp: Date.now(),
        },
      });
    }

    if (shouldBlock) {
      // fail_closed: block the tool call (no override — this isn't a security finding)
      const blockReason = formatServiceErrorBlock(errorInfo, "blocked");
      auditLog.logBlock(sessionKey, toolName, blockReason, "sync", toolCallId);
      return { block: true, blockReason };
    } else {
      // fail_open: allow but warn the agent to stop
      const warningReason = formatServiceErrorBlock(errorInfo, "allowed");
      auditLog.logAllow(sessionKey, toolName, `Service error (${errorInfo.category}), fail_open → allowed`, toolCallId);
      return { block: false, blockReason: warningReason };
    }
  }

  // Security finding: DANGER from actual LLM evaluation
  if (llmResult.decision === "DANGER") {
    const reason = llmResult.reason || "Blocked by LLM security audit";
    const ruleTag = ruleResult.ruleId ? ` (rule: ${ruleResult.ruleId})` : "";
    const pin = registerPendingOverride(sessionKey, toolName, params, toolCallId);
    auditLog.logBlock(sessionKey, toolName, reason, "sync", toolCallId, pin);
    const blockReason = `[SecAgent] ${reason}${ruleTag}${llmResult.recommendation ? `\nRecommendation: ${llmResult.recommendation}` : ""}`;
    return {
      block: true,
      blockReason: blockReason + formatOverrideHint(pin),
      buttons: overrideButtons(pin),
    };
  }

  auditLog.logAllow(sessionKey, toolName, "LLM audit → SAFE", toolCallId);
  return undefined;
}

export async function afterToolCall(
  event: PluginHookAfterToolCallEvent,
  ctx: PluginHookToolContext,
): Promise<void> {
  const { toolName, params, result } = event;
  const sessionKey = ctx.sessionKey ?? "default";
  const toolCallId = event.toolCallId ?? ctx.toolCallId ?? sessionState.getLastToolCallId(sessionKey) ?? undefined;

  onToolCallComplete(sessionKey, toolName, params, event.error ? "error" : "success");

  // Skip async audit for calls that were explicitly approved via override —
  // re-auditing them would just re-flag the same operation and set a spurious
  // danger flag that blocks the next unrelated tool call.
  if (sessionState.consumeLastCallOverridden(sessionKey)) {
    return;
  }

  // Re-classify to check tier
  const intentCtx = getIntentContext(sessionKey);
  const ruleResult = ruleEngine.classify(toolName, params, intentCtx,
    ctx.workspacePath ?? workspacePath);
  if (ruleResult.tier !== "YELLOW") {
    return; // GREEN → no audit needed; RED → already audited synchronously
  }

  // YELLOW → enqueue for async audit
  asyncQueue.enqueue({
    toolName,
    params,
    result,
    sessionKey,
    intentContext: { ...intentCtx },
    timestamp: Date.now(),
    toolCallId,
  });

  auditLog.logAsyncEnqueue(sessionKey, toolName, asyncQueue.length, toolCallId);
}

// ─── Additional Event Handlers ───

export function onUserMessageEvent(sessionKey: string, message: string): void {
  onUserMessage(sessionKey, message, config?.llm.trustedSenderLabels);
}

export function onSessionReset(sessionKey: string): void {
  resetSession(sessionKey);
}

// ─── OpenClaw Plugin Registration ───

function register(api: OpenClawPluginApi): void {
  const pluginConfig = (api.pluginConfig ?? {}) as Partial<SecAgentConfig>;
  const wsDir = api.config.workspace?.dir;

  init({
    config: pluginConfig,
    workspacePath: wsDir,
    pluginDir: getDirname(),
    emitAgentEvent: api.emitAgentEvent,
  });

  // Route all sec-agent log output through the gateway's logger
  auditLog.setExternalLogger(api.logger);

  // ─── Wire up LLM call function via gateway's OpenAI-compatible endpoint ───
  if (config.llm.enabled) {
    const llmCallFn = createGatewayLLMCallFn(config, api);
    if (llmCallFn) {
      llmAuditor.setLLMCallFn(llmCallFn);
      api.logger.info("[sec-agent] 🚀 LLM connected",
        `endpoint=${config.llm.endpoint || "(gateway internal)"}`,
        `model=${config.llm.model}`,
      );
    } else {
      api.logger.error("[sec-agent] ⚠️ LLM enabled but no endpoint configured -- " +
        "set llm.endpoint and llm.apiKey in plugin config. " +
        "RED operations will pass without real LLM audit.");
    }
  }

  api.logger.info("[sec-agent] 🚀 Initialized",
    `rules=${ruleEngine.getRules().length}`,
    `llm=${config.llm.enabled ? config.llm.model : "disabled"}`,
    `policy=${config.timeouts.syncTimeoutPolicy}`,
  );

  if (config.dashboard?.enabled) {
    api.logger.info(`[sec-agent] 📊 Dashboard: http://${config.dashboard.host}:${config.dashboard.port}`);
  }

  // ─── Core hooks ───
  api.on("before_tool_call", beforeToolCall, { priority: 9999 });
  api.on("after_tool_call", afterToolCall, { priority: 100 });

  // ─── Intent tracking ───
  // before_prompt_build: event.prompt is the current user input for this turn,
  // event.messages is the session history (not including the current message).
  // ctx contains message source info (channelId, trigger, agentId, messageProvider).
  api.on("before_prompt_build", (
    event: PluginHookBeforePromptBuildEvent,
    ctx: PluginHookAgentContext,
  ) => {
    const sk = ctx.sessionKey ?? "default";
    if (typeof event.prompt === "string" && event.prompt.length > 0) {
      onUserMessage(sk, event.prompt, config.llm.trustedSenderLabels);
      auditLog.debug(`🧠 Intent: userGoal updated via before_prompt_build`);
    }
    updateSource(sk, {
      channelId: ctx.channelId,
      trigger: ctx.trigger,
      agentId: ctx.agentId,
      messageProvider: ctx.messageProvider,
    });
  });

  // llm_input: backup — event.prompt is also the current user input, fires later.
  api.on("llm_input", (event: any, ctx: PluginHookAgentContext) => {
    const sk = ctx.sessionKey ?? "default";
    const intentCtx = getIntentContext(sk);
    if (intentCtx.userGoal) return; // already set by before_prompt_build
    const prompt = event?.prompt;
    if (typeof prompt === "string" && prompt.length > 0) {
      onUserMessage(sk, prompt, config.llm.trustedSenderLabels);
      auditLog.debug(`🧠 Intent: userGoal updated via llm_input`);
    }
  });

  // ─── Session lifecycle ───
  api.on("session_start", (_event: unknown, ctx: any) => {
    const sk = ctx?.sessionKey;
    if (sk) resetSession(sk);
  });

  api.on("before_reset", (_event: unknown, ctx: any) => {
    const sk = ctx?.sessionKey;
    if (sk) resetSession(sk);
  });

  api.on("before_compaction", (_event: unknown, ctx: any) => {
    const sk = ctx?.sessionKey;
    if (sk) resetSession(sk);
  });
}

/**
 * Create an LLM call function that calls the gateway's OpenAI-compatible endpoint.
 * Returns null if no endpoint is configured.
 */
function createGatewayLLMCallFn(
  cfg: SecAgentConfig,
  api: OpenClawPluginApi,
): LLMCallFn | null {
  const endpoint = cfg.llm.endpoint;
  const apiKey = cfg.llm.apiKey;

  if (!endpoint) {
    return null;
  }

  return async (params) => {
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (apiKey) {
      headers["Authorization"] = `Bearer ${apiKey}`;
    }

    const response = await fetch(endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify({
        model: params.model,
        messages: params.messages,
        max_tokens: params.max_tokens,
      }),
    });

    if (!response.ok) {
      if (response.status === 429) {
        const retryAfter = response.headers.get("Retry-After");
        const retryAfterMs = retryAfter ? parseInt(retryAfter, 10) * 1000 : undefined;
        throw new LLMHttpError(response.status, response.statusText, retryAfterMs);
      }
      throw new LLMHttpError(response.status, response.statusText);
    }

    const data = await response.json() as any;

    // OpenAI-compatible response format
    const content = data?.choices?.[0]?.message?.content
      ?? data?.content
      ?? "";

    return { content };
  };
}

// ─── Helpers ───

function getDirname(): string {
  try {
    return path.dirname(fileURLToPath(import.meta.url));
  } catch {
    return __dirname;
  }
}

// ─── Exported for Testing ───

export function _getRuleEngine(): RuleEngine { return ruleEngine; }
export function _getLLMAuditor(): LLMAuditor { return llmAuditor; }
export function _getAsyncQueue(): AsyncAuditQueue { return asyncQueue; }
export function _getAuditLog(): AuditLog { return auditLog; }
export { computeParamsFingerprint as _computeParamsFingerprint };
export { stopDashboard } from "./src/dashboard/server.js";
export { updateConfig as _updateConfig };

// ─── Default Export (OpenClaw plugin format) ───

const plugin = {
  id: "sec-agent",
  name: "SecAgent",
  description: "Real-time security audit layer for AI Agent tool calls",
  configSchema: {
    type: "object" as const,
    properties: {
      llm: { type: "object" as const },
      timeouts: { type: "object" as const },
      logging: { type: "object" as const },
      dashboard: { type: "object" as const },
    },
  },
  register,
};

export { plugin, register };
export default plugin;
