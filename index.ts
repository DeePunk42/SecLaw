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
import type { SecAgentConfig } from "./src/config.js";
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
): string {
  const pin = generatePin();
  sessionState.addPendingOverride(sessionKey, {
    pin,
    toolName,
    paramsFingerprint: computeParamsFingerprint(toolName, params),
    timestamp: Date.now(),
  });
  return pin;
}

function formatOverrideHint(pin: string): string {
  return [
    "",
    "--- Override ---",
    `If the user confirms this is intentional, they can tap or type: /override_${pin}`,
    `(Alternative: SEC_OVERRIDE:${pin})`,
    "Explain the risk to the user and let them decide whether to proceed.",
  ].join("\n");
}

function overrideButtons(pin: string): Array<Array<{ text: string; callback_data: string }>> {
  return [
    [{ text: "⚠️ Confirm Override", callback_data: `SEC_OVERRIDE:${pin}` }],
  ];
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
  }
}

// ─── Hook Handlers ───

export async function beforeToolCall(
  event: PluginHookBeforeToolCallEvent,
  ctx: PluginHookToolContext,
): Promise<PluginHookBeforeToolCallResult | undefined> {
  const { toolName, params } = event;
  const sessionKey = ctx.sessionKey ?? "default";
  const wsPath = ctx.workspacePath ?? workspacePath;

  auditLog.logBeforeToolCallStart(sessionKey, toolName, params);

  // 0. Check for active override grant (matches by toolName; fingerprint kept for audit only)
  if (sessionState.consumeActiveOverride(sessionKey, toolName)) {
    auditLog.logOverrideUsed(sessionKey, toolName);
    consumeDangerFlag(sessionKey);  // clear any lingering danger flag
    return undefined;  // allow
  }

  // 1. Check for danger flag from async audit
  const dangerReport = consumeDangerFlag(sessionKey);
  auditLog.logDangerFlagCheck(sessionKey, !!dangerReport);
  if (dangerReport) {
    const blockReason = formatDangerAlert(dangerReport);
    auditLog.logBlock(sessionKey, toolName, blockReason, "async");
    const pin = registerPendingOverride(sessionKey, toolName, params);
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
    auditLog.logRuleMatch(sessionKey, toolName, ruleResult.ruleId, ruleResult.tier, ruleResult.reason);
  } else {
    auditLog.logNoRuleMatch(sessionKey, toolName);
  }

  auditLog.logClassification(sessionKey, toolName, params, ruleResult.tier);

  // 3. GREEN → allow execution, async audit will handle it
  if (ruleResult.tier === "GREEN") {
    return undefined;
  }

  // 4. YELLOW → synchronous LLM audit with rule context
  if (!config.llm.enabled) {
    // LLM disabled — apply timeout policy
    if (config.timeouts.syncTimeoutPolicy === "fail_closed") {
      const reason = `YELLOW operation blocked: LLM audit disabled (fail_closed policy)`;
      auditLog.logBlock(sessionKey, toolName, reason, "sync");
      const pin = registerPendingOverride(sessionKey, toolName, params);
      return {
        block: true,
        blockReason: `[SecAgent] ${reason}` + formatOverrideHint(pin),
        buttons: overrideButtons(pin),
      };
    }
    auditLog.logLLMSkipped(sessionKey, toolName);
    auditLog.logAllow(sessionKey, toolName, "LLM disabled, YELLOW → pass-through (fail_open)");
    return undefined;
  }

  auditLog.logLLMAuditStart(sessionKey, toolName);
  auditLog.logIntentContext(sessionKey, toolName, intentCtx, config.llm.promptRecentCalls);
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

  auditLog.logLLMAudit(sessionKey, toolName, llmResult.decision, llmResult.reason, durationMs);
  auditLog.logLLMAuditDetail(sessionKey, toolName, llmResult, durationMs);

  if (llmResult.decision === "DANGER") {
    const reason = llmResult.reason || "Blocked by LLM security audit";
    auditLog.logBlock(sessionKey, toolName, reason, "sync");
    const ruleTag = ruleResult.ruleId ? ` (rule: ${ruleResult.ruleId})` : "";
    const pin = registerPendingOverride(sessionKey, toolName, params);
    const blockReason = `[SecAgent] ${reason}${ruleTag}${llmResult.recommendation ? `\nRecommendation: ${llmResult.recommendation}` : ""}`;
    return {
      block: true,
      blockReason: blockReason + formatOverrideHint(pin),
      buttons: overrideButtons(pin),
    };
  }

  auditLog.logAllow(sessionKey, toolName, "LLM audit → SAFE");
  return undefined;
}

export async function afterToolCall(
  event: PluginHookAfterToolCallEvent,
  ctx: PluginHookToolContext,
): Promise<void> {
  const { toolName, params, result } = event;
  const sessionKey = ctx.sessionKey ?? "default";

  onToolCallComplete(sessionKey, toolName, params, event.error ? "error" : "success");

  // Skip async audit for calls that were explicitly approved via override —
  // re-auditing them would just re-flag the same operation and set a spurious
  // danger flag that blocks the next unrelated tool call.
  if (sessionState.consumeLastCallOverridden(sessionKey)) {
    return;
  }

  const intentCtx = getIntentContext(sessionKey);
  asyncQueue.enqueue({
    toolName,
    params,
    result,
    sessionKey,
    intentContext: { ...intentCtx },
    timestamp: Date.now(),
  });

  auditLog.logAsyncEnqueue(sessionKey, toolName, asyncQueue.length);
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
        "YELLOW operations will pass without real LLM audit.");
    }
  }

  api.logger.info("[sec-agent] 🚀 Initialized",
    `rules=${ruleEngine.getRules().length}`,
    `llm=${config.llm.enabled ? config.llm.model : "disabled"}`,
    `policy=${config.timeouts.syncTimeoutPolicy}`,
  );

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
      throw new Error(`LLM endpoint returned ${response.status}: ${response.statusText}`);
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
    },
  },
  register,
};

export { plugin, register };
export default plugin;
