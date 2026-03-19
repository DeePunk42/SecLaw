/**
 * SecLaw Plugin Entry Point
 *
 * Conforms to OpenClaw plugin API — exports a default object with
 * register(api) that uses api.on() to register hook handlers.
 *
 * Also exports init() / beforeToolCall() / afterToolCall() directly
 * for standalone testing without the full OpenClaw runtime.
 */

import crypto from "crypto";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { fileURLToPath } from "url";
import type { SecLawConfig, LLMErrorInfo } from "./src/config.js";
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
import {
  startDashboard,
  stopDashboard,
  type ModelOption,
} from "./src/dashboard/server.js";
import { getOpenClawDir } from "./src/hardening/platform.js";

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
  // Extended by SecLaw — not in upstream but consumed if present
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

/** Minimal subset of OpenClawPluginApi used by SecLaw */
export interface OpenClawPluginApi {
  id: string;
  name: string;
  config: {
    workspace?: { dir?: string };
    models?: {
      providers?: Record<
        string,
        {
          baseUrl: string;
          apiKey?: unknown;
          auth?: string; // "api-key" | "oauth" | "token" | "aws-sdk"
          api?: string;
          models?: Array<{ id: string; name: string; [key: string]: unknown }>;
        }
      >;
    };
  } & Record<string, unknown>;
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
  runtime?: {
    config?: {
      loadConfig?: () => Record<string, unknown>;
    };
    modelAuth?: {
      resolveApiKeyForProvider: (params: {
        provider: string;
        cfg?: Record<string, unknown>;
      }) => Promise<{
        apiKey?: string;
        profileId?: string;
        source: string;
        mode: "api-key" | "oauth" | "token" | "aws-sdk";
      }>;
    };
  };
}

type GatewayProviderConfig = {
  baseUrl: string;
  apiKey?: unknown;
  auth?: string;
  api?: string;
  models?: Array<{ id: string; name?: string; [key: string]: unknown }>;
};

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

type ModelCallErrorCode =
  | "config_invalid"
  | "auth_failed"
  | "upstream_429"
  | "upstream_5xx"
  | "upstream_http_error"
  | "network_error"
  | "response_parse_failed"
  | "unknown";

function formatModelTestError(error: unknown): {
  error: string;
  statusCode?: number;
  errorCode: ModelCallErrorCode;
} {
  if (error instanceof LLMHttpError) {
    let errorCode: ModelCallErrorCode = "upstream_http_error";
    if (error.statusCode === 401 || error.statusCode === 403) {
      errorCode = "auth_failed";
    } else if (error.statusCode === 429) {
      errorCode = "upstream_429";
    } else if (error.statusCode >= 500) {
      errorCode = "upstream_5xx";
    }
    return {
      error: error.message,
      statusCode: error.statusCode,
      errorCode,
    };
  }
  if (error instanceof Error) {
    if (error.message.startsWith("config_invalid:")) {
      return { error: error.message, errorCode: "config_invalid" };
    }
    if (error.message.startsWith("response_parse_failed:")) {
      return { error: error.message, errorCode: "response_parse_failed" };
    }
    return { error: error.message, errorCode: "network_error" };
  }
  return { error: String(error), errorCode: "unknown" };
}

// ─── Plugin State ───

let ruleEngine: RuleEngine;
let llmAuditor: LLMAuditor;
let auditLog: AuditLog;
let asyncQueue: AsyncAuditQueue;
let config: SecLawConfig;
let workspacePath: string | undefined;
let varDir: string;
let availableModelsProvider: (() => ModelOption[]) | null = null;
let gatewayApi: OpenClawPluginApi | null = null;
let managedRulesDir = "";

const RULE_FILE_NAME_RE = /^[A-Za-z0-9._-]+\.(ya?ml)$/i;

// ─── Override helpers ───

function computeParamsFingerprint(
  toolName: string,
  params: Record<string, unknown>,
): string {
  return crypto
    .createHash("sha256")
    .update(toolName + ":" + JSON.stringify(params))
    .digest("hex");
}

function generatePin(): string {
  const n = crypto.randomInt(0, 1_000_000); // 0–999999
  return String(n).padStart(6, "0"); // 6-digit decimal
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

function formatOverrideHint(pin: string, showPin: boolean): string {
  if (!showPin) {
    return [
      "",
      "--- Override ---",
      "The current sender is not in llm.trustedSenderLabels, so override is unavailable.",
      "If this sender should be trusted, add it to llm.trustedSenderLabels in plugin config (dashboard recommended).",
    ].join("\n");
  }
  return [
    "",
    "--- Override ---",
    `If the user confirms this is intentional, they can reply with: /pin${pin}`,
    "Explain the risk to the user and let them decide whether to proceed.",
  ].join("\n");
}

function overrideButtons(
  pin: string,
): Array<Array<{ text: string; callback_data: string }>> {
  return [[{ text: "⚠️ Confirm Override", callback_data: `/pin${pin}` }]];
}

function isSenderTrusted(sessionKey: string): boolean {
  const senderLabel = getIntentContext(sessionKey).senderLabel;
  return (
    senderLabel != null &&
    (config.llm.trustedSenderLabels ?? []).includes(senderLabel)
  );
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
      `[SecLaw] SERVICE UNAVAILABLE — LLM security audit could not be completed`,
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
    `[SecLaw] WARNING — LLM security audit skipped due to service error`,
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
  config?: Partial<SecLawConfig>;
  workspacePath?: string;
  pluginDir?: string;
  varDir?: string;
  emitAgentEvent?: EmitAgentEventFn;
  llmCall?: LLMCallFn;
}

function getManagedRulesDir(): string {
  return path.join(getOpenClawDir(), "seclaw", "rules");
}

function listManagedRuleFiles(dir = managedRulesDir): string[] {
  try {
    if (!dir || !fs.existsSync(dir)) return [];
    return fs
      .readdirSync(dir, { withFileTypes: true })
      .filter((entry) => entry.isFile() && RULE_FILE_NAME_RE.test(entry.name))
      .map((entry) => entry.name)
      .sort((a, b) => a.localeCompare(b));
  } catch {
    return [];
  }
}

function isValidRuleFileName(name: unknown): name is string {
  return typeof name === "string" && RULE_FILE_NAME_RE.test(name);
}

function bootstrapManagedRules(pluginDir: string): void {
  managedRulesDir = getManagedRulesDir();
  fs.mkdirSync(managedRulesDir, { recursive: true });

  const builtInRulesDir = path.join(pluginDir, "rules");
  if (!fs.existsSync(builtInRulesDir)) return;

  const sourceFiles = fs
    .readdirSync(builtInRulesDir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && RULE_FILE_NAME_RE.test(entry.name))
    .map((entry) => entry.name);

  sourceFiles.forEach((fileName) => {
    const sourcePath = path.join(builtInRulesDir, fileName);
    const targetPath = path.join(managedRulesDir, fileName);
    if (!fs.existsSync(targetPath)) {
      fs.copyFileSync(sourcePath, targetPath);
    }
  });
}

function resolveActiveRuleFile(): string | undefined {
  const availableFiles = listManagedRuleFiles();
  if (availableFiles.length === 0) return undefined;

  const configured = config.rules?.activeRuleFile;
  if (configured && availableFiles.includes(configured)) return configured;

  const defaultFile = availableFiles.includes("default.yaml")
    ? "default.yaml"
    : availableFiles[0];
  config.rules = { ...(config.rules || {}), activeRuleFile: defaultFile };
  return defaultFile;
}

function reloadRuleEngineFromManagedRules(): void {
  const activeFile = resolveActiveRuleFile();
  if (!activeFile) {
    ruleEngine.setRules([]);
    return;
  }
  const activePath = path.join(managedRulesDir, activeFile);
  ruleEngine.loadRules({ defaultRulesPath: activePath });
}

export function init(ctx: PluginInitContext): void {
  assertNoDeprecatedLLMConfig(ctx.config);
  config = loadConfig(ctx.config);
  const pluginDir = ctx.pluginDir || getDirname();
  workspacePath = ctx.workspacePath;
  varDir = ctx.varDir || path.join(os.homedir(), ".openclaw", "seclaw");
  bootstrapManagedRules(pluginDir);

  ruleEngine = new RuleEngine();
  reloadRuleEngineFromManagedRules();

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
      getAvailableModels: () => availableModelsProvider?.() ?? [],
      testModelAvailability: async (model: string) => {
        if (!gatewayApi) {
          return {
            ok: false,
            model,
            error: "Gateway API unavailable: plugin runtime is not ready",
            statusCode: 503,
            errorCode: "config_invalid" as const,
          };
        }
        const testCfg: SecLawConfig = {
          ...config,
          llm: {
            ...config.llm,
            model,
            enabled: true,
          },
        };
        const call = createGatewayLLMCallFn(testCfg, gatewayApi);
        if (!call) {
          return {
            ok: false,
            model,
            error: `Failed to resolve provider endpoint for model "${model}"`,
            statusCode: 400,
            errorCode: "config_invalid" as const,
          };
        }
        const startedAt = Date.now();
        try {
          const response = await call({
            model,
            messages: [{ role: "user", content: "Reply with OK only." }],
            max_tokens: 16,
          });
          const latencyMs = Date.now() - startedAt;
          const preview = response.content.trim().slice(0, 120);
          return {
            ok: true,
            model,
            latencyMs,
            preview,
          };
        } catch (error) {
          const formatted = formatModelTestError(error);
          return {
            ok: false,
            model,
            error: formatted.error,
            statusCode: formatted.statusCode,
            errorCode: formatted.errorCode,
          };
        }
      },
      getWorkspacePath: () => workspacePath,
      getVarDir: () => varDir,
      getOpenClawDir: () => getOpenClawDir(),
    }).catch(() => {
      // Best-effort — dashboard failure shouldn't block the plugin
    });
  }
}

// ─── Config Persistence Helpers ───

function assertNoDeprecatedLLMConfig(partial?: Partial<SecLawConfig>): void {
  const llm = (partial as { llm?: Record<string, unknown> } | undefined)?.llm;
  if (!llm || typeof llm !== "object") return;

  const deprecated: string[] = [];
  if ("apiKey" in llm) deprecated.push("llm.apiKey");
  if ("endpoint" in llm) deprecated.push("llm.endpoint");
  if (deprecated.length === 0) return;

  throw new Error(
    `[seclaw] Deprecated config field(s): ${deprecated.join(", ")}. ` +
      "Remove them from openclaw.json and use provider/model configuration only.",
  );
}

function upsertSecLawPluginConfig(
  openClawConfig: Record<string, unknown>,
  seclawConfig: SecLawConfig,
): Record<string, unknown> {
  const next = { ...openClawConfig };
  const pluginsObj =
    next.plugins &&
    typeof next.plugins === "object" &&
    !Array.isArray(next.plugins)
      ? { ...(next.plugins as Record<string, unknown>) }
      : {};
  const entriesObj =
    pluginsObj.entries &&
    typeof pluginsObj.entries === "object" &&
    !Array.isArray(pluginsObj.entries)
      ? { ...(pluginsObj.entries as Record<string, unknown>) }
      : {};
  const seclawEntry =
    entriesObj.seclaw &&
    typeof entriesObj.seclaw === "object" &&
    !Array.isArray(entriesObj.seclaw)
      ? { ...(entriesObj.seclaw as Record<string, unknown>) }
      : {};

  seclawEntry.config = seclawConfig;
  entriesObj.seclaw = seclawEntry;
  pluginsObj.entries = entriesObj;
  next.plugins = pluginsObj;
  return next;
}

function persistConfigToOpenClaw(nextConfig: SecLawConfig): {
  ok: boolean;
  error?: string;
} {
  const openClawPath = path.join(getOpenClawDir(), "openclaw.json");
  try {
    const raw = fs.readFileSync(openClawPath, "utf-8");
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {
        ok: false,
        error: `Invalid openclaw.json format at ${openClawPath}`,
      };
    }
    if (Array.isArray((parsed as Record<string, unknown>).plugins)) {
      return {
        ok: false,
        error:
          "Unsupported openclaw.json format: plugins must be an object with plugins.entries.<id>, not an array.",
      };
    }
    const updated = upsertSecLawPluginConfig(
      parsed as Record<string, unknown>,
      nextConfig,
    );
    fs.writeFileSync(openClawPath, JSON.stringify(updated, null, 2), "utf-8");
    return { ok: true };
  } catch (err: any) {
    return {
      ok: false,
      error: `Failed to persist seclaw config to ${openClawPath}: ${err.message}`,
    };
  }
}

// ─── Runtime Config Update ───

function updateConfig(partial: Partial<SecLawConfig>): {
  ok: boolean;
  errors?: string[];
} {
  const errors: string[] = [];
  const llmPartial = (partial as { llm?: Record<string, unknown> }).llm;
  if (llmPartial && typeof llmPartial === "object") {
    if ("apiKey" in llmPartial || "endpoint" in llmPartial) {
      errors.push("llm.apiKey and llm.endpoint are no longer supported");
    }
  }

  // Validate & apply llm changes
  if (partial.llm) {
    if (partial.llm.model !== undefined) {
      if (
        typeof partial.llm.model !== "string" ||
        partial.llm.model.length === 0
      ) {
        errors.push("llm.model must be a non-empty string");
      }
    }
    if (partial.llm.enabled !== undefined) {
      if (typeof partial.llm.enabled !== "boolean") {
        errors.push("llm.enabled must be a boolean");
      }
    }
    if (partial.llm.maxConcurrent !== undefined) {
      if (
        typeof partial.llm.maxConcurrent !== "number" ||
        partial.llm.maxConcurrent < 1 ||
        partial.llm.maxConcurrent > 10
      ) {
        errors.push("llm.maxConcurrent must be a number between 1 and 10");
      }
    }
    if (partial.llm.trustedSenderLabels !== undefined) {
      if (!Array.isArray(partial.llm.trustedSenderLabels)) {
        errors.push("llm.trustedSenderLabels must be an array of strings");
      }
    }
    // Validate provider existence for "provider/model" format models
    if (partial.llm.model !== undefined && partial.llm.model.includes("/")) {
      const providerName = partial.llm.model.slice(
        0,
        partial.llm.model.indexOf("/"),
      );
      if (gatewayApi) {
        const provider = findProviderConfig(
          getMergedProviders(gatewayApi),
          providerName,
        );
        if (!provider) {
          const implicitProbe = resolveProviderTransport(
            `${providerName}/probe`,
            gatewayApi,
          );
          if (!implicitProbe) {
            errors.push(
              `llm.model: provider "${providerName}" not found in effective providers`,
            );
          }
        } else if (
          !provider.apiKey &&
          (provider.auth === "oauth" || provider.auth === "token") &&
          !gatewayApi.runtime?.modelAuth
        ) {
          errors.push(
            `llm.model: provider "${providerName}" uses ${provider.auth} auth but runtime.modelAuth is not available`,
          );
        }
      }
    }
  }

  // Validate & apply timeout changes
  if (partial.timeouts) {
    if (partial.timeouts.syncAuditMs !== undefined) {
      if (
        typeof partial.timeouts.syncAuditMs !== "number" ||
        partial.timeouts.syncAuditMs < 1000 ||
        partial.timeouts.syncAuditMs > 120000
      ) {
        errors.push("timeouts.syncAuditMs must be between 1000 and 120000");
      }
    }
    if (partial.timeouts.asyncAuditMs !== undefined) {
      if (
        typeof partial.timeouts.asyncAuditMs !== "number" ||
        partial.timeouts.asyncAuditMs < 1000 ||
        partial.timeouts.asyncAuditMs > 120000
      ) {
        errors.push("timeouts.asyncAuditMs must be between 1000 and 120000");
      }
    }
    if (partial.timeouts.syncTimeoutPolicy !== undefined) {
      if (
        partial.timeouts.syncTimeoutPolicy !== "fail_closed" &&
        partial.timeouts.syncTimeoutPolicy !== "fail_open"
      ) {
        errors.push(
          "timeouts.syncTimeoutPolicy must be 'fail_closed' or 'fail_open'",
        );
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

  // Validate rules changes
  if (partial.rules) {
    if (
      partial.rules.activeRuleFile !== undefined &&
      !isValidRuleFileName(partial.rules.activeRuleFile)
    ) {
      errors.push("rules.activeRuleFile must be a .yaml/.yml file name");
    } else if (partial.rules.activeRuleFile !== undefined) {
      const availableFiles = listManagedRuleFiles();
      if (!availableFiles.includes(partial.rules.activeRuleFile!)) {
        errors.push(
          `rules.activeRuleFile not found in ${managedRulesDir || getManagedRulesDir()}`,
        );
      }
    }
  }

  if (errors.length > 0) return { ok: false, errors };

  // Capture pre-change state for enable toggle detection
  const wasLLMEnabled = config.llm.enabled;

  const nextConfig: SecLawConfig = {
    ...config,
    llm: partial.llm ? { ...config.llm, ...partial.llm } : config.llm,
    timeouts: partial.timeouts
      ? { ...config.timeouts, ...partial.timeouts }
      : config.timeouts,
    logging: partial.logging
      ? { ...config.logging, ...partial.logging }
      : config.logging,
    rules: partial.rules ? { ...(config.rules || {}), ...partial.rules } : config.rules,
  };

  const persistResult = persistConfigToOpenClaw(nextConfig);
  if (!persistResult.ok) {
    return {
      ok: false,
      errors: [persistResult.error || "Failed to persist config"],
    };
  }

  config = nextConfig;
  if (partial.logging) {
    auditLog.setLoggingConfig(config.logging);
  }

  if (partial.rules?.activeRuleFile !== undefined) {
    reloadRuleEngineFromManagedRules();
  }

  // Sync references that were broken by spread operator
  if (partial.llm || partial.timeouts) {
    llmAuditor.setConfig(config.llm, config.timeouts);
  }

  // Recreate llmCallFn when model changes at runtime (gateway mode)
  if (partial.llm?.model && gatewayApi && config.llm.enabled) {
    const newCallFn = createGatewayLLMCallFn(config, gatewayApi);
    if (newCallFn) {
      llmAuditor.setLLMCallFn(newCallFn);
    }
  }

  // Handle llm.enabled toggled on at runtime
  if (
    !wasLLMEnabled &&
    config.llm.enabled &&
    gatewayApi &&
    !partial.llm?.model
  ) {
    const newCallFn = createGatewayLLMCallFn(config, gatewayApi);
    if (newCallFn) {
      llmAuditor.setLLMCallFn(newCallFn);
    }
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
    // Backtrack: mark the original blocked card as overridden (dashboard update)
    const activePin = sessionState.getActiveOverridePin(sessionKey);
    if (activePin) {
      const pending = sessionState.getPendingOverride(sessionKey, activePin);
      if (pending?.toolCallId) {
        auditLog.logOverrideUsed(sessionKey, toolName, pending.toolCallId);
      }
    }
    // Log for JSONL audit trail only (no toolCallId → no ToolCallRecord card)
    auditLog.logOverrideUsed(sessionKey, toolName);
    consumeDangerFlag(sessionKey); // clear any lingering danger flag
    return undefined; // allow
  }

  // 1. Check for danger flag from async audit
  const dangerReport = consumeDangerFlag(sessionKey);
  auditLog.logDangerFlagCheck(sessionKey, !!dangerReport);
  if (dangerReport) {
    const blockReason = formatDangerAlert(dangerReport);
    const pin = registerPendingOverride(
      sessionKey,
      toolName,
      params,
      toolCallId,
    );
    auditLog.logBlock(
      sessionKey,
      toolName,
      blockReason,
      "async",
      toolCallId,
      pin,
    );
    const trusted = isSenderTrusted(sessionKey);
    return {
      block: true,
      blockReason: blockReason + formatOverrideHint(pin, trusted),
      ...(trusted ? { buttons: overrideButtons(pin) } : {}),
    };
  }

  // 2. Classify via unified rule engine
  const intentCtx = getIntentContext(sessionKey);
  const ruleResult = ruleEngine.classify(toolName, params, intentCtx, wsPath);

  if (ruleResult.ruleId) {
    auditLog.logRuleMatch(
      sessionKey,
      toolName,
      ruleResult.ruleId,
      ruleResult.tier,
      ruleResult.reason,
      toolCallId,
    );
  } else {
    auditLog.logNoRuleMatch(sessionKey, toolName);
  }

  auditLog.logClassification(
    sessionKey,
    toolName,
    params,
    ruleResult.tier,
    toolCallId,
  );

  // 3. GREEN → allow execution, no audit at all
  if (ruleResult.tier === "GREEN") {
    return undefined;
  }

  // 4. YELLOW → allow execution, afterToolCall will handle async audit
  if (ruleResult.tier === "YELLOW") {
    auditLog.logIntentContext(
      sessionKey,
      toolName,
      intentCtx,
      config.llm.promptRecentCalls,
      toolCallId,
    );
    return undefined;
  }

  // 5. RED → synchronous LLM audit with rule context
  if (!config.llm.enabled) {
    // LLM disabled — apply timeout policy
    if (config.timeouts.syncTimeoutPolicy === "fail_closed") {
      const reason = `RED operation blocked: LLM audit disabled (fail_closed policy)`;
      const pin = registerPendingOverride(
        sessionKey,
        toolName,
        params,
        toolCallId,
      );
      auditLog.logBlock(sessionKey, toolName, reason, "sync", toolCallId, pin);
      const trusted = isSenderTrusted(sessionKey);
      return {
        block: true,
        blockReason: `[SecLaw] ${reason}` + formatOverrideHint(pin, trusted),
        ...(trusted ? { buttons: overrideButtons(pin) } : {}),
      };
    }
    auditLog.logLLMSkipped(sessionKey, toolName);
    auditLog.logAllow(
      sessionKey,
      toolName,
      "LLM disabled, RED → pass-through (fail_open)",
      toolCallId,
    );
    return undefined;
  }

  auditLog.logLLMAuditStart(sessionKey, toolName);
  auditLog.logIntentContext(
    sessionKey,
    toolName,
    intentCtx,
    config.llm.promptRecentCalls,
    toolCallId,
  );
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

  auditLog.logLLMAudit(
    sessionKey,
    toolName,
    llmResult.decision,
    llmResult.reason,
    durationMs,
    toolCallId,
  );
  auditLog.logLLMAuditDetail(sessionKey, toolName, llmResult, durationMs);

  // Service error: not a security finding — handle separately
  if (
    llmResult._errorInfo &&
    llmResult._errorInfo.category !== "unknown_error"
  ) {
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
      auditLog.logAllow(
        sessionKey,
        toolName,
        `Service error (${errorInfo.category}), fail_open → allowed`,
        toolCallId,
      );
      return { block: false, blockReason: warningReason };
    }
  }

  // Security finding: DANGER from actual LLM evaluation
  if (llmResult.decision === "DANGER") {
    const reason = llmResult.reason || "Blocked by LLM security audit";
    const ruleTag = ruleResult.ruleId ? ` (rule: ${ruleResult.ruleId})` : "";
    const pin = registerPendingOverride(
      sessionKey,
      toolName,
      params,
      toolCallId,
    );
    auditLog.logBlock(sessionKey, toolName, reason, "sync", toolCallId, pin);
    const blockReason = `[SecLaw] ${reason}${ruleTag}${llmResult.recommendation ? `\nRecommendation: ${llmResult.recommendation}` : ""}`;
    const trusted = isSenderTrusted(sessionKey);
    return {
      block: true,
      blockReason: blockReason + formatOverrideHint(pin, trusted),
      ...(trusted ? { buttons: overrideButtons(pin) } : {}),
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
  const toolCallId =
    event.toolCallId ??
    ctx.toolCallId ??
    sessionState.getLastToolCallId(sessionKey) ??
    undefined;

  onToolCallComplete(
    sessionKey,
    toolName,
    params,
    event.error ? "error" : "success",
  );

  // Skip async audit for calls that were explicitly approved via override —
  // re-auditing them would just re-flag the same operation and set a spurious
  // danger flag that blocks the next unrelated tool call.
  if (sessionState.consumeLastCallOverridden(sessionKey)) {
    return;
  }

  // Re-classify to check tier
  const intentCtx = getIntentContext(sessionKey);
  const ruleResult = ruleEngine.classify(
    toolName,
    params,
    intentCtx,
    ctx.workspacePath ?? workspacePath,
  );
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
  const pluginConfig = (api.pluginConfig ?? {}) as Partial<SecLawConfig>;
  const wsDir = api.config.workspace?.dir;

  // Build available models list from effective providers
  availableModelsProvider = () => {
    const providers = getMergedProviders(api);
    if (Object.keys(providers).length === 0) return [];
    const options: ModelOption[] = [];
    for (const [providerName, provider] of Object.entries(providers)) {
      if (provider.models) {
        for (const m of provider.models) {
          options.push({
            value: `${providerName}/${m.id}`,
            label: `${providerName} / ${m.name || m.id}`,
          });
        }
      }
    }
    return options;
  };

  init({
    config: pluginConfig,
    workspacePath: wsDir,
    pluginDir: getDirname(),
    emitAgentEvent: api.emitAgentEvent,
  });

  // Route all seclaw log output through the gateway's logger
  auditLog.setExternalLogger(api.logger);

  // ─── Wire up LLM call function via gateway providers ───
  gatewayApi = api;
  if (config.llm.enabled) {
    const llmCallFn = createGatewayLLMCallFn(config, api);
    if (llmCallFn) {
      llmAuditor.setLLMCallFn(llmCallFn);
      // Determine auth mode for logging
      const resolved = resolveProviderTransport(config.llm.model, api);
      const providerAuth = resolved?.authMode;
      const hasStaticKey = !!resolved?.staticApiKey;
      const hasRuntimeAuth = !!api.runtime?.modelAuth;
      if (!hasStaticKey && hasRuntimeAuth) {
        api.logger.info(
          "[seclaw] 🚀 LLM connected via provider config (OAuth/dynamic auth)",
          `model=${config.llm.model}`,
        );
      } else if (!hasStaticKey && !hasRuntimeAuth && (providerAuth === "oauth" || providerAuth === "token")) {
        api.logger.error(
          `[seclaw] ⚠️ LLM provider "${resolved?.providerName}" uses ${providerAuth} auth but runtime.modelAuth is not available -- ` +
            "LLM calls will fail with 401. Ensure the gateway provides runtime.modelAuth.",
        );
      } else {
        api.logger.info(
          "[seclaw] 🚀 LLM connected via provider config",
          `model=${config.llm.model}`,
        );
      }
    } else {
      if (config.llm.model.includes("/")) {
        const providerName = config.llm.model.slice(
          0,
          config.llm.model.indexOf("/"),
        );
        api.logger.error(
          `[seclaw] ⚠️ LLM enabled but provider "${providerName}" not found in effective providers -- ` +
            "check openclaw.json configuration. " +
            "RED operations will pass without real LLM audit.",
        );
      } else if (!config.llm.model) {
        api.logger.error(
          "[seclaw] ⚠️ LLM enabled but no model configured -- " +
            "set llm.model as provider/model in plugin config. " +
            "RED operations will pass without real LLM audit.",
        );
      } else {
        api.logger.error(
          "[seclaw] ⚠️ LLM enabled but model is not provider/model -- " +
            "set llm.model as provider/model in plugin config. " +
            "RED operations will pass without real LLM audit.",
        );
      }
    }
  }

  api.logger.info(
    "[seclaw] 🚀 Initialized",
    `rules=${ruleEngine.getRules().length}`,
    `llm=${config.llm.enabled ? config.llm.model : "disabled"}`,
    `policy=${config.timeouts.syncTimeoutPolicy}`,
  );

  if (config.dashboard?.enabled) {
    api.logger.info(
      `[seclaw] 📊 Dashboard: http://${config.dashboard.host}:${config.dashboard.port}`,
    );
  }

  // ─── Core hooks ───
  api.on("before_tool_call", beforeToolCall, { priority: 9999 });
  api.on("after_tool_call", afterToolCall, { priority: 100 });

  // ─── Intent tracking ───
  // before_prompt_build: event.prompt is the current user input for this turn,
  // event.messages is the session history (not including the current message).
  // ctx contains message source info (channelId, trigger, agentId, messageProvider).
  api.on(
    "before_prompt_build",
    (event: PluginHookBeforePromptBuildEvent, ctx: PluginHookAgentContext) => {
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
    },
  );

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

type ProviderApiSurface =
  | "openai-completions"
  | "openai-responses"
  | "openai-codex-responses";

type ResolvedProviderTransport = {
  providerName: string;
  modelId: string;
  apiSurface: ProviderApiSurface;
  endpoint: string;
  staticApiKey?: string;
  authMode?: string;
};

function resolveRuntimeConfig(api: OpenClawPluginApi): Record<string, unknown> | undefined {
  try {
    return api.runtime?.config?.loadConfig?.();
  } catch {
    return undefined;
  }
}

function normalizeProviderKey(input: string): string {
  return input.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function extractProvidersFromConfig(
  cfg: Record<string, unknown> | undefined,
): Record<string, GatewayProviderConfig> {
  const models = cfg?.models;
  if (!models || typeof models !== "object") return {};
  const providers = (models as { providers?: unknown }).providers;
  if (!providers || typeof providers !== "object") return {};
  return providers as Record<string, GatewayProviderConfig>;
}

function getMergedProviders(api: OpenClawPluginApi): Record<string, GatewayProviderConfig> {
  const fromApi = api.config.models?.providers ?? {};
  const fromRuntime = extractProvidersFromConfig(resolveRuntimeConfig(api));
  return { ...fromApi, ...fromRuntime };
}

function findProviderConfig(
  providers: Record<string, GatewayProviderConfig>,
  providerName: string,
): GatewayProviderConfig | undefined {
  if (providers[providerName]) return providers[providerName];
  const normalizedTarget = normalizeProviderKey(providerName);
  for (const [key, value] of Object.entries(providers)) {
    if (normalizeProviderKey(key) === normalizedTarget) return value;
  }
  return undefined;
}

function hasAuthProfileForProvider(
  cfg: Record<string, unknown> | undefined,
  providerName: string,
): { found: boolean; mode?: string } {
  const auth = cfg?.auth;
  if (!auth || typeof auth !== "object") return { found: false };
  const profiles = (auth as { profiles?: unknown }).profiles;
  if (!profiles || typeof profiles !== "object") return { found: false };
  const target = normalizeProviderKey(providerName);
  for (const profile of Object.values(profiles as Record<string, unknown>)) {
    if (!profile || typeof profile !== "object") continue;
    const p = profile as { provider?: unknown; mode?: unknown };
    if (typeof p.provider !== "string") continue;
    if (normalizeProviderKey(p.provider) !== target) continue;
    return {
      found: true,
      mode: typeof p.mode === "string" ? p.mode : undefined,
    };
  }
  return { found: false };
}

function normalizeApiSurface(apiValue: unknown): ProviderApiSurface {
  const normalized = typeof apiValue === "string" ? apiValue.trim() : "";
  if (
    normalized === "openai-responses" ||
    normalized === "openai-codex-responses"
  ) {
    return normalized;
  }
  return "openai-completions";
}

function appendEndpoint(
  baseUrl: string,
  endpointPath: "/chat/completions" | "/responses" | "/codex/responses",
): string {
  const trimmed = baseUrl.replace(/\/+$/, "");
  if (trimmed.endsWith(endpointPath)) return trimmed;
  return `${trimmed}${endpointPath}`;
}

function stripApiPath(endpoint: string): string {
  return endpoint
    .replace(/\/chat\/completions$/, "")
    .replace(/\/responses$/, "");
}

function isHostMatch(baseUrl: string, host: string): boolean {
  try {
    return new URL(baseUrl).hostname.toLowerCase() === host;
  } catch {
    return baseUrl.toLowerCase().includes(host);
  }
}

function buildAttributionHeaders(transport: ResolvedProviderTransport): Record<string, string> {
  const provider = normalizeProviderKey(transport.providerName);
  const headers: Record<string, string> = {};
  const isOpenAI =
    provider === "openai" &&
    (transport.apiSurface === "openai-completions" || transport.apiSurface === "openai-responses") &&
    isHostMatch(transport.endpoint, "api.openai.com");
  const isCodex =
    provider === "openaicodex" &&
    (transport.apiSurface === "openai-codex-responses" ||
      transport.apiSurface === "openai-responses") &&
    isHostMatch(transport.endpoint, "chatgpt.com");
  if (isOpenAI || isCodex) {
    headers.originator = "openclaw";
    headers["User-Agent"] = "openclaw/seclaw";
  }
  return headers;
}

function resolveProviderTransport(
  model: string,
  api: OpenClawPluginApi,
): ResolvedProviderTransport | null {
  if (!model.includes("/")) {
    return null;
  }
  const slashIdx = model.indexOf("/");
  const providerName = model.slice(0, slashIdx).trim();
  const modelId = model.slice(slashIdx + 1).trim();
  if (!providerName || !modelId) {
    return null;
  }

  const providers = getMergedProviders(api);
  const provider = findProviderConfig(providers, providerName);
  if (!provider) {
    const runtimeCfg = resolveRuntimeConfig(api);
    const authProfile = hasAuthProfileForProvider(runtimeCfg, providerName);
    if (normalizeProviderKey(providerName) === "openaicodex" && authProfile.found) {
      return {
        providerName,
        modelId,
        apiSurface: "openai-codex-responses",
        endpoint: appendEndpoint("https://chatgpt.com/backend-api", "/codex/responses"),
        authMode: authProfile.mode ?? "oauth",
      };
    }
    return null;
  }

  const modelDef = provider.models?.find((item) => item.id === modelId);
  const apiSurface = normalizeApiSurface(
    modelDef && typeof modelDef === "object" && "api" in modelDef
      ? (modelDef as { api?: unknown }).api
      : provider.api,
  );
  const endpoint =
    apiSurface === "openai-codex-responses"
      ? appendEndpoint(provider.baseUrl, "/codex/responses")
      : apiSurface === "openai-responses"
        ? appendEndpoint(provider.baseUrl, "/responses")
        : appendEndpoint(provider.baseUrl, "/chat/completions");

  return {
    providerName,
    modelId,
    apiSurface,
    endpoint,
    staticApiKey: typeof provider.apiKey === "string" ? provider.apiKey : undefined,
    authMode: provider.auth,
  };
}

function buildRequestPayload(
  transport: ResolvedProviderTransport,
  params: Parameters<LLMCallFn>[0],
): Record<string, unknown> {
  if (transport.apiSurface === "openai-codex-responses") {
    const systemMsg = params.messages.find((m) => m.role === "system");
    const nonSystemMsgs = params.messages.filter((m) => m.role !== "system");
    return {
      model: transport.modelId,
      instructions: systemMsg?.content || "You are a helpful assistant.",
      input: nonSystemMsgs.map((message) => ({
        role: message.role,
        content: message.content,
      })),
      max_output_tokens: params.max_tokens,
      store: false,
    };
  }
  if (transport.apiSurface === "openai-responses") {
    return {
      model: transport.modelId,
      input: params.messages.map((message) => ({
        role: message.role,
        content: message.content,
      })),
      max_output_tokens: params.max_tokens,
    };
  }
  return {
    model: transport.modelId,
    messages: params.messages,
    max_tokens: params.max_tokens,
  };
}

function extractResponseOutputText(output: unknown): string {
  if (!Array.isArray(output)) {
    return "";
  }
  const textParts: string[] = [];
  for (const item of output) {
    if (!item || typeof item !== "object") continue;
    const content = (item as { content?: unknown }).content;
    if (!Array.isArray(content)) continue;
    for (const block of content) {
      if (!block || typeof block !== "object") continue;
      const type = (block as { type?: unknown }).type;
      const text = (block as { text?: unknown }).text;
      if (type === "output_text" && typeof text === "string") {
        textParts.push(text);
      }
    }
  }
  return textParts.join("\n").trim();
}

function parseResponseContent(
  transport: ResolvedProviderTransport,
  data: unknown,
): string {
  const payload = data as {
    choices?: Array<{ message?: { content?: unknown } }>;
    content?: unknown;
    output_text?: unknown;
    output?: unknown;
  };
  if (
    transport.apiSurface === "openai-responses" ||
    transport.apiSurface === "openai-codex-responses"
  ) {
    if (typeof payload?.output_text === "string" && payload.output_text.trim().length > 0) {
      return payload.output_text.trim();
    }
    const parsedOutput = extractResponseOutputText(payload?.output);
    if (parsedOutput) {
      return parsedOutput;
    }
  }

  const chatContent = payload?.choices?.[0]?.message?.content;
  if (typeof chatContent === "string" && chatContent.trim().length > 0) {
    return chatContent.trim();
  }
  if (typeof payload?.content === "string" && payload.content.trim().length > 0) {
    return payload.content.trim();
  }
  throw new Error(
    `response_parse_failed: provider ${transport.providerName} returned no parseable text content`,
  );
}

async function resolveBearerToken(
  transport: ResolvedProviderTransport,
  api: OpenClawPluginApi,
): Promise<string | undefined> {
  const staticToken = transport.staticApiKey?.trim();
  const dynamicRequired =
    !staticToken || transport.authMode === "oauth" || transport.authMode === "token";

  if (!dynamicRequired) {
    return staticToken;
  }

  const resolver = api.runtime?.modelAuth?.resolveApiKeyForProvider;
  if (!resolver) {
    if (staticToken) return staticToken;
    if (transport.authMode === "oauth" || transport.authMode === "token") {
      throw new LLMHttpError(
        401,
        `Provider "${transport.providerName}" requires runtime auth resolution, but runtime.modelAuth is unavailable`,
      );
    }
    return undefined;
  }

  try {
    const authResult = await resolver({
      provider: transport.providerName,
      cfg: resolveRuntimeConfig(api),
    });
    const token = authResult.apiKey?.trim();
    if (token) return token;
    if (transport.authMode === "oauth" || transport.authMode === "token") {
      throw new LLMHttpError(
        401,
        `Auth resolution returned empty token for provider "${transport.providerName}"`,
      );
    }
    return staticToken;
  } catch (error: unknown) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new LLMHttpError(
      401,
      `Auth resolution failed for provider "${transport.providerName}": ${detail}`,
    );
  }
}

/**
 * Create an LLM call function that mimics OpenClaw provider routing and payload semantics.
 * Returns null when the model cannot be resolved via effective providers.
 */
function createGatewayLLMCallFn(
  cfg: SecLawConfig,
  api: OpenClawPluginApi,
): LLMCallFn | null {
  const initial = resolveProviderTransport(cfg.llm.model, api);

  if (!initial) {
    return null;
  }

  return async (params) => {
    const current = resolveProviderTransport(params.model, api) ?? initial;

    // Force /chat/completions for non-codex. SecLaw audit calls are simple
    // (user messages only, no streaming) and other surfaces have extra constraints.
    const effective: ResolvedProviderTransport =
      current.apiSurface === "openai-codex-responses"
        ? current
        : {
            ...current,
            apiSurface: "openai-completions",
            endpoint: appendEndpoint(stripApiPath(current.endpoint), "/chat/completions"),
          };

    const bearerToken = await resolveBearerToken(current, api);

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...buildAttributionHeaders(effective),
    };
    if (bearerToken) {
      headers["Authorization"] = `Bearer ${bearerToken}`;
    }

    const response = await fetch(effective.endpoint, {
      method: "POST",
      headers,
      body: JSON.stringify(buildRequestPayload(effective, params)),
    });

    if (!response.ok) {
      if (response.status === 429) {
        const retryAfter = response.headers.get("Retry-After");
        const retryAfterMs = retryAfter
          ? parseInt(retryAfter, 10) * 1000
          : undefined;
        throw new LLMHttpError(
          response.status,
          response.statusText,
          retryAfterMs,
        );
      }
      let detail = response.statusText;
      try {
        const text = (await response.text()).trim();
        if (text) {
          detail = `${detail || "HTTP Error"} - ${text.slice(0, 240)}`;
        }
      } catch {
        // ignore body parse failures on error responses
      }
      throw new LLMHttpError(response.status, detail);
    }

    const data = (await response.json()) as unknown;
    const content = parseResponseContent(effective, data);

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

export function _getRuleEngine(): RuleEngine {
  return ruleEngine;
}
export function _getLLMAuditor(): LLMAuditor {
  return llmAuditor;
}
export function _getAsyncQueue(): AsyncAuditQueue {
  return asyncQueue;
}
export function _getAuditLog(): AuditLog {
  return auditLog;
}
export function _setVarDir(dir: string): void {
  varDir = dir;
}
export function _setGatewayApi(api: OpenClawPluginApi | null): void {
  gatewayApi = api;
}
export { computeParamsFingerprint as _computeParamsFingerprint };
export { stopDashboard } from "./src/dashboard/server.js";
export { updateConfig as _updateConfig };

// ─── Default Export (OpenClaw plugin format) ───

const plugin = {
  id: "seclaw",
  name: "SecLaw",
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
