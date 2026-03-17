// ─── Shared Types ───

export type Tier = "GREEN" | "YELLOW" | "RED";

export type AuditDecision = "SAFE" | "DANGER";

export type ToolCallOutcome = "success" | "error" | "blocked";

export interface IntentContext {
  userGoal: string;
  senderLabel?: string;
  channelId?: string;
  trigger?: string;
  agentId?: string;
  messageProvider?: string;
  stepIndex: number;
  turnNumber: number;
  recentToolCalls: Array<{
    toolName: string;
    params: Record<string, unknown>;
    outcome: ToolCallOutcome;
  }>;
}

export interface RuleCondition {
  type:
    | "command_matches"
    | "command_starts_with"
    | "pipe_to_shell"
    | "path_in_workspace"
    | "path_matches"
    | "url_is_internal"
    | "has_dynamic_expansion"
    | "is_dangerous_command"
    | "reads_sensitive_files"
    | "is_sensitive_write_path"
    | "url_is_metadata"
    | "url_is_credential";
  pattern?: string;
  prefix?: string;
  value?: boolean;
}

export interface Rule {
  id: string;
  name: string;
  toolMatch: string[];
  conditions: RuleCondition[];
  tier: Tier;
  reason?: string;
  priority: number;
}

export interface RuleResult {
  tier: Tier;
  ruleId?: string;
  reason?: string;
}

export type LLMErrorCategory =
  | "rate_limited"    // 429
  | "auth_error"      // 401, 403
  | "server_error"    // 5xx
  | "network_error"   // DNS/connection failure
  | "unknown_error";  // Other (including plain Error from test mocks)

export interface LLMErrorInfo {
  category: LLMErrorCategory;
  statusCode?: number;
  retryAfterMs?: number;   // 429 Retry-After header
  message: string;
  timestamp: number;
}

export interface RetryConfig {
  maxRetries: number;          // default 2
  initialBackoffMs: number;    // default 1000, doubles each retry
  cooldownMs: number;          // default 30000
  cooldownThreshold: number;   // consecutive 429 count to trigger cooldown, default 3
}

export interface LLMAuditResult {
  decision: AuditDecision;
  reason?: string;
  recommendation?: string;
  /** The prompt sent to LLM (populated only when debug logging is useful). */
  _prompt?: string;
  /** The raw LLM response text. */
  _rawResponse?: string;
  /** Whether the result came from cache. */
  _cached?: boolean;
  /** Populated when the result was produced due to an LLM service error (not a security evaluation). */
  _errorInfo?: LLMErrorInfo;
}

export interface AuditQueueItem {
  toolName: string;
  params: Record<string, unknown>;
  result?: unknown;
  sessionKey: string;
  intentContext: IntentContext;
  timestamp: number;
  toolCallId?: string;
}

export interface DangerReport {
  toolName: string;
  params: Record<string, unknown>;
  reason: string;
  recommendation?: string;
  timestamp: number;
  source: "sync" | "async";
  ruleId?: string;
}

export interface PendingOverride {
  pin: string;                    // 6-digit decimal (e.g. "038291")
  toolName: string;
  paramsFingerprint: string;      // SHA256(toolName:JSON(params))
  timestamp: number;
  toolCallId?: string;            // original blocked toolCallId (for override backtracking)
}

// ─── Plugin Hook Types (mirroring OpenClaw's plugin system) ───

export interface PluginHookBeforeToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
}

export interface PluginHookBeforeToolCallResult {
  block?: boolean;
  blockReason?: string;
  params?: Record<string, unknown>;
}

export interface PluginHookAfterToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
  result?: unknown;
}

export interface PluginHookToolContext {
  sessionKey: string;
  workspacePath?: string;
  agentId?: string;
}

// ─── Configuration ───

export interface LLMConfig {
  model: string;
  enabled: boolean;
  maxConcurrent: number;
  /** Gateway internal endpoint for LLM calls (e.g. "http://127.0.0.1:3000/v1/chat/completions") */
  endpoint?: string;
  /** Auth token for the gateway endpoint */
  apiKey?: string;
  /** Number of recent tool calls to include in the LLM audit prompt (default 3) */
  promptRecentCalls?: number;
  /** Trusted sender labels; operations from other senders get extra scrutiny */
  trustedSenderLabels?: string[];
  /** Retry configuration for transient LLM errors (429, 5xx) */
  retry?: RetryConfig;
}

export interface TimeoutConfig {
  syncAuditMs: number;
  asyncAuditMs: number;
  syncTimeoutPolicy: "fail_closed" | "fail_open";
}

export interface LoggingConfig {
  level: "debug" | "info" | "warn" | "error";
  auditJsonl: boolean;
}

export interface AgentProfileConfig {
  classification?: {
    safeCommands?: string[];
  };
}

export interface DashboardConfig {
  enabled: boolean;
  port: number;
  host: string;
}

export interface SecLawConfig {
  llm: LLMConfig;
  timeouts: TimeoutConfig;
  logging: LoggingConfig;
  dashboard?: DashboardConfig;
  rules?: { extra?: Rule[] };
  agentProfiles?: Record<string, AgentProfileConfig>;
}

const DEFAULT_CONFIG: SecLawConfig = {
  llm: {
    model: "",
    enabled: true,
    maxConcurrent: 2,
    trustedSenderLabels: ["openclaw-control-ui"],
    retry: {
      maxRetries: 2,
      initialBackoffMs: 1000,
      cooldownMs: 30000,
      cooldownThreshold: 3,
    },
  },
  timeouts: {
    syncAuditMs: 30000,
    asyncAuditMs: 30000,
    syncTimeoutPolicy: "fail_closed",
  },
  logging: {
    level: "debug",
    auditJsonl: true,
  },
  dashboard: {
    enabled: true,
    port: 19198,
    host: "0.0.0.0",
  },
};

export function loadConfig(partial?: Partial<SecLawConfig>): SecLawConfig {
  if (!partial) return { ...DEFAULT_CONFIG };
  return {
    llm: { ...DEFAULT_CONFIG.llm, ...partial.llm },
    timeouts: { ...DEFAULT_CONFIG.timeouts, ...partial.timeouts },
    logging: { ...DEFAULT_CONFIG.logging, ...partial.logging },
    dashboard: { ...DEFAULT_CONFIG.dashboard!, ...partial.dashboard },
    rules: partial.rules,
    agentProfiles: partial.agentProfiles,
  };
}
