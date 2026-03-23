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

// ─── Platform ───

export type Platform = "linux" | "macos" | "windows";

// ─── Sigma-Style Rule Types ───

/** Raw YAML rule before compilation */
export interface SigmaRule {
  id: string;
  name: string;
  tool: string[];
  platform?: Platform[];
  tier: Tier;
  priority: number;
  reason?: string;
  tags?: string[];
  detection: DetectionBlock;
}

/** Detection block: named selections + condition expression */
export interface DetectionBlock {
  [selectionName: string]: SelectionFields | string;
  condition: string;
}

/** A selection: field|modifier → value mappings (AND within one selection) */
export type SelectionFields = Record<string, unknown>;

/** Compiled rule ready for matching */
export interface CompiledRule {
  id: string;
  name: string;
  tool: string[];
  platform?: Platform[];
  tier: Tier;
  priority: number;
  reason?: string;
  tags?: string[];
  matcher: (ctx: MatchContext) => boolean;
}

/** Command decomposition (exec tool only) */
export interface CommandDecomposition {
  primary: string | null;
  all: string[];
  segments: string[];
}

/** File path decomposition */
export interface FileDecomposition {
  dir: string;
  name: string;
  ext: string;
  inWorkspace: boolean;
}

/** URL decomposition */
export interface URLDecomposition {
  host: string;
  port: number | null;
  path: string;
  scheme: string;
  isPrivateIP: boolean;
}

/** Context passed to rule matchers */
export interface MatchContext {
  tool: string;
  params: Record<string, unknown>;
  platform: Platform;
  workspacePath?: string;

  // Raw param shortcuts
  command?: string;
  path?: string;
  url?: string;
  action?: string;
  host?: string;
  elevated?: boolean;
  content?: string;
  query?: string;

  // Decomposition caches (lazily computed)
  cmd?: CommandDecomposition;
  file?: FileDecomposition;
  urlParsed?: URLDecomposition;

  // Extension point for future features
  ext: Record<string, unknown>;
}

/** Pre-classify hook for future extensions (e.g., script detection) */
export type PreClassifyHook = (ctx: MatchContext) => void | Promise<void>;

/** YAML rule file structure with lists, macros, and rules */
export interface RuleFile {
  lists?: Record<string, string[]>;
  macros?: Record<string, { detection: DetectionBlock }>;
  rules: SigmaRule[];
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
  /** Whether the sender was trusted at enqueue time. */
  trusted: boolean;
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
  /** Number of recent tool calls to include in the LLM audit prompt (default 3) */
  promptRecentCalls?: number;
  /** Trusted sender labels; operations from other senders get extra scrutiny */
  trustedSenderLabels?: string[];
  /** Retry configuration for transient LLM errors (429, 5xx) */
  retry?: RetryConfig;
  /** Explicit API key for SecLaw's own LLM calls. Bypasses provider-level auth. */
  apiKey?: string;
}

export interface TimeoutConfig {
  auditTimeoutMs: number;
  syncTimeoutPolicy: "fail_closed" | "fail_open";
}

export interface LoggingConfig {
  level: "debug" | "info" | "warn" | "error";
  auditJsonl: boolean;
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
  rules?: { activeRuleFile?: string };
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
    auditTimeoutMs: 60000,
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
  rules: {
    activeRuleFile: "default.yaml",
  },
};

export function loadConfig(partial?: Partial<SecLawConfig>): SecLawConfig {
  if (!partial) return { ...DEFAULT_CONFIG };
  return {
    llm: { ...DEFAULT_CONFIG.llm, ...partial.llm },
    timeouts: { ...DEFAULT_CONFIG.timeouts, ...partial.timeouts },
    logging: { ...DEFAULT_CONFIG.logging, ...partial.logging },
    dashboard: { ...DEFAULT_CONFIG.dashboard!, ...partial.dashboard },
    rules: { ...DEFAULT_CONFIG.rules!, ...partial.rules },
  };
}
