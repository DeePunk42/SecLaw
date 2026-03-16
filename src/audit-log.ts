/**
 * Audit log: writes security audit events to JSONL files and
 * routes console output through an external logger (api.logger)
 * when running inside the OpenClaw gateway.
 */

import * as fs from "fs";
import * as path from "path";
import type {
  LoggingConfig,
  DangerReport,
  IntentContext,
  LLMAuditResult,
} from "./config.js";

export type AuditEventType =
  | "tool_classified"
  | "rule_matched"
  | "llm_audit"
  | "tool_blocked"
  | "tool_allowed"
  | "danger_detected"
  | "danger_cleared"
  | "override_used";

export interface AuditLogEntry {
  timestamp: string;
  eventType: AuditEventType;
  sessionKey: string;
  toolName?: string;
  params?: Record<string, unknown>;
  tier?: "GREEN" | "YELLOW" | "RED";
  ruleId?: string;
  decision?: string;
  reason?: string;
  source?: "sync" | "async";
  durationMs?: number;
  [key: string]: unknown;
}

/** Logger interface matching OpenClaw's PluginLogger. */
export interface ExternalLogger {
  debug?: (message: string) => void;
  info: (message: string) => void;
  warn?: (message: string) => void;
  error: (message: string) => void;
}

export type AuditLogSubscriber = (entry: AuditLogEntry) => void;

const LOG_LEVELS = { debug: 0, info: 1, warn: 2, error: 3 } as const;
type LogLevel = keyof typeof LOG_LEVELS;

const PREFIX = "[sec-agent]";

export class AuditLog {
  private config: LoggingConfig;
  private logStream: fs.WriteStream | null = null;
  private logLevel: number;
  private ext: ExternalLogger | null = null;
  private subscribers: AuditLogSubscriber[] = [];
  private recentEntries: AuditLogEntry[] = [];
  private static readonly MAX_RECENT = 500;

  constructor(config: LoggingConfig) {
    this.config = config;
    this.logLevel = LOG_LEVELS[config.level] ?? LOG_LEVELS.info;
  }

  /**
   * Attach the gateway's plugin logger so all output goes through it.
   */
  setExternalLogger(logger: ExternalLogger): void {
    this.ext = logger;
  }

  /**
   * Register a subscriber to receive new log entries in real time.
   */
  subscribe(fn: AuditLogSubscriber): void {
    this.subscribers.push(fn);
  }

  /**
   * Remove a previously registered subscriber.
   */
  unsubscribe(fn: AuditLogSubscriber): void {
    const idx = this.subscribers.indexOf(fn);
    if (idx !== -1) this.subscribers.splice(idx, 1);
  }

  /**
   * Return the most recent N log entries from the ring buffer.
   */
  getRecentEntries(limit?: number): AuditLogEntry[] {
    if (limit === undefined || limit >= this.recentEntries.length) {
      return [...this.recentEntries];
    }
    return this.recentEntries.slice(-limit);
  }

  /**
   * Update logging config at runtime (used by dashboard config editor).
   */
  setLoggingConfig(newConfig: LoggingConfig): void {
    this.config = newConfig;
    this.logLevel = LOG_LEVELS[newConfig.level] ?? LOG_LEVELS.info;
  }

  /**
   * Initialize the JSONL log file stream.
   */
  init(logDir: string): void {
    if (!this.config.auditJsonl) return;

    try {
      if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir, { recursive: true });
      }
      const logFile = path.join(logDir, "sec-agent-audit.jsonl");
      this.logStream = fs.createWriteStream(logFile, { flags: "a" });
    } catch {
      // Silently fail — audit log is best-effort
    }
  }

  // ─── Core logging (routes through external logger when available) ───

  shouldLog(level: LogLevel): boolean {
    return LOG_LEVELS[level] >= this.logLevel;
  }

  debug(msg: string): void {
    if (!this.shouldLog("debug")) return;
    if (this.ext?.debug) this.ext.debug(`${PREFIX} ${msg}`);
    else console.debug(`${PREFIX} ${msg}`);
  }

  info(msg: string): void {
    if (!this.shouldLog("info")) return;
    if (this.ext) this.ext.info(`${PREFIX} ${msg}`);
    else console.info(`${PREFIX} ${msg}`);
  }

  warn(msg: string): void {
    if (!this.shouldLog("warn")) return;
    if (this.ext?.warn) this.ext.warn(`${PREFIX} ${msg}`);
    else if (this.ext) this.ext.error(`${PREFIX} [WARN] ${msg}`);
    else console.warn(`${PREFIX} ${msg}`);
  }

  error(msg: string): void {
    if (!this.shouldLog("error")) return;
    if (this.ext) this.ext.error(`${PREFIX} ${msg}`);
    else console.error(`${PREFIX} ${msg}`);
  }

  // ─── JSONL file logging ───

  log(entry: AuditLogEntry): void {
    // Ring buffer + subscriber notification always active (independent of JSONL)
    this.recentEntries.push(entry);
    if (this.recentEntries.length > AuditLog.MAX_RECENT) {
      this.recentEntries.shift();
    }
    for (const fn of this.subscribers) {
      try { fn(entry); } catch { /* best-effort */ }
    }

    // JSONL file write (conditional)
    if (!this.config.auditJsonl || !this.logStream) return;

    try {
      const sanitized = { ...entry };
      if (sanitized.params) {
        const paramStr = JSON.stringify(sanitized.params);
        if (paramStr.length > 1000) {
          sanitized.params = {
            _truncated: paramStr.slice(0, 1000) + "...",
          } as Record<string, unknown>;
        }
      }
      this.logStream.write(JSON.stringify(sanitized) + "\n");
    } catch {
      // Best-effort
    }
  }

  // ─── Structured event logging ───
  //
  // Visibility at each log level:
  //   debug : every step (classify, rule, LLM, allow, queue)
  //   info  : YELLOW classify + final decision (ALLOW/BLOCK) + DANGER
  //   warn  : danger flag found
  //   error : DANGER detection

  logBeforeToolCallStart(
    _sessionKey: string,
    _toolName: string,
    _params: Record<string, unknown>,
  ): void {
    // Intentionally silent — kept for JSONL / future use
  }

  logDangerFlagCheck(sessionKey: string, found: boolean): void {
    if (found) {
      this.warn(`🚩 Danger flag active -- all subsequent tool calls will be blocked`);
    } else {
      this.debug(`Danger flag: clear`);
    }
  }

  logClassification(
    sessionKey: string,
    toolName: string,
    params: Record<string, unknown>,
    tier: "GREEN" | "YELLOW" | "RED",
  ): void {
    const paramSummary = this.summarizeParams(toolName, params);
    if (tier === "GREEN") {
      this.debug(`🟢 GREEN ${toolName}(${paramSummary}) -- no audit`);
    } else if (tier === "YELLOW") {
      this.debug(`🟡 YELLOW ${toolName}(${paramSummary}) -- deferred to async audit`);
    } else {
      this.info(`🔴 RED ${toolName}(${paramSummary}) -- requires sync audit`);
    }

    this.log({
      timestamp: new Date().toISOString(),
      eventType: "tool_classified",
      sessionKey,
      toolName,
      params,
      tier,
    });
  }

  logRuleMatch(
    sessionKey: string,
    toolName: string,
    ruleId: string,
    decision: string,
    reason?: string,
  ): void {
    this.log({
      timestamp: new Date().toISOString(),
      eventType: "rule_matched",
      sessionKey,
      toolName,
      ruleId,
      decision,
      reason,
    });
  }

  logNoRuleMatch(_sessionKey: string, _toolName: string): void {
    // Intentionally silent
  }

  logLLMAuditStart(_sessionKey: string, _toolName: string): void {
    // Intentionally silent
  }

  logLLMAudit(
    sessionKey: string,
    toolName: string,
    decision: string,
    reason?: string,
    durationMs?: number,
  ): void {
    this.log({
      timestamp: new Date().toISOString(),
      eventType: "llm_audit",
      sessionKey,
      toolName,
      decision,
      reason,
      durationMs,
    });
  }

  logLLMSkipped(sessionKey: string, toolName: string): void {
    this.debug(`⏭️ LLM audit skipped (LLM disabled)`);
  }

  logBlock(
    sessionKey: string,
    toolName: string,
    reason: string,
    source: "sync" | "async",
  ): void {
    // BLOCKED is always visible at info level
    this.info(`⛔ BLOCKED ${toolName} [${source}] -- ${reason.split("\n")[0]}`);

    this.log({
      timestamp: new Date().toISOString(),
      eventType: "tool_blocked",
      sessionKey,
      toolName,
      reason,
      source,
    });
  }

  logAllow(sessionKey: string, toolName: string, reason: string): void {
    // Final ALLOW decision visible at info for YELLOW (caller already logged YELLOW at info)
    this.info(`✅ ALLOW ${toolName} -- ${reason}`);

    this.log({
      timestamp: new Date().toISOString(),
      eventType: "tool_allowed",
      sessionKey,
      toolName,
      reason,
    });
  }

  logDanger(sessionKey: string, report: DangerReport): void {
    this.error(
      `🚨 DANGER ${report.toolName} [${report.source}]${report.ruleId ? ` rule=${report.ruleId}` : ""} -- ${report.reason}`,
    );

    this.log({
      timestamp: new Date().toISOString(),
      eventType: "danger_detected",
      sessionKey,
      toolName: report.toolName,
      reason: report.reason,
      source: report.source,
      ruleId: report.ruleId,
    });
  }

  logOverrideUsed(sessionKey: string, toolName: string): void {
    this.warn(`🔓 OVERRIDE ${toolName} -- trusted sender confirmed override`);
    this.log({
      timestamp: new Date().toISOString(),
      eventType: "override_used",
      sessionKey,
      toolName,
    });
  }

  logAsyncEnqueue(
    _sessionKey: string,
    _toolName: string,
    _queueLength: number,
  ): void {
    // Intentionally silent
  }

  logAsyncProcessStart(_sessionKey: string, _toolName: string): void {
    // Intentionally silent
  }

  logIntentUpdate(sessionKey: string, field: string, value: string): void {
    this.debug(
      `🧠 Intent: ${field} = "${value.slice(0, 80)}${value.length > 80 ? "..." : ""}"`,
    );
  }

  // ─── Debug: full intent context dump ───

  logIntentContext(
    sessionKey: string,
    toolName: string,
    ctx: IntentContext,
    maxRecentCalls?: number,
  ): void {
    if (!this.shouldLog("debug")) return;

    const n = maxRecentCalls ?? 3;
    const recentSlice = ctx.recentToolCalls.slice(-n);

    this.debug(`🔍 ──── intent context ────`);
    this.debug(`  userGoal   : ${ctx.userGoal || "(empty)"}`);
    this.debug(`  senderLabel: ${ctx.senderLabel || "(unknown)"}`);
    this.debug(`  channelId  : ${ctx.channelId || "(unknown)"}`);
    this.debug(`  trigger    : ${ctx.trigger || "(unknown)"}`);
    this.debug(`  agentId    : ${ctx.agentId || "(unknown)"}`);
    this.debug(`  messageProvider: ${ctx.messageProvider || "(unknown)"}`);
    this.debug(`  turn       : ${ctx.turnNumber}  step: ${ctx.stepIndex}`);
    if (recentSlice.length > 0) {
      this.debug(`  recentCalls: (${recentSlice.length})`);
      for (const call of recentSlice) {
        const paramSnippet = this.summarizeParams(call.toolName, call.params);
        this.debug(`    - ${call.toolName}(${paramSnippet}) → ${call.outcome}`);
      }
    } else {
      this.debug(`  recentCalls: (none)`);
    }
    this.debug(`────────────────────────`);

    this.log({
      timestamp: new Date().toISOString(),
      eventType: "tool_classified",
      sessionKey,
      toolName,
      intentContext: ctx as unknown as Record<string, unknown>,
    });
  }

  // ─── Debug: full LLM audit detail ───

  logLLMAuditDetail(
    _sessionKey: string,
    _toolName: string,
    _result: LLMAuditResult,
    _durationMs: number,
  ): void {
    // Intentionally silent
  }

  close(): void {
    if (this.logStream) {
      this.logStream.end();
      this.logStream = null;
    }
  }

  // ─── Helpers ───

  private summarizeParams(
    toolName: string,
    params: Record<string, unknown>,
  ): string {
    if (toolName === "exec" || toolName === "bash") {
      const cmd = typeof params.command === "string" ? params.command : "";
      return cmd.length > 80 ? cmd.slice(0, 80) + "..." : cmd;
    }
    if (
      toolName === "fs_write" ||
      toolName === "fs_read" ||
      toolName === "fs_delete" ||
      toolName === "read"
    ) {
      return typeof params.path === "string"
        ? params.path
        : JSON.stringify(params).slice(0, 80);
    }
    if (toolName === "web_fetch") {
      return typeof params.url === "string"
        ? params.url
        : JSON.stringify(params).slice(0, 80);
    }
    const str = JSON.stringify(params);
    return str.length > 80 ? str.slice(0, 80) + "..." : str;
  }
}
