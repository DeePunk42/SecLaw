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
  LLMErrorInfo,
} from "./config.js";

export type AuditEventType =
  | "tool_classified"
  | "rule_matched"
  | "llm_audit"
  | "tool_blocked"
  | "tool_allowed"
  | "danger_detected"
  | "danger_cleared"
  | "override_used"
  | "async_audit_enqueued"
  | "async_audit_complete"
  | "intent_context"
  | "llm_service_error";

export interface AuditLogEntry {
  timestamp: string;
  eventType: AuditEventType;
  sessionKey: string;
  toolName?: string;
  params?: Record<string, unknown>;
  intentContext?: Record<string, unknown>;
  tier?: "GREEN" | "YELLOW" | "RED";
  ruleId?: string;
  decision?: string;
  reason?: string;
  source?: "sync" | "async";
  durationMs?: number;
  toolCallId?: string;
  [key: string]: unknown;
}

export interface ToolCallRecord {
  toolCallId: string;
  sessionKey: string;
  toolName: string;
  startedAt: string;
  updatedAt: string;
  tier?: "GREEN" | "YELLOW" | "RED";
  ruleId?: string;
  ruleReason?: string;
  finalStatus: "allowed" | "blocked" | "overridden" | "pending";
  syncAudit?: { decision: string; reason?: string; durationMs?: number };
  asyncAuditStatus?: "enqueued" | "complete";
  asyncAudit?: { decision: string; reason?: string; durationMs?: number };
  dangerDetected?: boolean;
  overridePin?: string;
  overrideUsed?: boolean;
  intentContext?: Record<string, unknown>;
  params?: Record<string, unknown>;
  blockReason?: string;
  blockSource?: "sync" | "async";
  serviceError?: {
    category: string;
    statusCode?: number;
    message: string;
  };
  events: AuditLogEntry[];
}

export type ToolCallSubscriber = (record: ToolCallRecord) => void;

/** Logger interface matching OpenClaw's PluginLogger. */
export interface ExternalLogger {
  debug?: (message: string) => void;
  info: (message: string) => void;
  warn: (message: string) => void;
  error: (message: string) => void;
}

export type AuditLogSubscriber = (entry: AuditLogEntry) => void;

const LOG_LEVELS = { debug: 0, info: 1, warn: 2, error: 3 } as const;
type LogLevel = keyof typeof LOG_LEVELS;

const PREFIX = "[seclaw]";

export class AuditLog {
  private config: LoggingConfig;
  private logStream: fs.WriteStream | null = null;
  private logLevel: number;
  private ext: ExternalLogger | null = null;
  private subscribers: AuditLogSubscriber[] = [];
  private recentEntries: AuditLogEntry[] = [];
  private static readonly MAX_RECENT = 500;

  private toolCallRecords = new Map<string, ToolCallRecord>();
  private toolCallIds: string[] = [];
  private static readonly MAX_TOOL_CALL_RECORDS = 500;
  private toolCallSubscribers: ToolCallSubscriber[] = [];
  private toolCallStream: fs.WriteStream | null = null;
  private toolCallLogDir: string | null = null;

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
   * Register a subscriber to receive ToolCallRecord updates in real time.
   */
  subscribeToolCalls(fn: ToolCallSubscriber): void {
    this.toolCallSubscribers.push(fn);
  }

  /**
   * Remove a previously registered ToolCallRecord subscriber.
   */
  unsubscribeToolCalls(fn: ToolCallSubscriber): void {
    const idx = this.toolCallSubscribers.indexOf(fn);
    if (idx !== -1) this.toolCallSubscribers.splice(idx, 1);
  }

  /**
   * Return ToolCallRecords in order, optionally limited.
   */
  getToolCallRecords(limit?: number): ToolCallRecord[] {
    const ids = limit !== undefined
      ? this.toolCallIds.slice(-limit)
      : this.toolCallIds;
    const result: ToolCallRecord[] = [];
    for (const id of ids) {
      const rec = this.toolCallRecords.get(id);
      if (rec) result.push(rec);
    }
    return result;
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
      const logFile = path.join(logDir, "seclaw-audit.jsonl");
      this.logStream = fs.createWriteStream(logFile, { flags: "a" });
    } catch {
      // Silently fail — audit log is best-effort
    }
  }

  /**
   * Initialize tool call log persistence (JSONL).
   * Loads existing records from disk and opens a write stream for new ones.
   */
  initToolCallLog(logDir: string): void {
    try {
      this.toolCallLogDir = logDir;
      fs.mkdirSync(logDir, { recursive: true });
      this.loadPersistedToolCalls(path.join(logDir, "tool-calls.jsonl"));
      this.toolCallStream = fs.createWriteStream(
        path.join(logDir, "tool-calls.jsonl"),
        { flags: "a" },
      );
      this.toolCallStream.on("error", () => {
        // Best-effort — stream errors (e.g. directory removed) are silently ignored
        this.toolCallStream = null;
      });
    } catch {
      // Best-effort — persistence failure shouldn't block the plugin
    }
  }

  private loadPersistedToolCalls(filePath: string): void {
    try {
      if (!fs.existsSync(filePath)) return;
      const content = fs.readFileSync(filePath, "utf-8");
      const lines = content.split("\n").filter((l) => l.trim());

      // Deduplicate by toolCallId (last occurrence wins)
      const deduped = new Map<string, Record<string, unknown>>();
      for (const line of lines) {
        try {
          const parsed = JSON.parse(line) as Record<string, unknown>;
          if (typeof parsed.toolCallId === "string") {
            deduped.set(parsed.toolCallId, parsed);
          }
        } catch {
          // Skip malformed lines
        }
      }

      // Take last MAX records
      const entries = [...deduped.entries()];
      const start = Math.max(0, entries.length - AuditLog.MAX_TOOL_CALL_RECORDS);
      const trimmed = entries.slice(start);

      for (const [id, data] of trimmed) {
        const record: ToolCallRecord = {
          toolCallId: id,
          sessionKey: (data.sessionKey as string) || "",
          toolName: (data.toolName as string) || "unknown",
          startedAt: (data.startedAt as string) || "",
          updatedAt: (data.updatedAt as string) || "",
          tier: data.tier as ToolCallRecord["tier"],
          ruleId: data.ruleId as string | undefined,
          ruleReason: data.ruleReason as string | undefined,
          finalStatus: (data.finalStatus as ToolCallRecord["finalStatus"]) || "pending",
          syncAudit: data.syncAudit as ToolCallRecord["syncAudit"],
          asyncAuditStatus: data.asyncAuditStatus as ToolCallRecord["asyncAuditStatus"],
          asyncAudit: data.asyncAudit as ToolCallRecord["asyncAudit"],
          dangerDetected: data.dangerDetected as boolean | undefined,
          overridePin: data.overridePin as string | undefined,
          overrideUsed: data.overrideUsed as boolean | undefined,
          intentContext: data.intentContext as Record<string, unknown> | undefined,
          params: data.params as Record<string, unknown> | undefined,
          blockReason: data.blockReason as string | undefined,
          blockSource: data.blockSource as "sync" | "async" | undefined,
          serviceError: data.serviceError as ToolCallRecord["serviceError"],
          events: [],
        };
        this.toolCallRecords.set(id, record);
        this.toolCallIds.push(id);
      }
    } catch {
      // Best-effort — failed load doesn't block startup
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

    // Aggregate into ToolCallRecord if toolCallId is present
    if (entry.toolCallId) {
      this.aggregateIntoToolCallRecord(entry.toolCallId, entry);
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

  private aggregateIntoToolCallRecord(toolCallId: string, entry: AuditLogEntry): void {
    let record = this.toolCallRecords.get(toolCallId);
    if (!record) {
      record = {
        toolCallId,
        sessionKey: entry.sessionKey,
        toolName: entry.toolName || "unknown",
        startedAt: entry.timestamp,
        updatedAt: entry.timestamp,
        finalStatus: "pending",
        events: [],
      };
      this.toolCallRecords.set(toolCallId, record);
      this.toolCallIds.push(toolCallId);

      // Evict oldest if over limit
      while (this.toolCallIds.length > AuditLog.MAX_TOOL_CALL_RECORDS) {
        const oldId = this.toolCallIds.shift()!;
        this.toolCallRecords.delete(oldId);
      }
    }

    record.updatedAt = entry.timestamp;
    record.events.push(entry);

    switch (entry.eventType) {
      case "tool_classified":
        if (entry.tier) record.tier = entry.tier;
        if (entry.params) record.params = entry.params;
        // GREEN/YELLOW → default to allowed (may be overridden by later events)
        if (entry.tier === "GREEN" || entry.tier === "YELLOW") {
          record.finalStatus = "allowed";
        }
        break;
      case "rule_matched":
        record.ruleId = entry.ruleId;
        if (entry.reason) record.ruleReason = entry.reason;
        break;
      case "intent_context":
        if (entry.intentContext) {
          record.intentContext = entry.intentContext as Record<string, unknown>;
        }
        break;
      case "llm_audit":
        record.syncAudit = {
          decision: entry.decision || "unknown",
          reason: entry.reason,
          durationMs: entry.durationMs,
        };
        break;
      case "tool_blocked":
        record.finalStatus = "blocked";
        if (entry.overridePin) {
          record.overridePin = entry.overridePin as string;
        }
        if (entry.params) {
          record.params = entry.params as Record<string, unknown>;
        }
        if (entry.intentContext) {
          record.intentContext = entry.intentContext as Record<string, unknown>;
        }
        if (entry.reason) {
          record.blockReason = entry.reason as string;
        }
        if (entry.source) {
          record.blockSource = entry.source as "sync" | "async";
        }
        break;
      case "tool_allowed":
        record.finalStatus = "allowed";
        break;
      case "async_audit_enqueued":
        record.asyncAuditStatus = "enqueued";
        break;
      case "async_audit_complete":
        record.asyncAuditStatus = "complete";
        record.asyncAudit = {
          decision: entry.decision || "unknown",
          reason: entry.reason,
          durationMs: entry.durationMs,
        };
        if (entry.decision === "DANGER") {
          record.dangerDetected = true;
        }
        break;
      case "override_used":
        record.finalStatus = "overridden";
        record.overrideUsed = true;
        break;
      case "danger_detected":
        record.dangerDetected = true;
        break;
      case "llm_service_error":
        record.serviceError = {
          category: (entry.errorCategory as string) || "unknown",
          statusCode: entry.statusCode as number | undefined,
          message: (entry.reason as string) || "",
        };
        break;
    }

    // Notify subscribers
    for (const fn of this.toolCallSubscribers) {
      try { fn(record); } catch { /* best-effort */ }
    }

    // Persist to JSONL (without events array)
    if (this.toolCallStream) {
      try {
        const { events, ...persistable } = record;
        this.toolCallStream.write(JSON.stringify(persistable) + "\n");
      } catch { /* best-effort */ }
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
    toolCallId?: string,
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
      toolCallId,
    });
  }

  logRuleMatch(
    sessionKey: string,
    toolName: string,
    ruleId: string,
    decision: string,
    reason?: string,
    toolCallId?: string,
  ): void {
    this.log({
      timestamp: new Date().toISOString(),
      eventType: "rule_matched",
      sessionKey,
      toolName,
      ruleId,
      decision,
      reason,
      toolCallId,
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
    toolCallId?: string,
  ): void {
    this.log({
      timestamp: new Date().toISOString(),
      eventType: "llm_audit",
      sessionKey,
      toolName,
      decision,
      reason,
      durationMs,
      toolCallId,
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
    toolCallId?: string,
    overridePin?: string,
    params?: Record<string, unknown>,
    intentContext?: IntentContext,
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
      toolCallId,
      overridePin,
      params,
      intentContext: intentContext as unknown as Record<string, unknown> | undefined,
    });
  }

  logAllow(sessionKey: string, toolName: string, reason: string, toolCallId?: string): void {
    // Final ALLOW decision visible at info for YELLOW (caller already logged YELLOW at info)
    this.info(`✅ ALLOW ${toolName} -- ${reason}`);

    this.log({
      timestamp: new Date().toISOString(),
      eventType: "tool_allowed",
      sessionKey,
      toolName,
      reason,
      toolCallId,
    });
  }

  logDanger(sessionKey: string, report: DangerReport, toolCallId?: string): void {
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
      toolCallId,
    });
  }

  logOverrideUsed(sessionKey: string, toolName: string, toolCallId?: string): void {
    this.warn(`🔓 OVERRIDE ${toolName} -- trusted sender confirmed override`);
    this.log({
      timestamp: new Date().toISOString(),
      eventType: "override_used",
      sessionKey,
      toolName,
      toolCallId,
    });
  }

  logAsyncEnqueue(
    sessionKey: string,
    toolName: string,
    queueLength: number,
    toolCallId?: string,
  ): void {
    this.log({
      timestamp: new Date().toISOString(),
      eventType: "async_audit_enqueued",
      sessionKey,
      toolName,
      queueLength,
      toolCallId,
    });
  }

  logAsyncAuditComplete(
    sessionKey: string,
    toolName: string,
    decision: string,
    reason?: string,
    durationMs?: number,
    toolCallId?: string,
  ): void {
    this.log({
      timestamp: new Date().toISOString(),
      eventType: "async_audit_complete",
      sessionKey,
      toolName,
      decision,
      reason,
      durationMs,
      toolCallId,
    });
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
    toolCallId?: string,
  ): void {
    // Console output gated by debug level
    if (this.shouldLog("debug")) {
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
    }

    // Always log for ToolCallRecord aggregation + SSE push
    // Truncate recentToolCalls to match promptRecentCalls setting
    const n = maxRecentCalls ?? 3;
    const truncatedCtx = {
      ...ctx,
      recentToolCalls: ctx.recentToolCalls.slice(-n),
    };
    this.log({
      timestamp: new Date().toISOString(),
      eventType: "intent_context",
      sessionKey,
      toolName,
      intentContext: truncatedCtx as unknown as Record<string, unknown>,
      toolCallId,
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

  logLLMServiceError(
    sessionKey: string,
    toolName: string,
    errorInfo: LLMErrorInfo,
    toolCallId?: string,
  ): void {
    this.warn(`⚠️ LLM service error: ${errorInfo.category}${errorInfo.statusCode ? ` (${errorInfo.statusCode})` : ""} — ${errorInfo.message}`);

    this.log({
      timestamp: new Date().toISOString(),
      eventType: "llm_service_error",
      sessionKey,
      toolName,
      errorCategory: errorInfo.category,
      statusCode: errorInfo.statusCode,
      reason: errorInfo.message,
      toolCallId,
    });
  }

  close(): void {
    if (this.logStream) {
      this.logStream.end();
      this.logStream = null;
    }
    if (this.toolCallStream) {
      this.toolCallStream.end();
      this.toolCallStream = null;
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
