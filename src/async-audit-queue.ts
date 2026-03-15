/**
 * Async audit queue: serially processes tool calls after execution.
 * Re-classifies via rule engine; if YELLOW, runs LLM audit.
 * If danger is detected, triggers interrupt.
 */

import type {
  AuditQueueItem,
  DangerReport,
  SecAgentConfig,
} from "./config.js";
import { RuleEngine } from "./rule-engine.js";
import { LLMAuditor } from "./llm-auditor.js";
import { triggerInterrupt } from "./interrupt.js";
import { AuditLog } from "./audit-log.js";

export class AsyncAuditQueue {
  private queue: AuditQueueItem[] = [];
  private processing = false;
  private ruleEngine: RuleEngine;
  private llmAuditor: LLMAuditor;
  private auditLog: AuditLog;
  private config: SecAgentConfig;
  private fingerprints = new Set<string>();

  constructor(
    ruleEngine: RuleEngine,
    llmAuditor: LLMAuditor,
    auditLog: AuditLog,
    config: SecAgentConfig,
  ) {
    this.ruleEngine = ruleEngine;
    this.llmAuditor = llmAuditor;
    this.auditLog = auditLog;
    this.config = config;
  }

  /**
   * Enqueue a tool call for async audit.
   * Deduplicates by fingerprint.
   */
  enqueue(item: AuditQueueItem): void {
    const fingerprint = this.llmAuditor.computeFingerprint(
      item.toolName,
      item.params,
      item.intentContext.userGoal,
    );

    // Deduplicate within the current queue
    if (this.fingerprints.has(fingerprint)) return;
    this.fingerprints.add(fingerprint);

    this.queue.push(item);
    this.processNext();
  }

  /**
   * Get the current queue length (for monitoring).
   */
  get length(): number {
    return this.queue.length;
  }

  /**
   * Check if the queue is currently processing.
   */
  get isProcessing(): boolean {
    return this.processing;
  }

  /**
   * Drain the queue (for testing/shutdown).
   */
  async drain(): Promise<void> {
    while (this.queue.length > 0 || this.processing) {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }

  /**
   * Clear the queue without processing.
   */
  clear(): void {
    this.queue = [];
    this.fingerprints.clear();
    this.processing = false;
  }

  // ─── Private ───

  private async processNext(): Promise<void> {
    if (this.processing) return;
    if (this.queue.length === 0) return;

    this.processing = true;

    while (this.queue.length > 0) {
      const item = this.queue.shift()!;
      try {
        await this.auditItem(item);
      } catch {
        // Log and continue — don't let one failure stop the queue
      }
    }

    this.fingerprints.clear();
    this.processing = false;
  }

  private async auditItem(item: AuditQueueItem): Promise<void> {
    const { toolName, params, sessionKey, intentContext } = item;
    const workspacePath = undefined; // TODO: pass from context if available

    this.auditLog.logAsyncProcessStart(sessionKey, toolName);

    // Step 1: Rule engine classification
    const ruleResult = this.ruleEngine.classify(
      toolName,
      params,
      intentContext,
      workspacePath,
    );

    // GREEN → no further async audit needed
    if (ruleResult.tier === "GREEN") {
      return;
    }

    // YELLOW → LLM audit
    if (!this.config.llm.enabled) {
      return;
    }
    const startTime = Date.now();
    const ruleContext = ruleResult.ruleId
      ? { ruleId: ruleResult.ruleId, reason: ruleResult.reason }
      : undefined;
    const llmResult = await this.llmAuditor.auditWithTimeout(
      { toolName, params, intentContext, sessionKey },
      this.config.timeouts.asyncAuditMs,
      ruleContext,
    );
    const durationMs = Date.now() - startTime;

    this.auditLog.logLLMAudit(
      sessionKey,
      toolName,
      llmResult.decision,
      llmResult.reason,
      durationMs,
    );
    this.auditLog.logLLMAuditDetail(sessionKey, toolName, llmResult, durationMs);

    if (llmResult.decision === "DANGER") {
      const report: DangerReport = {
        toolName,
        params,
        reason: llmResult.reason || "Flagged as dangerous by async LLM audit",
        recommendation: llmResult.recommendation,
        timestamp: Date.now(),
        source: "async",
        ruleId: ruleResult.ruleId,
      };
      this.auditLog.logDanger(sessionKey, report);
      triggerInterrupt(sessionKey, report);
    }
  }
}
