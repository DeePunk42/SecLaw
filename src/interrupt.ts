/**
 * Danger flag management and interrupt mechanism.
 * When async audit detects danger, sets a per-session flag
 * that blocks all subsequent tool calls until cleared.
 */

import type { DangerReport } from "./config.js";
import { sessionState } from "./session-state.js";

/** Callback type for agent event emission. */
export type EmitAgentEventFn = (event: {
  stream: string;
  data: unknown;
}) => void;

/** Module-level reference to the agent event emitter (set during plugin init). */
let emitAgentEvent: EmitAgentEventFn | null = null;

/**
 * Register the agent event emitter function.
 * Called during plugin initialization.
 */
export function setEmitAgentEvent(fn: EmitAgentEventFn): void {
  emitAgentEvent = fn;
}

/**
 * Trigger an interrupt for a session.
 * Sets the danger flag and notifies the frontend.
 */
export function triggerInterrupt(
  sessionKey: string,
  report: DangerReport,
): void {
  // 1. Set per-session danger flag
  sessionState.setDangerFlag(sessionKey, report);

  // 2. Emit agent event for real-time UI notification
  if (emitAgentEvent) {
    emitAgentEvent({
      stream: "security",
      data: {
        type: "danger_detected",
        sessionKey,
        report: {
          toolName: report.toolName,
          reason: report.reason,
          recommendation: report.recommendation,
          timestamp: report.timestamp,
          source: report.source,
          ruleId: report.ruleId,
        },
      },
    });
  }
}

/**
 * Consume the danger flag for a session.
 * Returns the report if set, null otherwise.
 * The flag is cleared after consumption.
 */
export function consumeDangerFlag(
  sessionKey: string,
): DangerReport | null {
  return sessionState.consumeDangerFlag(sessionKey);
}

/**
 * Check if a session has an active danger flag without consuming it.
 */
export function hasDangerFlag(sessionKey: string): boolean {
  return sessionState.hasDangerFlag(sessionKey);
}

/**
 * Clear the danger flag for a session (e.g., after user acknowledgment).
 */
export function clearDangerFlag(sessionKey: string): void {
  sessionState.consumeDangerFlag(sessionKey);
}

/**
 * Reset all security state for a session (e.g., on /new or /reset).
 */
export function resetSession(sessionKey: string): void {
  sessionState.resetSession(sessionKey);
}

/**
 * Format a danger report into a human-readable block reason string.
 */
export function formatDangerAlert(report: DangerReport): string {
  const lines = [
    `[SecLaw] SECURITY ALERT — Operation blocked`,
    ``,
    `Tool: ${report.toolName}`,
    `Reason: ${report.reason}`,
  ];

  if (report.recommendation) {
    lines.push(`Recommendation: ${report.recommendation}`);
  }

  if (report.ruleId) {
    lines.push(`Rule: ${report.ruleId}`);
  }

  lines.push(
    ``,
    `Source: ${report.source === "async" ? "Async audit detected prior dangerous operation" : "Synchronous audit"}`,
    `Time: ${new Date(report.timestamp).toISOString()}`,
  );

  return lines.join("\n");
}
