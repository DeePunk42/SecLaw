/**
 * Per-session state management.
 * Tracks danger flags, audit results, and session metadata.
 */

import type { DangerReport, IntentContext, PendingOverride } from "./config.js";

interface SessionState {
  dangerFlag: DangerReport | null;
  intentContext: IntentContext;
  auditCache: Map<string, { decision: string; timestamp: number }>;
  pendingOverrides: Map<string, PendingOverride>;  // key = pin
  activeOverridePin: string | null;                 // confirmed pin, awaiting consumption
  lastCallOverridden: boolean;                      // set by consumeActiveOverride, cleared by afterToolCall
  lastToolCallId: string | null;                    // set by beforeToolCall, used as fallback in afterToolCall
}

const DEFAULT_INTENT_CONTEXT: IntentContext = {
  userGoal: "",
  stepIndex: 0,
  turnNumber: 0,
  recentToolCalls: [],
};

const RECENT_TOOL_CALLS_LIMIT = 10;

class SessionStateManager {
  private sessions = new Map<string, SessionState>();

  /**
   * Get or create session state for a given session key.
   */
  getSession(sessionKey: string): SessionState {
    let state = this.sessions.get(sessionKey);
    if (!state) {
      state = {
        dangerFlag: null,
        intentContext: { ...DEFAULT_INTENT_CONTEXT, recentToolCalls: [] },
        auditCache: new Map(),
        pendingOverrides: new Map(),
        activeOverridePin: null,
        lastCallOverridden: false,
        lastToolCallId: null,
      };
      this.sessions.set(sessionKey, state);
    }
    return state;
  }

  /**
   * Set the danger flag for a session.
   */
  setDangerFlag(sessionKey: string, report: DangerReport): void {
    this.getSession(sessionKey).dangerFlag = report;
  }

  /**
   * Consume (read and clear) the danger flag for a session.
   * Returns the report if one was set, null otherwise.
   */
  consumeDangerFlag(sessionKey: string): DangerReport | null {
    const state = this.getSession(sessionKey);
    const flag = state.dangerFlag;
    state.dangerFlag = null;
    return flag;
  }

  /**
   * Check if a danger flag is set without consuming it.
   */
  hasDangerFlag(sessionKey: string): boolean {
    return this.getSession(sessionKey).dangerFlag !== null;
  }

  /**
   * Get the intent context for a session.
   */
  getIntentContext(sessionKey: string): IntentContext {
    return this.getSession(sessionKey).intentContext;
  }

  /**
   * Update intent context fields.
   */
  updateIntentContext(
    sessionKey: string,
    updates: Partial<IntentContext>,
  ): void {
    const state = this.getSession(sessionKey);
    Object.assign(state.intentContext, updates);
  }

  /**
   * Record a tool call in the session's recent history (ring buffer).
   */
  recordToolCall(
    sessionKey: string,
    entry: {
      toolName: string;
      params: Record<string, unknown>;
      outcome: "success" | "error" | "blocked";
    },
  ): void {
    const state = this.getSession(sessionKey);
    const calls = state.intentContext.recentToolCalls;
    calls.push(entry);
    if (calls.length > RECENT_TOOL_CALLS_LIMIT) {
      calls.shift();
    }
    state.intentContext.stepIndex++;
  }

  /**
   * Increment the turn number (called on new user messages).
   */
  incrementTurn(sessionKey: string): void {
    this.getSession(sessionKey).intentContext.turnNumber++;
  }

  /**
   * Set an audit cache entry.
   */
  setAuditCache(
    sessionKey: string,
    fingerprint: string,
    decision: string,
  ): void {
    this.getSession(sessionKey).auditCache.set(fingerprint, {
      decision,
      timestamp: Date.now(),
    });
  }

  /**
   * Get a cached audit result if it exists and hasn't expired.
   */
  getAuditCache(
    sessionKey: string,
    fingerprint: string,
    ttlMs: number = 5 * 60 * 1000,
  ): string | null {
    const state = this.getSession(sessionKey);
    const entry = state.auditCache.get(fingerprint);
    if (!entry) return null;
    if (Date.now() - entry.timestamp > ttlMs) {
      state.auditCache.delete(fingerprint);
      return null;
    }
    return entry.decision;
  }

  // ─── Override management ───

  /**
   * Register a pending override for a session.
   */
  addPendingOverride(sessionKey: string, override: PendingOverride): void {
    this.getSession(sessionKey).pendingOverrides.set(override.pin, override);
  }

  /**
   * Look up a pending override by PIN.
   */
  getPendingOverride(sessionKey: string, pin: string): PendingOverride | null {
    return this.getSession(sessionKey).pendingOverrides.get(pin) ?? null;
  }

  /**
   * Set (or clear) the active override PIN directly.
   */
  setActiveOverride(sessionKey: string, pin: string | null): void {
    this.getSession(sessionKey).activeOverridePin = pin;
  }

  /**
   * Activate a pending override: verify it exists, then mark as active.
   * Returns true if activation succeeded.
   */
  activateOverride(sessionKey: string, pin: string): boolean {
    const state = this.getSession(sessionKey);
    if (!state.pendingOverrides.has(pin)) return false;
    state.activeOverridePin = pin;
    return true;
  }

  /**
   * Check the active override and grant access if the toolName matches.
   * The override stays active for the entire turn — the LLM may make multiple
   * tool calls (e.g. first attempt errors, retry with different params) and
   * each one should be covered without requiring the user to send the PIN again.
   * Cleanup happens via clearTurnOverride() at the start of the next turn.
   *
   * Fingerprint is retained in PendingOverride for audit trail but NOT enforced,
   * because the LLM typically modifies params based on security feedback.
   */
  consumeActiveOverride(sessionKey: string, toolName: string): boolean {
    const state = this.getSession(sessionKey);
    const pin = state.activeOverridePin;
    if (!pin) return false;
    const pending = state.pendingOverrides.get(pin);
    if (!pending || pending.toolName !== toolName) return false;
    // Keep override active — don't clear activeOverridePin or pendingOverrides
    state.lastCallOverridden = true;
    return true;
  }

  /**
   * Return the current active override PIN (without consuming it).
   */
  getActiveOverridePin(sessionKey: string): string | null {
    return this.getSession(sessionKey).activeOverridePin;
  }

  /**
   * Clear the active override and its pending entry.
   * Called at the start of each new turn (onUserMessage) to ensure
   * overrides don't leak across turns.
   */
  clearTurnOverride(sessionKey: string): void {
    const state = this.getSession(sessionKey);
    if (state.activeOverridePin) {
      state.pendingOverrides.delete(state.activeOverridePin);
      state.activeOverridePin = null;
    }
  }

  /**
   * Check whether the last beforeToolCall was allowed via override.
   * Returns true once and then clears the flag.
   */
  consumeLastCallOverridden(sessionKey: string): boolean {
    const state = this.getSession(sessionKey);
    const was = state.lastCallOverridden;
    state.lastCallOverridden = false;
    return was;
  }

  // ─── Tool call ID tracking (for afterToolCall fallback) ───

  /**
   * Store the toolCallId generated during beforeToolCall so that
   * afterToolCall can retrieve it even if the runtime doesn't provide one.
   */
  setLastToolCallId(sessionKey: string, toolCallId: string): void {
    this.getSession(sessionKey).lastToolCallId = toolCallId;
  }

  /**
   * Get the toolCallId from the most recent beforeToolCall.
   */
  getLastToolCallId(sessionKey: string): string | null {
    return this.getSession(sessionKey).lastToolCallId;
  }

  /**
   * Collect all non-empty sender labels from active sessions.
   */
  getAllSenderLabels(): string[] {
    const labels: string[] = [];
    for (const state of this.sessions.values()) {
      if (state.intentContext.senderLabel) {
        labels.push(state.intentContext.senderLabel);
      }
    }
    return labels;
  }

  /**
   * Reset a session (clear all state).
   */
  resetSession(sessionKey: string): void {
    this.sessions.delete(sessionKey);
  }

  /**
   * Clear all sessions.
   */
  clear(): void {
    this.sessions.clear();
  }
}

/** Singleton session state manager. */
export const sessionState = new SessionStateManager();
