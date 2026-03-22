/**
 * Intent context accumulator.
 * Tracks user messages, message source, and tool call events to build
 * an understanding of the agent's current task and intent.
 */

import type { IntentContext, ToolCallOutcome } from "./config.js";
import { sessionState } from "./session-state.js";

/**
 * Parse a raw user message to strip OpenClaw-injected metadata blocks
 * (Conversation info / Sender) and extract the sender label.
 */
export function parseUserMessage(raw: string): { userMessage: string; senderLabel?: string } {
  let text = raw;
  let senderLabel: string | undefined;

  // Strip "Conversation info (untrusted metadata):\n```json\n...\n```" block
  text = text.replace(/Conversation info \(untrusted metadata\):\n```json\n[\s\S]*?\n```\n?/g, "");

  // Strip "Sender (untrusted metadata):\n```json\n...\n```" block and extract label
  text = text.replace(/Sender \(untrusted metadata\):\n```json\n([\s\S]*?)\n```\n?/g, (_match, json: string) => {
    try {
      const parsed = JSON.parse(json);
      if (parsed.label) {
        senderLabel = parsed.label;
      }
    } catch {
      // Ignore malformed JSON
    }
    return "";
  });

  const userMessage = text.trim();
  return { userMessage: userMessage || raw.trim(), senderLabel };
}

/**
 * Update context when a new user message is received.
 * When trustedSenderLabels is provided, also checks for /pin<pin> commands.
 */
export function onUserMessage(
  sessionKey: string,
  message: string,
  trustedSenderLabels?: string[],
): void {
  sessionState.incrementTurn(sessionKey);
  const { userMessage, senderLabel } = parseUserMessage(message);
  const updates: Partial<IntentContext> = { userGoal: userMessage };
  if (senderLabel) updates.senderLabel = senderLabel;
  sessionState.updateIntentContext(sessionKey, updates);

  // Override detection (enabled when trustedSenderLabels is non-empty)
  if (trustedSenderLabels && trustedSenderLabels.length > 0) {
    // New turn: clear any override from previous turn
    sessionState.clearTurnOverride(sessionKey);

    const match = userMessage.match(/\/pin(\d{6})/);
    if (match) {
      const pin = match[1].toLowerCase();
      const isTrusted = senderLabel == null || trustedSenderLabels.includes(senderLabel);
      if (isTrusted && sessionState.getPendingOverride(sessionKey, pin)) {
        sessionState.activateOverride(sessionKey, pin);
      }
    }
  }
}

/**
 * Update message source information from hook context.
 */
export function updateSource(
  sessionKey: string,
  source: {
    channelId?: string;
    trigger?: string;
    agentId?: string;
    messageProvider?: string;
  },
): void {
  sessionState.updateIntentContext(sessionKey, source);
}

/**
 * Record a tool call outcome in the context.
 */
export function onToolCallComplete(
  sessionKey: string,
  toolName: string,
  params: Record<string, unknown>,
  outcome: ToolCallOutcome,
): void {
  sessionState.recordToolCall(sessionKey, { toolName, params, outcome });
}

/**
 * Get the current intent context for a session.
 */
export function getIntentContext(sessionKey: string): IntentContext {
  return sessionState.getIntentContext(sessionKey);
}
