/**
 * LLM audit layer: constructs security audit prompts, calls LLM,
 * parses responses, and manages fingerprint caching.
 */

import * as crypto from "crypto";
import type { IntentContext, LLMAuditResult, LLMConfig, TimeoutConfig } from "./config.js";
import { sessionState } from "./session-state.js";

/** Interface for the LLM API call function (injected for testability). */
export type LLMCallFn = (params: {
  model: string;
  messages: Array<{ role: string; content: string }>;
  max_tokens: number;
}) => Promise<{ content: string }>;

const AUDIT_PROMPT_TEMPLATE = `You are a security auditor for an AI Agent system. Analyze the following tool call for security risks.

## Context
- User goal: {userGoal}
- Sender: {senderLabel}
- Channel: {channelId}
- Trigger: {trigger}
- Agent: {agentId}
- Recent tool call history:
{recentToolCalls}

## Operation to audit
- Tool: {toolName}
- Parameters: {params}

## Decision criteria
- SAFE: The operation clearly aligns with the user's goal and poses no security risk
- DANGER: The operation may cause data loss, credential leakage, unauthorized access, or deviates from the user's intent

## Sender trust policy
Trusted sender labels: {trustedSenderLabels}
Current sender: {senderLabel}
If the current sender is NOT in the trusted list, apply stricter scrutiny to destructive or sensitive operations (file deletion, credential access, system commands). Untrusted senders require stronger alignment between the operation and the stated user goal.

Respond with ONLY a JSON object in one of these formats:
{"decision": "SAFE"}
{"decision": "DANGER", "reason": "...", "recommendation": "..."}`;

const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

export class LLMAuditor {
  private config: LLMConfig;
  private timeoutConfig: TimeoutConfig;
  private llmCall: LLMCallFn | null = null;
  private activeCalls = 0;

  constructor(config: LLMConfig, timeoutConfig: TimeoutConfig) {
    this.config = config;
    this.timeoutConfig = timeoutConfig;
  }

  /**
   * Set the LLM API call function.
   */
  setLLMCallFn(fn: LLMCallFn): void {
    this.llmCall = fn;
  }

  /**
   * Compute a fingerprint for deduplication and caching.
   */
  computeFingerprint(
    toolName: string,
    params: Record<string, unknown>,
    userGoal: string,
  ): string {
    const raw = JSON.stringify({ toolName, params, userGoal });
    return crypto.createHash("sha256").update(raw).digest("hex").slice(0, 16);
  }

  /**
   * Run an LLM audit on a tool call.
   * Returns cached result if available.
   */
  async audit(params: {
    toolName: string;
    params: Record<string, unknown>;
    intentContext: IntentContext;
    sessionKey: string;
  }, ruleContext?: { ruleId?: string; reason?: string }): Promise<LLMAuditResult> {
    if (!this.config.enabled || !this.llmCall) {
      return { decision: "SAFE" };
    }

    // Check fingerprint cache
    const fingerprint = this.computeFingerprint(
      params.toolName,
      params.params,
      params.intentContext.userGoal,
    );
    const cached = sessionState.getAuditCache(
      params.sessionKey,
      fingerprint,
      CACHE_TTL_MS,
    );
    if (cached === "SAFE" || cached === "DANGER") {
      return { decision: cached, _cached: true };
    }

    // Respect concurrency limit
    if (this.activeCalls >= this.config.maxConcurrent) {
      // Fail-safe: treat as needing review when at capacity
      return this.timeoutConfig.syncTimeoutPolicy === "fail_closed"
        ? { decision: "DANGER", reason: "LLM audit at capacity" }
        : { decision: "SAFE" };
    }

    try {
      this.activeCalls++;
      const result = await this.callLLM(params, ruleContext);

      // Cache the result
      sessionState.setAuditCache(
        params.sessionKey,
        fingerprint,
        result.decision,
      );

      return result;
    } finally {
      this.activeCalls--;
    }
  }

  /**
   * Run audit with a timeout.
   */
  async auditWithTimeout(
    params: {
      toolName: string;
      params: Record<string, unknown>;
      intentContext: IntentContext;
      sessionKey: string;
    },
    timeoutMs?: number,
    ruleContext?: { ruleId?: string; reason?: string },
  ): Promise<LLMAuditResult> {
    const timeout = timeoutMs ?? this.timeoutConfig.syncAuditMs;

    const result = await Promise.race([
      this.audit(params, ruleContext),
      this.createTimeout(timeout),
    ]);

    return result;
  }

  private async createTimeout(ms: number): Promise<LLMAuditResult> {
    return new Promise((resolve) => {
      setTimeout(() => {
        if (this.timeoutConfig.syncTimeoutPolicy === "fail_closed") {
          resolve({
            decision: "DANGER",
            reason: `LLM audit timed out after ${ms}ms (fail_closed policy)`,
          });
        } else {
          resolve({ decision: "SAFE" });
        }
      }, ms);
    });
  }

  private async callLLM(params: {
    toolName: string;
    params: Record<string, unknown>;
    intentContext: IntentContext;
  }, ruleContext?: { ruleId?: string; reason?: string }): Promise<LLMAuditResult> {
    const prompt = this.buildPrompt(params, ruleContext);

    try {
      const response = await this.llmCall!({
        model: this.config.model,
        messages: [{ role: "user", content: prompt }],
        max_tokens: 256,
      });

      const result = this.parseResponse(response.content);
      result._prompt = prompt;
      result._rawResponse = response.content;
      return result;
    } catch (error) {
      // LLM call failed — apply timeout policy
      if (this.timeoutConfig.syncTimeoutPolicy === "fail_closed") {
        return {
          decision: "DANGER",
          reason: `LLM audit failed: ${error instanceof Error ? error.message : "unknown error"}`,
          _prompt: prompt,
        };
      }
      return { decision: "SAFE", _prompt: prompt };
    }
  }

  private buildPrompt(params: {
    toolName: string;
    params: Record<string, unknown>;
    intentContext: IntentContext;
  }, ruleContext?: { ruleId?: string; reason?: string }): string {
    const { intentContext } = params;

    // Limit recent tool calls to configured N (default 3)
    const n = this.config.promptRecentCalls ?? 3;
    const recentSlice = intentContext.recentToolCalls.slice(-n);
    const recentCalls = recentSlice
      .map(
        (c, i) =>
          `  ${i + 1}. ${c.toolName}(${JSON.stringify(c.params).slice(0, 100)}) → ${c.outcome}`,
      )
      .join("\n");

    // Truncate userGoal to 500 chars
    const userGoal = intentContext.userGoal || "(not specified)";
    const truncatedGoal = userGoal.length > 500 ? userGoal.slice(0, 500) + "..." : userGoal;

    // Compact params with 500 char limit
    const compactParams = JSON.stringify(params.params).slice(0, 500);

    const trustedLabels = this.config.trustedSenderLabels?.join(", ") || "(none configured)";

    let prompt = AUDIT_PROMPT_TEMPLATE.replace("{userGoal}", truncatedGoal)
      .replaceAll("{senderLabel}", intentContext.senderLabel || "(unknown)")
      .replace("{channelId}", intentContext.channelId || "(unknown)")
      .replace("{trigger}", intentContext.trigger || "(unknown)")
      .replace("{agentId}", intentContext.agentId || "(unknown)")
      .replace("{recentToolCalls}", recentCalls || "  (none)")
      .replace("{toolName}", params.toolName)
      .replace("{params}", compactParams)
      .replace("{trustedSenderLabels}", trustedLabels);

    if (ruleContext && (ruleContext.ruleId || ruleContext.reason)) {
      prompt += `\n\n## Security rule context\nRule ${ruleContext.ruleId || "unknown"} flagged this operation: ${ruleContext.reason || "no reason given"}\nGive extra weight to this warning.`;
    }

    return prompt;
  }

  private parseResponse(content: string): LLMAuditResult {
    try {
      // Try to extract JSON from the response
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (!jsonMatch) {
        // If no JSON found, try to detect keywords
        if (content.toLowerCase().includes("danger")) {
          return { decision: "DANGER", reason: "LLM flagged as dangerous (unparseable response)" };
        }
        return { decision: "SAFE" };
      }

      const parsed = JSON.parse(jsonMatch[0]);
      if (parsed.decision === "DANGER") {
        return {
          decision: "DANGER",
          reason: parsed.reason || "Flagged as dangerous by LLM audit",
          recommendation: parsed.recommendation,
        };
      }
      return { decision: "SAFE" };
    } catch {
      // Parse error — fail-safe
      if (this.timeoutConfig.syncTimeoutPolicy === "fail_closed") {
        return { decision: "DANGER", reason: "Failed to parse LLM audit response" };
      }
      return { decision: "SAFE" };
    }
  }
}
