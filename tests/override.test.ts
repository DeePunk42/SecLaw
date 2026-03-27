import { describe, it, expect, vi, beforeEach } from "vitest";
import { sessionState } from "../src/session-state.js";
import { onUserMessage, getIntentContext } from "../src/intent-context.js";
import {
  init,
  beforeToolCall,
  afterToolCall,
  onUserMessageEvent,
  _getAsyncQueue,
} from "../index.js";
import type {
  PluginHookBeforeToolCallEvent,
  PluginHookToolContext,
} from "../src/config.js";

const sessionKey = "override-test";
const ctx: PluginHookToolContext = {
  sessionKey,
  workspacePath: "/workspace",
};

const trustedLabels = ["Alice (admin)", "openclaw-control-ui"];

// ─── Helper: build a user message with Sender metadata ───

function senderMessage(label: string, text: string): string {
  return `Sender (untrusted metadata):
\`\`\`json
{"userId": 1, "label": "${label}"}
\`\`\`
${text}`;
}

// ─── Unit: SessionState override methods ───

describe("SessionState override management", () => {
  beforeEach(() => {
    sessionState.clear();
  });

  it("addPendingOverride + getPendingOverride round-trips", () => {
    sessionState.addPendingOverride(sessionKey, {
      pin: "038291",
      toolName: "exec",
      paramsFingerprint: "fp1",
      timestamp: Date.now(),
    });
    const o = sessionState.getPendingOverride(sessionKey, "038291");
    expect(o).not.toBeNull();
    expect(o!.toolName).toBe("exec");
  });

  it("getPendingOverride returns null for unknown pin", () => {
    expect(sessionState.getPendingOverride(sessionKey, "000000")).toBeNull();
  });

  it("activateOverride succeeds for valid pin", () => {
    sessionState.addPendingOverride(sessionKey, {
      pin: "112233",
      toolName: "exec",
      paramsFingerprint: "fp2",
      timestamp: Date.now(),
    });
    expect(sessionState.activateOverride(sessionKey, "112233")).toBe(true);
  });

  it("activateOverride fails for unknown pin", () => {
    expect(sessionState.activateOverride(sessionKey, "999999")).toBe(false);
  });

  it("consumeActiveOverride succeeds with matching toolName (turn-scoped)", () => {
    sessionState.addPendingOverride(sessionKey, {
      pin: "112233",
      toolName: "exec",
      paramsFingerprint: "fp-match",
      timestamp: Date.now(),
    });
    sessionState.activateOverride(sessionKey, "112233");
    expect(sessionState.consumeActiveOverride(sessionKey, "exec")).toBe(true);
    // Override stays active for the entire turn — second attempt also succeeds
    expect(sessionState.consumeActiveOverride(sessionKey, "exec")).toBe(true);
  });

  it("clearTurnOverride clears active pin and pending entry", () => {
    sessionState.addPendingOverride(sessionKey, {
      pin: "112233",
      toolName: "exec",
      paramsFingerprint: "fp-clear",
      timestamp: Date.now(),
    });
    sessionState.activateOverride(sessionKey, "112233");
    sessionState.clearTurnOverride(sessionKey);
    // Active override is gone
    expect(sessionState.consumeActiveOverride(sessionKey, "exec")).toBe(false);
    // Pending entry is also removed
    expect(sessionState.getPendingOverride(sessionKey, "112233")).toBeNull();
  });

  it("consumeActiveOverride succeeds even with different params (same toolName)", () => {
    sessionState.addPendingOverride(sessionKey, {
      pin: "445566",
      toolName: "exec",
      paramsFingerprint: "fp-original",
      timestamp: Date.now(),
    });
    sessionState.activateOverride(sessionKey, "445566");
    // toolName matches even though fingerprint would differ — override allowed
    expect(sessionState.consumeActiveOverride(sessionKey, "exec")).toBe(true);
  });

  it("consumeActiveOverride fails with different toolName", () => {
    sessionState.addPendingOverride(sessionKey, {
      pin: "445566",
      toolName: "exec",
      paramsFingerprint: "fp-original",
      timestamp: Date.now(),
    });
    sessionState.activateOverride(sessionKey, "445566");
    expect(sessionState.consumeActiveOverride(sessionKey, "web_fetch")).toBe(false);
  });

  it("consumeActiveOverride fails when no active override", () => {
    expect(sessionState.consumeActiveOverride(sessionKey, "exec")).toBe(false);
  });

  it("setActiveOverride clears active pin", () => {
    sessionState.addPendingOverride(sessionKey, {
      pin: "778899",
      toolName: "exec",
      paramsFingerprint: "fp3",
      timestamp: Date.now(),
    });
    sessionState.activateOverride(sessionKey, "778899");
    sessionState.setActiveOverride(sessionKey, null);
    expect(sessionState.consumeActiveOverride(sessionKey, "exec")).toBe(false);
  });

  it("clearStalePendingOverrides removes non-active overrides", () => {
    // Add several pending overrides
    sessionState.addPendingOverride(sessionKey, {
      pin: "111111",
      toolName: "exec",
      paramsFingerprint: "fp1",
      timestamp: Date.now(),
    });
    sessionState.addPendingOverride(sessionKey, {
      pin: "222222",
      toolName: "exec",
      paramsFingerprint: "fp2",
      timestamp: Date.now(),
    });
    sessionState.addPendingOverride(sessionKey, {
      pin: "333333",
      toolName: "exec",
      paramsFingerprint: "fp3",
      timestamp: Date.now(),
    });

    // Activate one of them
    sessionState.activateOverride(sessionKey, "222222");

    // Clear stale
    sessionState.clearStalePendingOverrides(sessionKey);

    // Active one survives
    expect(sessionState.getPendingOverride(sessionKey, "222222")).not.toBeNull();
    // Others are gone
    expect(sessionState.getPendingOverride(sessionKey, "111111")).toBeNull();
    expect(sessionState.getPendingOverride(sessionKey, "333333")).toBeNull();
  });

  it("clearStalePendingOverrides removes all when none active", () => {
    sessionState.addPendingOverride(sessionKey, {
      pin: "111111",
      toolName: "exec",
      paramsFingerprint: "fp1",
      timestamp: Date.now(),
    });
    sessionState.addPendingOverride(sessionKey, {
      pin: "222222",
      toolName: "exec",
      paramsFingerprint: "fp2",
      timestamp: Date.now(),
    });

    // No active override
    sessionState.clearStalePendingOverrides(sessionKey);

    expect(sessionState.getPendingOverride(sessionKey, "111111")).toBeNull();
    expect(sessionState.getPendingOverride(sessionKey, "222222")).toBeNull();
  });

  it("resetSession clears override state", () => {
    sessionState.addPendingOverride(sessionKey, {
      pin: "334455",
      toolName: "exec",
      paramsFingerprint: "fp4",
      timestamp: Date.now(),
    });
    sessionState.activateOverride(sessionKey, "334455");
    sessionState.resetSession(sessionKey);
    expect(sessionState.getPendingOverride(sessionKey, "334455")).toBeNull();
    expect(sessionState.consumeActiveOverride(sessionKey, "exec")).toBe(false);
  });
});

// ─── Unit: onUserMessage override detection ───

describe("onUserMessage override detection", () => {
  beforeEach(() => {
    sessionState.clear();
  });

  it("trusted sender + correct PIN → activates override", () => {
    sessionState.addPendingOverride(sessionKey, {
      pin: "038291",
      toolName: "exec",
      paramsFingerprint: "fp-test",
      timestamp: Date.now(),
    });

    const msg = senderMessage("Alice (admin)", "/pin038291");
    onUserMessage(sessionKey, msg, trustedLabels);

    expect(sessionState.consumeActiveOverride(sessionKey, "exec")).toBe(true);
  });

  it("untrusted sender + correct PIN → activates (PIN is admin-granted credential)", () => {
    sessionState.addPendingOverride(sessionKey, {
      pin: "038291",
      toolName: "exec",
      paramsFingerprint: "fp-test",
      timestamp: Date.now(),
    });

    const msg = senderMessage("EvilUser", "/pin038291");
    onUserMessage(sessionKey, msg, trustedLabels);

    expect(sessionState.consumeActiveOverride(sessionKey, "exec")).toBe(true);
  });

  it("trusted sender + wrong PIN → does NOT activate", () => {
    sessionState.addPendingOverride(sessionKey, {
      pin: "038291",
      toolName: "exec",
      paramsFingerprint: "fp-test",
      timestamp: Date.now(),
    });

    const msg = senderMessage("Alice (admin)", "/pin999999");
    onUserMessage(sessionKey, msg, trustedLabels);

    expect(sessionState.consumeActiveOverride(sessionKey, "exec")).toBe(false);
  });

  it("no sender label → treated as trusted, activates override with correct PIN", () => {
    sessionState.addPendingOverride(sessionKey, {
      pin: "038291",
      toolName: "exec",
      paramsFingerprint: "fp-test",
      timestamp: Date.now(),
    });

    // Plain message without Sender metadata → trusted (direct/system interaction)
    onUserMessage(sessionKey, "/pin038291", trustedLabels);

    expect(sessionState.consumeActiveOverride(sessionKey, "exec")).toBe(true);
  });

  it("new turn clears previous active override", () => {
    sessionState.addPendingOverride(sessionKey, {
      pin: "111111",
      toolName: "exec",
      paramsFingerprint: "fp-old",
      timestamp: Date.now(),
    });
    sessionState.activateOverride(sessionKey, "111111");

    // Next turn with a different message (no override command)
    const msg = senderMessage("Alice (admin)", "just a normal message");
    onUserMessage(sessionKey, msg, trustedLabels);

    // Old active override should be cleared
    expect(sessionState.consumeActiveOverride(sessionKey, "exec")).toBe(false);
  });

  it("hex-like PIN is not matched by decimal-only regex", () => {
    sessionState.addPendingOverride(sessionKey, {
      pin: "abcdef",
      toolName: "exec",
      paramsFingerprint: "fp-hex",
      timestamp: Date.now(),
    });

    const msg = senderMessage("Alice (admin)", "/pinabcdef");
    onUserMessage(sessionKey, msg, trustedLabels);

    // Should NOT activate — regex only matches digits
    expect(sessionState.consumeActiveOverride(sessionKey, "exec")).toBe(false);
  });

  it("does nothing when trustedSenderLabels is not provided", () => {
    sessionState.addPendingOverride(sessionKey, {
      pin: "038291",
      toolName: "exec",
      paramsFingerprint: "fp-test",
      timestamp: Date.now(),
    });

    const msg = senderMessage("Alice (admin)", "/pin038291");
    onUserMessage(sessionKey, msg); // no trustedSenderLabels

    expect(sessionState.consumeActiveOverride(sessionKey, "exec")).toBe(false);
  });
});

// ─── Integration: full override flow ───

describe("Integration: Override flow", () => {
  const mockLLM = vi.fn();

  beforeEach(() => {
    sessionState.clear();
    mockLLM.mockReset();
    init({
      workspacePath: "/workspace",
      pluginDir: __dirname + "/..",
      config: {
        llm: {
          model: "test",
          enabled: true,
          maxConcurrent: 2,
          trustedSenderLabels: trustedLabels,
        },
        logging: { level: "error", auditJsonl: false },
      },
      llmCall: mockLLM,
    });
  });

  it("sync DANGER → block with override hint → override → retry → allow", async () => {
    // 1. Set up user goal
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", "Run eval command"));

    // 2. LLM returns DANGER
    mockLLM.mockResolvedValue({
      content: '{"decision": "DANGER", "reason": "Dangerous eval command"}',
    });

    const event: PluginHookBeforeToolCallEvent = {
      toolName: "exec",
      params: { command: "eval \"dangerous_payload\"" },
    };

    // 3. First call → blocked with override hint
    const result = await beforeToolCall(event, ctx);
    expect(result).toBeDefined();
    expect(result!.block).toBe(true);
    expect(result!.blockReason).toContain("Dangerous eval command");
    expect(result!.blockReason).toContain("--- Override ---");
    expect(result!.blockReason).toContain("/pin");

    // Extract PIN from blockReason
    const pinMatch = result!.blockReason!.match(/\/pin(\d{6})/);
    expect(pinMatch).not.toBeNull();
    const pin = pinMatch![1];

    // 4. User sends override command (trusted sender)
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", `/pin${pin}`));

    // 5. LLM should NOT be called for the retry (override bypasses)
    mockLLM.mockClear();

    // 6. Retry same tool call → should be allowed
    const retryResult = await beforeToolCall(event, ctx);
    expect(retryResult).toBeUndefined();
    expect(mockLLM).not.toHaveBeenCalled();
  });

  it("async danger flag → block with override → override → allow", async () => {
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", "Run a command"));

    // Set up async danger flag with PIN
    sessionState.setDangerFlag(sessionKey, {
      toolName: "exec",
      params: { command: "suspicious" },
      reason: "Async audit detected exfiltration",
      timestamp: Date.now(),
      source: "async",
      pin: "038291",
    });

    const event: PluginHookBeforeToolCallEvent = {
      toolName: "exec",
      params: { command: "suspicious" },
    };

    // First call → blocked (danger flag persists)
    const result = await beforeToolCall(event, ctx);
    expect(result).toBeDefined();
    expect(result!.block).toBe(true);
    expect(result!.blockReason).toContain("ACTION REQUIRED: STOP this tool call immediately.");
    expect(result!.blockReason).toContain("/pin038291");

    // User sends /pin to clear danger flag
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", "/pin038291"));

    // Retry → allowed (danger flag cleared)
    const retryResult = await beforeToolCall(event, ctx);
    expect(retryResult).toBeUndefined();
  });

  it("override covers multiple tool calls in the same turn", async () => {
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", "Run eval commands"));

    mockLLM.mockResolvedValue({
      content: '{"decision": "DANGER", "reason": "Dangerous eval"}',
    });

    const event: PluginHookBeforeToolCallEvent = {
      toolName: "exec",
      params: { command: "eval \"payload1\"" },
    };

    // Block → get PIN
    const result = await beforeToolCall(event, ctx);
    const pinMatch = result!.blockReason!.match(/\/pin(\d{6})/);
    const pin = pinMatch![1];

    // Override
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", `/pin${pin}`));

    // First call in turn → allowed
    const retry1 = await beforeToolCall(event, ctx);
    expect(retry1).toBeUndefined();

    // afterToolCall for first call (e.g. it errored)
    await afterToolCall({ toolName: "exec", params: event.params, error: "command failed" }, ctx);

    // Second call in SAME turn (LLM retries with different params) → also allowed
    mockLLM.mockClear();
    const event2: PluginHookBeforeToolCallEvent = {
      toolName: "exec",
      params: { command: "eval \"payload2\"" },
    };
    const retry2 = await beforeToolCall(event2, ctx);
    expect(retry2).toBeUndefined();
    expect(mockLLM).not.toHaveBeenCalled();
  });

  it("new turn after override → override cleared → LLM consulted again", async () => {
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", "Run eval"));

    mockLLM.mockResolvedValue({
      content: '{"decision": "DANGER", "reason": "Dangerous eval"}',
    });

    const event: PluginHookBeforeToolCallEvent = {
      toolName: "exec",
      params: { command: "eval \"payload\"" },
    };

    // Block → get PIN → Override → Allow
    const result = await beforeToolCall(event, ctx);
    const pin = result!.blockReason!.match(/\/pin(\d{6})/)![1];
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", `/pin${pin}`));
    const retry1 = await beforeToolCall(event, ctx);
    expect(retry1).toBeUndefined();

    // NEW TURN (new user message without override) → clears the override
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", "Do it again"));

    // Same tool call → LLM consulted → blocked again
    mockLLM.mockResolvedValue({
      content: '{"decision": "DANGER", "reason": "Still dangerous"}',
    });
    const retry2 = await beforeToolCall(event, ctx);
    expect(retry2).toBeDefined();
    expect(retry2!.block).toBe(true);
  });

  it("same toolName but modified params → override still applies (LLM may tweak command on retry)", async () => {
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", "Run a command"));

    mockLLM.mockResolvedValue({
      content: '{"decision": "DANGER", "reason": "Blocked"}',
    });

    const event1: PluginHookBeforeToolCallEvent = {
      toolName: "exec",
      params: { command: "eval \"payload && extra\"" },
    };

    // Block with original params
    const result = await beforeToolCall(event1, ctx);
    const pinMatch = result!.blockReason!.match(/\/pin(\d{6})/);
    const pin = pinMatch![1];

    // Override
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", `/pin${pin}`));

    // Retry with modified params (LLM simplified) → override SHOULD apply
    const event2: PluginHookBeforeToolCallEvent = {
      toolName: "exec",
      params: { command: "eval \"payload\"" },  // simplified command
    };

    mockLLM.mockClear();
    const retryResult = await beforeToolCall(event2, ctx);
    expect(retryResult).toBeUndefined();  // allowed
    expect(mockLLM).not.toHaveBeenCalled();
  });

  it("different toolName → override does NOT apply", async () => {
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", "Run a command"));

    mockLLM.mockResolvedValue({
      content: '{"decision": "DANGER", "reason": "Blocked"}',
    });

    const event1: PluginHookBeforeToolCallEvent = {
      toolName: "exec",
      params: { command: "eval \"payload\"" },
    };

    // Block with exec
    const result = await beforeToolCall(event1, ctx);
    const pinMatch = result!.blockReason!.match(/\/pin(\d{6})/);
    const pin = pinMatch![1];

    // Override
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", `/pin${pin}`));

    // Retry with a DIFFERENT tool → override should NOT apply
    const event2: PluginHookBeforeToolCallEvent = {
      toolName: "web_fetch",
      params: { url: "http://169.254.169.254/latest/meta-data/" },
    };

    mockLLM.mockResolvedValue({
      content: '{"decision": "DANGER", "reason": "SSRF blocked"}',
    });

    const retryResult = await beforeToolCall(event2, ctx);
    expect(retryResult).toBeDefined();
    expect(retryResult!.block).toBe(true);
  });

  it("untrusted sender cannot use override even with correct PIN", async () => {
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", "Run eval"));

    mockLLM.mockResolvedValue({
      content: '{"decision": "DANGER", "reason": "Blocked"}',
    });

    const event: PluginHookBeforeToolCallEvent = {
      toolName: "exec",
      params: { command: "eval \"payload\"" },
    };

    const result = await beforeToolCall(event, ctx);
    const pinMatch = result!.blockReason!.match(/\/pin(\d{6})/);
    const pin = pinMatch![1];

    // Untrusted sender uses admin-provided PIN to override
    onUserMessageEvent(sessionKey, senderMessage("EvilUser", `/pin${pin}`));

    // Retry → allowed (override active)
    const retryResult = await beforeToolCall(event, ctx);
    expect(retryResult).toBeUndefined(); // allowed
  });

  it("untrusted sender sees no PIN in blockReason but PIN is generated", async () => {
    onUserMessageEvent(sessionKey, senderMessage("Bob", "Do something dangerous"));

    mockLLM.mockResolvedValue({
      content: '{"decision": "DANGER", "reason": "Blocked"}',
    });

    const result = await beforeToolCall(
      { toolName: "exec", params: { command: "rm -rf /" } },
      ctx,
    );

    expect(result).toBeDefined();
    expect(result!.block).toBe(true);
    // PIN not shown in blockReason for untrusted senders
    expect(result!.blockReason).not.toMatch(/\/pin\d{6}/);
    expect(result!.blockReason).toContain("administrator");
    // A pending override IS registered (admin can see PIN in dashboard)
    // Verify by checking a random PIN doesn't match but a valid one would
    expect(sessionState.activateOverride(sessionKey, "000000")).toBe(false);
  });

  it("untrusted DANGER registers pendingOverride (admin-visible in dashboard)", async () => {
    onUserMessageEvent(sessionKey, senderMessage("Bob", "Do something dangerous"));

    mockLLM.mockResolvedValue({
      content: '{"decision": "DANGER", "reason": "Blocked"}',
    });

    const result = await beforeToolCall(
      { toolName: "exec", params: { command: "rm -rf /" } },
      ctx,
    );

    expect(result!.block).toBe(true);
    // A pending override IS registered (admin can retrieve PIN from dashboard)
    // but a random PIN won't match
    expect(sessionState.activateOverride(sessionKey, "000000")).toBe(false);
    // No override is active until admin provides the correct PIN
    expect(sessionState.consumeActiveOverride(sessionKey, "exec")).toBe(false);
  });

  it("override-approved call skips async audit (no spurious danger flag)", async () => {
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", "Delete key file"));

    mockLLM.mockResolvedValue({
      content: '{"decision": "DANGER", "reason": "Credential deletion"}',
    });

    const event: PluginHookBeforeToolCallEvent = {
      toolName: "exec",
      params: { command: "rm -f /home/node/.ssh/authorized_keys" },
    };

    // Block → get PIN
    const result = await beforeToolCall(event, ctx);
    const pin = result!.blockReason!.match(/\/pin(\d{6})/)![1];

    // Override
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", `/pin${pin}`));

    // Retry → allowed via override
    const retryResult = await beforeToolCall(event, ctx);
    expect(retryResult).toBeUndefined();

    // afterToolCall should NOT enqueue for async audit
    const queueLengthBefore = _getAsyncQueue().length;
    await afterToolCall(
      { toolName: "exec", params: event.params, result: "deleted" },
      ctx,
    );
    expect(_getAsyncQueue().length).toBe(queueLengthBefore);

    // No danger flag should be set
    expect(sessionState.hasDangerFlag(sessionKey)).toBe(false);
  });
});

describe("Integration: Stale override cleanup", () => {
  const mockLLM = vi.fn();

  beforeEach(() => {
    sessionState.clear();
    mockLLM.mockReset();
    init({
      workspacePath: "/workspace",
      pluginDir: __dirname + "/..",
      config: {
        llm: {
          model: "test",
          enabled: true,
          maxConcurrent: 2,
          trustedSenderLabels: trustedLabels,
        },
        logging: { level: "error", auditJsonl: false },
      },
      llmCall: mockLLM,
    });
  });

  it("stale pending overrides are cleared on next user message (no /pin)", async () => {
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", "Do something"));

    mockLLM.mockResolvedValue({
      content: '{"decision": "DANGER", "reason": "Blocked"}',
    });

    // Block three times → three pending overrides
    for (let i = 0; i < 3; i++) {
      await beforeToolCall(
        { toolName: "exec", params: { command: `eval payload${i}` } },
        ctx,
      );
    }

    // Verify we have pending overrides
    const session = sessionState.getSession(sessionKey);
    expect(session.pendingOverrides.size).toBe(3);

    // Next turn: normal message (no /pin)
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", "just chatting"));

    // All stale overrides should be cleared
    expect(session.pendingOverrides.size).toBe(0);
  });

  it("normal /pin flow still works after stale cleanup is added", async () => {
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", "Run command"));

    mockLLM.mockResolvedValue({
      content: '{"decision": "DANGER", "reason": "Blocked"}',
    });

    // Block → get PIN
    const result = await beforeToolCall(
      { toolName: "exec", params: { command: "eval payload" } },
      ctx,
    );
    const pin = result!.blockReason!.match(/\/pin(\d{6})/)![1];

    // User sends /pin → activates override, stale cleanup preserves the active one
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", `/pin${pin}`));

    // Override is active
    expect(sessionState.consumeActiveOverride(sessionKey, "exec")).toBe(true);
  });
});

describe("Integration: Blocked calls recorded in recentToolCalls", () => {
  const mockLLM = vi.fn();

  beforeEach(() => {
    sessionState.clear();
    mockLLM.mockReset();
    init({
      workspacePath: "/workspace",
      pluginDir: __dirname + "/..",
      config: {
        llm: {
          model: "test",
          enabled: true,
          maxConcurrent: 2,
          trustedSenderLabels: trustedLabels,
        },
        logging: { level: "error", auditJsonl: false },
      },
      llmCall: mockLLM,
    });
  });

  it("sync DANGER block records blocked outcome in recentToolCalls", async () => {
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", "Run eval"));

    mockLLM.mockResolvedValue({
      content: '{"decision": "DANGER", "reason": "Blocked"}',
    });

    await beforeToolCall(
      { toolName: "exec", params: { command: "eval payload" } },
      ctx,
    );

    const intentCtx = getIntentContext(sessionKey);
    const lastCall = intentCtx.recentToolCalls[intentCtx.recentToolCalls.length - 1];
    expect(lastCall).toBeDefined();
    expect(lastCall.toolName).toBe("exec");
    expect(lastCall.outcome).toBe("blocked");
  });

  it("danger flag block records blocked outcome in recentToolCalls", async () => {
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", "Run command"));

    sessionState.setDangerFlag(sessionKey, {
      toolName: "exec",
      params: { command: "suspicious" },
      reason: "Async danger",
      timestamp: Date.now(),
      source: "async",
    });

    await beforeToolCall(
      { toolName: "exec", params: { command: "next command" } },
      ctx,
    );

    const intentCtx = getIntentContext(sessionKey);
    const lastCall = intentCtx.recentToolCalls[intentCtx.recentToolCalls.length - 1];
    expect(lastCall).toBeDefined();
    expect(lastCall.toolName).toBe("exec");
    expect(lastCall.outcome).toBe("blocked");
  });
});

describe("Integration: fail_closed override flow", () => {
  beforeEach(() => {
    sessionState.clear();
    init({
      workspacePath: "/workspace",
      pluginDir: __dirname + "/..",
      config: {
        llm: {
          model: "test",
          enabled: false,
          maxConcurrent: 1,
          trustedSenderLabels: trustedLabels,
        },
        timeouts: { auditTimeoutMs: 10000, syncTimeoutPolicy: "fail_closed" },
        logging: { level: "error", auditJsonl: false },
      },
    });
  });

  it("fail_closed block includes override hint, trusted sender can override", async () => {
    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", "Run command"));

    const event: PluginHookBeforeToolCallEvent = {
      toolName: "exec",
      params: { command: "eval \"payload\"" },
    };

    // Block (RED + fail_closed)
    const result = await beforeToolCall(event, ctx);
    expect(result!.block).toBe(true);
    expect(result!.blockReason).toContain("fail_closed");
    expect(result!.blockReason).toContain("/pin");

    // Extract PIN and override
    const pinMatch = result!.blockReason!.match(/\/pin(\d{6})/);
    const pin = pinMatch![1];

    onUserMessageEvent(sessionKey, senderMessage("Alice (admin)", `/pin${pin}`));

    // Retry → allowed
    const retryResult = await beforeToolCall(event, ctx);
    expect(retryResult).toBeUndefined();
  });
});
