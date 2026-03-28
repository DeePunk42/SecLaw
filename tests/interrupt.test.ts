import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  triggerInterrupt,
  consumeDangerFlag,
  hasDangerFlag,
  clearDangerFlag,
  resetSession,
  formatDangerAlert,
  setEmitAgentEvent,
} from "../src/interrupt.js";
import { sessionState } from "../src/session-state.js";
import type { DangerReport } from "../src/config.js";

describe("Interrupt", () => {
  const sessionKey = "test-session";
  const report: DangerReport = {
    toolName: "exec",
    params: { command: "rm -rf /" },
    reason: "Catastrophic deletion attempt",
    recommendation: "Do not execute this command",
    timestamp: Date.now(),
    source: "sync",
    ruleId: "DEL-001",
  };

  beforeEach(() => {
    sessionState.clear();
    setEmitAgentEvent(null as any);
  });

  it("sets and consumes danger flag", () => {
    expect(hasDangerFlag(sessionKey)).toBe(false);
    triggerInterrupt(sessionKey, report);
    expect(hasDangerFlag(sessionKey)).toBe(true);

    const consumed = consumeDangerFlag(sessionKey);
    expect(consumed).toEqual(report);
    expect(hasDangerFlag(sessionKey)).toBe(false);
  });

  it("returns null when no danger flag is set", () => {
    const consumed = consumeDangerFlag(sessionKey);
    expect(consumed).toBeNull();
  });

  it("clears danger flag explicitly", () => {
    triggerInterrupt(sessionKey, report);
    clearDangerFlag(sessionKey);
    expect(hasDangerFlag(sessionKey)).toBe(false);
  });

  it("resets session state", () => {
    triggerInterrupt(sessionKey, report);
    resetSession(sessionKey);
    expect(hasDangerFlag(sessionKey)).toBe(false);
  });

  it("emits agent event on interrupt", () => {
    const mockEmit = vi.fn();
    setEmitAgentEvent(mockEmit);

    triggerInterrupt(sessionKey, report);

    expect(mockEmit).toHaveBeenCalledOnce();
    expect(mockEmit).toHaveBeenCalledWith({
      stream: "security",
      data: expect.objectContaining({
        type: "danger_detected",
        sessionKey,
      }),
    });
  });

  it("formatDangerAlert produces readable output", () => {
    const alert = formatDangerAlert(report);
    expect(alert).toContain("[SecLaw] SECURITY ALERT");
    expect(alert).toContain("exec");
    expect(alert).toContain("Catastrophic deletion attempt");
    expect(alert).toContain("Do not execute this command");
    expect(alert).toContain("DEL-001");
  });

  it("formats alert without optional fields", () => {
    const minReport: DangerReport = {
      toolName: "bash",
      params: {},
      reason: "Suspicious activity",
      timestamp: Date.now(),
      source: "async",
    };
    const alert = formatDangerAlert(minReport);
    expect(alert).toContain("bash");
    expect(alert).toContain("Suspicious activity");
    expect(alert).not.toContain("Recommendation:");
    expect(alert).not.toContain("Rule:");
  });
});
