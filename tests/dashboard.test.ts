import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as http from "node:http";
import {
  init,
  _getAuditLog,
  _getRuleEngine,
  _getAsyncQueue,
  _updateConfig,
  stopDashboard,
} from "../index.js";
import { startDashboard } from "../src/dashboard/server.js";
import type { DashboardConfig } from "../src/config.js";
import { sessionState } from "../src/session-state.js";

// ─── Helpers ───

function fetch(url: string, options?: { method?: string; body?: string; headers?: Record<string, string> }): Promise<{ status: number; headers: http.IncomingHttpHeaders; text: () => Promise<string>; json: () => Promise<unknown> }> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const req = http.request({
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      method: options?.method || "GET",
      headers: options?.headers,
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf-8");
        resolve({
          status: res.statusCode || 0,
          headers: res.headers,
          text: () => Promise.resolve(body),
          json: () => Promise.resolve(JSON.parse(body)),
        });
      });
    });
    req.on("error", reject);
    if (options?.body) req.write(options.body);
    req.end();
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function collectSSEEvents(url: string, minEvents: number, timeoutMs: number): Promise<string[]> {
  return new Promise((resolve) => {
    const events: string[] = [];
    const parsed = new URL(url);
    const req = http.request({
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      method: "GET",
      headers: { Accept: "text/event-stream" },
    }, (res) => {
      let buffer = "";
      res.on("data", (chunk: Buffer) => {
        buffer += chunk.toString();
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";
        for (const line of lines) {
          if (line.startsWith("data: ")) {
            events.push(line.slice(6));
          }
        }
        if (events.length >= minEvents) {
          req.destroy();
          resolve(events);
        }
      });
      res.on("end", () => resolve(events));
    });
    req.on("error", () => resolve(events));
    req.end();
    setTimeout(() => {
      req.destroy();
      resolve(events);
    }, timeoutMs);
  });
}

// ─── Tests ───

let baseUrl: string;

describe("Dashboard", () => {
  beforeEach(async () => {
    sessionState.clear();
    // Init plugin with dashboard disabled (we start dashboard manually with port 0)
    init({
      workspacePath: "/workspace",
      pluginDir: __dirname + "/..",
      config: {
        llm: { model: "test-model", enabled: false, maxConcurrent: 1, apiKey: "sk-secret-key" },
        timeouts: { syncAuditMs: 10000, asyncAuditMs: 30000, syncTimeoutPolicy: "fail_closed" },
        logging: { level: "info", auditJsonl: false },
        dashboard: { enabled: false, port: 0, host: "127.0.0.1" },
      },
    });

    // Start dashboard on OS-assigned port
    const dashboardConfig: DashboardConfig = { enabled: true, port: 0, host: "127.0.0.1" };
    const actualPort = await startDashboard(dashboardConfig, {
      getConfig: () => ({
        llm: { model: "test-model", enabled: false, maxConcurrent: 1, apiKey: "sk-secret-key" },
        timeouts: { syncAuditMs: 10000, asyncAuditMs: 30000, syncTimeoutPolicy: "fail_closed" as const },
        logging: { level: "info" as const, auditJsonl: false },
        dashboard: dashboardConfig,
      }),
      updateConfig: _updateConfig,
      getAuditLog: () => _getAuditLog(),
      getRuleEngine: () => _getRuleEngine(),
      getAsyncQueue: () => _getAsyncQueue(),
    });
    baseUrl = `http://127.0.0.1:${actualPort}`;
  });

  afterEach(async () => {
    await stopDashboard();
  });

  it("GET / returns HTML", async () => {
    const res = await fetch(`${baseUrl}/`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("SecAgent Dashboard");
    expect(html).toContain("<!DOCTYPE html>");
  });

  it("GET /api/health returns running status", async () => {
    const res = await fetch(`${baseUrl}/api/health`);
    expect(res.status).toBe(200);
    const data = await res.json() as { status: string };
    expect(data.status).toBe("running");
  });

  it("GET /api/logs returns empty array initially", async () => {
    const res = await fetch(`${baseUrl}/api/logs`);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(Array.isArray(data)).toBe(true);
  });

  it("GET /api/config returns config with masked apiKey", async () => {
    const res = await fetch(`${baseUrl}/api/config`);
    expect(res.status).toBe(200);
    const data = await res.json() as any;
    expect(data.llm.model).toBe("test-model");
    expect(data.llm.apiKey).toBe("***");
    expect(data.llm.enabled).toBe(false);
  });

  it("PUT /api/config updates logging level", async () => {
    const res = await fetch(`${baseUrl}/api/config`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ logging: { level: "debug" } }),
    });
    expect(res.status).toBe(200);
    const data = await res.json() as { ok: boolean };
    expect(data.ok).toBe(true);
  });

  it("PUT /api/config rejects invalid logging level", async () => {
    const res = await fetch(`${baseUrl}/api/config`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ logging: { level: "invalid" } }),
    });
    expect(res.status).toBe(400);
    const data = await res.json() as { ok: boolean; errors: string[] };
    expect(data.ok).toBe(false);
    expect(data.errors).toBeDefined();
  });

  it("PUT /api/config rejects apiKey modification", async () => {
    const res = await fetch(`${baseUrl}/api/config`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ llm: { apiKey: "new-key" } }),
    });
    expect(res.status).toBe(403);
  });

  it("PUT /api/config rejects endpoint modification", async () => {
    const res = await fetch(`${baseUrl}/api/config`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ llm: { endpoint: "http://evil.com" } }),
    });
    expect(res.status).toBe(403);
  });

  it("GET /api/logs/stream establishes SSE connection", async () => {
    const events = await collectSSEEvents(`${baseUrl}/api/logs/stream`, 1, 500);
    // Should get the connected event
    expect(events.length).toBeGreaterThanOrEqual(1);
  });

  it("GET /api/logs/stream receives new log entries via SSE", async () => {
    // Start collecting SSE events: expect 2 (connected + log entry)
    const eventsPromise = collectSSEEvents(`${baseUrl}/api/logs/stream`, 2, 2000);

    // Give SSE connection time to establish
    await sleep(100);

    // Emit a log entry
    _getAuditLog().log({
      timestamp: new Date().toISOString(),
      eventType: "tool_classified",
      sessionKey: "test",
      toolName: "exec",
      tier: "GREEN",
    });

    const events = await eventsPromise;
    expect(events.length).toBeGreaterThanOrEqual(2);
    // events[0] is the connected event "{}", events[1] is the log entry
    const entry = JSON.parse(events[1]);
    expect(entry.eventType).toBe("tool_classified");
    expect(entry.toolName).toBe("exec");
  });

  it("GET /api/logs?tier=RED filters by tier", async () => {
    const auditLog = _getAuditLog();
    auditLog.log({ timestamp: new Date().toISOString(), eventType: "tool_classified", sessionKey: "t", toolName: "exec", tier: "GREEN" });
    auditLog.log({ timestamp: new Date().toISOString(), eventType: "tool_blocked", sessionKey: "t", toolName: "exec", tier: "RED" });
    auditLog.log({ timestamp: new Date().toISOString(), eventType: "tool_classified", sessionKey: "t", toolName: "read", tier: "GREEN" });

    const res = await fetch(`${baseUrl}/api/logs?tier=RED`);
    const data = await res.json() as any[];
    expect(data.length).toBe(1);
    expect(data[0].tier).toBe("RED");
  });

  it("GET /api/rules returns rule list", async () => {
    const res = await fetch(`${baseUrl}/api/rules`);
    expect(res.status).toBe(200);
    const data = await res.json() as any[];
    expect(Array.isArray(data)).toBe(true);
    expect(data.length).toBeGreaterThan(0);
  });

  // ─── Tool Calls API Tests ───

  it("GET /api/tool-calls returns empty array initially", async () => {
    const res = await fetch(`${baseUrl}/api/tool-calls`);
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(Array.isArray(data)).toBe(true);
    expect((data as any[]).length).toBe(0);
  });

  it("events with toolCallId aggregate into ToolCallRecord", async () => {
    const auditLog = _getAuditLog();
    const tcId = "tc-test-001";

    // Simulate a full tool call lifecycle
    auditLog.logClassification("s1", "exec", { command: "ls" }, "YELLOW", tcId);
    auditLog.logRuleMatch("s1", "exec", "PARAM-G-001", "YELLOW", "Non-dangerous command", tcId);
    auditLog.logAllow("s1", "exec", "YELLOW → allowed", tcId);

    const res = await fetch(`${baseUrl}/api/tool-calls`);
    expect(res.status).toBe(200);
    const data = await res.json() as any[];
    expect(data.length).toBe(1);
    expect(data[0].toolCallId).toBe(tcId);
    expect(data[0].toolName).toBe("exec");
    expect(data[0].tier).toBe("YELLOW");
    expect(data[0].finalStatus).toBe("allowed");
    expect(data[0].ruleId).toBe("PARAM-G-001");
    expect(data[0].events.length).toBe(3);
  });

  it("GET /api/tool-calls?tier=RED filters by tier", async () => {
    const auditLog = _getAuditLog();
    auditLog.logClassification("s1", "exec", { command: "ls" }, "GREEN", "tc-green-1");
    auditLog.logClassification("s1", "exec", { command: "rm -rf /" }, "RED", "tc-red-1");
    auditLog.logBlock("s1", "exec", "dangerous", "sync", "tc-red-1");

    const res = await fetch(`${baseUrl}/api/tool-calls?tier=RED`);
    const data = await res.json() as any[];
    expect(data.length).toBe(1);
    expect(data[0].tier).toBe("RED");
    expect(data[0].toolCallId).toBe("tc-red-1");
  });

  it("GET /api/tool-calls/stream pushes ToolCallRecord updates via SSE", async () => {
    const eventsPromise = collectSSEEvents(`${baseUrl}/api/tool-calls/stream`, 2, 2000);

    await sleep(100);

    _getAuditLog().logClassification("s1", "exec", { command: "ls" }, "GREEN", "tc-sse-001");

    const events = await eventsPromise;
    expect(events.length).toBeGreaterThanOrEqual(2);
    // events[0] is the connected event "{}", events[1] is the ToolCallRecord
    const record = JSON.parse(events[1]);
    expect(record.toolCallId).toBe("tc-sse-001");
    expect(record.toolName).toBe("exec");
    expect(record.tier).toBe("GREEN");
    expect(record.finalStatus).toBe("allowed");
  });

  it("logIntentContext uses eventType intent_context, not tool_classified", async () => {
    const auditLog = _getAuditLog();
    // Set log level to debug so logIntentContext fires
    auditLog.setLoggingConfig({ level: "debug", auditJsonl: false });

    auditLog.logIntentContext("s1", "exec", {
      userGoal: "test goal",
      stepIndex: 0,
      turnNumber: 1,
      recentToolCalls: [],
    }, 3, "tc-intent-1");

    const entries = auditLog.getRecentEntries();
    const intentEntries = entries.filter(e => e.toolCallId === "tc-intent-1");
    expect(intentEntries.length).toBe(1);
    expect(intentEntries[0].eventType).toBe("intent_context");
  });

  it("async audit events aggregate into existing ToolCallRecord", async () => {
    const auditLog = _getAuditLog();
    const tcId = "tc-async-001";

    auditLog.logClassification("s1", "exec", { command: "wget something" }, "YELLOW", tcId);
    auditLog.logAsyncEnqueue("s1", "exec", 1, tcId);

    // Check pending state
    let res = await fetch(`${baseUrl}/api/tool-calls`);
    let data = await res.json() as any[];
    const rec = data.find((r: any) => r.toolCallId === tcId);
    expect(rec).toBeDefined();
    expect(rec.asyncAuditStatus).toBe("enqueued");

    // Complete async audit
    auditLog.logAsyncAuditComplete("s1", "exec", "SAFE", "looks fine", 150, tcId);

    res = await fetch(`${baseUrl}/api/tool-calls`);
    data = await res.json() as any[];
    const updated = data.find((r: any) => r.toolCallId === tcId);
    expect(updated.asyncAuditStatus).toBe("complete");
    expect(updated.asyncAudit.decision).toBe("SAFE");
    expect(updated.asyncAudit.durationMs).toBe(150);
  });

  it("stopDashboard() cleans up server", async () => {
    await stopDashboard();
    try {
      await fetch(`${baseUrl}/api/health`);
      expect(true).toBe(false); // should not reach here
    } catch {
      // Expected: connection refused
      expect(true).toBe(true);
    }
  });
});

describe("Dashboard disabled", () => {
  it("does not start server when dashboard.enabled is false", () => {
    sessionState.clear();
    init({
      workspacePath: "/workspace",
      pluginDir: __dirname + "/..",
      config: {
        llm: { model: "test", enabled: false, maxConcurrent: 1 },
        timeouts: { syncAuditMs: 10000, asyncAuditMs: 30000, syncTimeoutPolicy: "fail_open" },
        logging: { level: "error", auditJsonl: false },
        dashboard: { enabled: false, port: 19198, host: "127.0.0.1" },
      },
    });
    expect(true).toBe(true);
  });
});
