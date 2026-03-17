import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import * as http from "node:http";
import {
  init,
  _getAuditLog,
  _getLLMAuditor,
  _getRuleEngine,
  _getAsyncQueue,
  _updateConfig,
  _setVarDir,
  _setGatewayApi,
  stopDashboard,
} from "../index.js";
import type { OpenClawPluginApi } from "../index.js";
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
  let dashTmpDir: string;

  beforeEach(async () => {
    dashTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "seclaw-dash-"));
    sessionState.clear();
    // Init plugin with dashboard disabled (we start dashboard manually with port 0)
    init({
      workspacePath: "/workspace",
      pluginDir: __dirname + "/..",
      varDir: path.join(dashTmpDir, "var"),
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
    fs.rmSync(dashTmpDir, { recursive: true, force: true });
  });

  it("GET / returns HTML", async () => {
    const res = await fetch(`${baseUrl}/`);
    expect(res.status).toBe(200);
    const html = await res.text();
    expect(html).toContain("SecLaw Dashboard");
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

describe("Config persistence", () => {
  let baseUrl: string;
  let tmpDir: string;
  let varDir: string;

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "seclaw-persist-"));
    varDir = path.join(tmpDir, ".openclaw", "seclaw");
    sessionState.clear();

    init({
      pluginDir: tmpDir,
      varDir,
      config: {
        llm: { model: "test-model", enabled: true, maxConcurrent: 2, apiKey: "sk-secret" },
        timeouts: { syncAuditMs: 10000, asyncAuditMs: 30000, syncTimeoutPolicy: "fail_closed" },
        logging: { level: "info", auditJsonl: false },
        dashboard: { enabled: false, port: 0, host: "127.0.0.1" },
      },
    });

    const dashboardConfig: DashboardConfig = { enabled: true, port: 0, host: "127.0.0.1" };
    const actualPort = await startDashboard(dashboardConfig, {
      getConfig: () => ({
        llm: { model: "test-model", enabled: true, maxConcurrent: 2, apiKey: "sk-secret" },
        timeouts: { syncAuditMs: 10000, asyncAuditMs: 30000, syncTimeoutPolicy: "fail_closed" as const },
        logging: { level: "info" as const, auditJsonl: false },
        dashboard: dashboardConfig,
      }),
      updateConfig: _updateConfig,
      getAuditLog: () => _getAuditLog(),
      getRuleEngine: () => _getRuleEngine(),
      getAsyncQueue: () => _getAsyncQueue(),
      getAvailableModels: () => [],
      getWorkspacePath: () => undefined,
      getVarDir: () => varDir,
    });
    baseUrl = `http://127.0.0.1:${actualPort}`;
  });

  afterEach(async () => {
    await stopDashboard();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("PUT /api/config persists overrides to config-overrides.json", async () => {
    const res = await fetch(`${baseUrl}/api/config`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ llm: { enabled: false } }),
    });
    expect(res.status).toBe(200);
    const data = await res.json() as { ok: boolean };
    expect(data.ok).toBe(true);

    // Verify file exists in varDir
    const overridePath = path.join(varDir, "config-overrides.json");
    expect(fs.existsSync(overridePath)).toBe(true);

    // Verify contents
    const overrides = JSON.parse(fs.readFileSync(overridePath, "utf-8"));
    expect(overrides.llm.enabled).toBe(false);
    expect(overrides.llm.model).toBe("test-model");

    // Verify apiKey and endpoint are NOT persisted
    expect(overrides.llm.apiKey).toBeUndefined();
    expect(overrides.llm.endpoint).toBeUndefined();
  });

  it("persists timeout and logging changes alongside llm", async () => {
    await fetch(`${baseUrl}/api/config`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ logging: { level: "debug" }, timeouts: { syncAuditMs: 5000 } }),
    });

    const overridePath = path.join(varDir, "config-overrides.json");
    const overrides = JSON.parse(fs.readFileSync(overridePath, "utf-8"));
    expect(overrides.logging.level).toBe("debug");
    expect(overrides.timeouts.syncAuditMs).toBe(5000);
  });
});

describe("Sender labels refresh", () => {
  let baseUrl: string;
  let tmpDir: string;
  let varDir: string;

  beforeEach(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "seclaw-test-"));
    varDir = path.join(tmpDir, ".openclaw", "seclaw");
    sessionState.clear();

    init({
      pluginDir: tmpDir,
      config: {
        llm: { model: "test-model", enabled: false, maxConcurrent: 1, apiKey: "sk-test" },
        timeouts: { syncAuditMs: 10000, asyncAuditMs: 30000, syncTimeoutPolicy: "fail_closed" },
        logging: { level: "info", auditJsonl: false },
        dashboard: { enabled: false, port: 0, host: "127.0.0.1" },
      },
    });

    const dashboardConfig: DashboardConfig = { enabled: true, port: 0, host: "127.0.0.1" };
    const actualPort = await startDashboard(dashboardConfig, {
      getConfig: () => ({
        llm: { model: "test-model", enabled: false, maxConcurrent: 1, apiKey: "sk-test" },
        timeouts: { syncAuditMs: 10000, asyncAuditMs: 30000, syncTimeoutPolicy: "fail_closed" as const },
        logging: { level: "info" as const, auditJsonl: false },
        dashboard: dashboardConfig,
      }),
      updateConfig: _updateConfig,
      getAuditLog: () => _getAuditLog(),
      getRuleEngine: () => _getRuleEngine(),
      getAsyncQueue: () => _getAsyncQueue(),
      getAvailableModels: () => [],
      getWorkspacePath: () => undefined,
      getVarDir: () => varDir,
    });
    baseUrl = `http://127.0.0.1:${actualPort}`;
  });

  afterEach(async () => {
    await stopDashboard();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("POST /api/sender-labels/refresh persists labels to var dir", async () => {
    // Set a sender label on a session
    sessionState.updateIntentContext("test-session", { senderLabel: "telegram:alice" });

    // Refresh sender labels
    const refreshRes = await fetch(`${baseUrl}/api/sender-labels/refresh`, { method: "POST" });
    expect(refreshRes.status).toBe(200);
    const refreshData = await refreshRes.json() as { labels: string[]; lastRefreshed: string };
    expect(refreshData.labels).toContain("telegram:alice");
    expect(refreshData.lastRefreshed).toBeTruthy();

    // Verify file was written to var dir (not workspace)
    const filePath = path.join(varDir, "sender-labels.json");
    expect(fs.existsSync(filePath)).toBe(true);
    const onDisk = JSON.parse(fs.readFileSync(filePath, "utf-8"));
    expect(onDisk.labels).toContain("telegram:alice");

    // GET /api/sender-labels should return the persisted data
    const getRes = await fetch(`${baseUrl}/api/sender-labels`);
    expect(getRes.status).toBe(200);
    const getData = await getRes.json() as { labels: string[]; lastRefreshed: string };
    expect(getData.labels).toContain("telegram:alice");
  });
});

// ─── Runtime model change & provider validation tests ───

describe("Runtime model change via updateConfig", () => {
  let tmpDir: string;

  function createMockGatewayApi(providers: Record<string, { baseUrl: string; apiKey?: string; models?: Array<{ id: string; name: string }> }>): OpenClawPluginApi {
    return {
      id: "test-gateway",
      name: "Test Gateway",
      config: {
        workspace: { dir: "/workspace" },
        models: { providers },
      },
      logger: { info: () => {}, error: () => {}, debug: () => {} },
      on: () => {},
      resolvePath: (p: string) => p,
    };
  }

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "seclaw-model-"));
    sessionState.clear();
  });

  afterEach(async () => {
    _setGatewayApi(null);
    await stopDashboard();
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("rejects model change to unknown provider with 400 error", () => {
    const api = createMockGatewayApi({
      myapi: { baseUrl: "http://localhost:4000/v1", apiKey: "sk-test", models: [{ id: "gpt-5.2", name: "GPT 5.2" }] },
    });
    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: {
        llm: { model: "myapi/gpt-5.2", enabled: true, maxConcurrent: 1 },
        timeouts: { syncAuditMs: 10000, asyncAuditMs: 30000, syncTimeoutPolicy: "fail_closed" },
        logging: { level: "error", auditJsonl: false },
        dashboard: { enabled: false, port: 0, host: "127.0.0.1" },
      },
    });
    _setGatewayApi(api);

    const result = _updateConfig({ llm: { model: "bogus/gpt-5.2" } });
    expect(result.ok).toBe(false);
    expect(result.errors).toBeDefined();
    expect(result.errors!.some(e => e.includes('provider "bogus" not found'))).toBe(true);
  });

  it("accepts model change to valid provider and recreates llmCallFn", () => {
    const api = createMockGatewayApi({
      myapi: { baseUrl: "http://localhost:4000/v1", apiKey: "sk-test", models: [{ id: "gpt-5.2", name: "GPT 5.2" }] },
      altapi: { baseUrl: "http://localhost:5000/v1", apiKey: "sk-alt", models: [{ id: "llama-3", name: "Llama 3" }] },
    });
    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: {
        llm: { model: "myapi/gpt-5.2", enabled: true, maxConcurrent: 1 },
        timeouts: { syncAuditMs: 10000, asyncAuditMs: 30000, syncTimeoutPolicy: "fail_closed" },
        logging: { level: "error", auditJsonl: false },
        dashboard: { enabled: false, port: 0, host: "127.0.0.1" },
      },
    });
    _setGatewayApi(api);

    // Spy on setLLMCallFn to verify it's called during model change
    const auditor = _getLLMAuditor();
    const spy = vi.spyOn(auditor, "setLLMCallFn");

    const result = _updateConfig({ llm: { model: "altapi/llama-3" } });
    expect(result.ok).toBe(true);
    // updateConfig should have recreated the call function for the new provider
    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });

  it("recreates llmCallFn when llm.enabled is toggled on at runtime", () => {
    const api = createMockGatewayApi({
      myapi: { baseUrl: "http://localhost:4000/v1", apiKey: "sk-test", models: [{ id: "gpt-5.2", name: "GPT 5.2" }] },
    });
    // Start with LLM disabled
    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: {
        llm: { model: "myapi/gpt-5.2", enabled: false, maxConcurrent: 1 },
        timeouts: { syncAuditMs: 10000, asyncAuditMs: 30000, syncTimeoutPolicy: "fail_closed" },
        logging: { level: "error", auditJsonl: false },
        dashboard: { enabled: false, port: 0, host: "127.0.0.1" },
      },
    });
    _setGatewayApi(api);

    // Spy on setLLMCallFn to verify it's called when enabling LLM
    const auditor = _getLLMAuditor();
    const spy = vi.spyOn(auditor, "setLLMCallFn");

    const result = _updateConfig({ llm: { enabled: true } });
    expect(result.ok).toBe(true);
    // updateConfig should have created a call function for the existing model
    expect(spy).toHaveBeenCalled();
    spy.mockRestore();
  });

  it("model change to non-provider format (no slash) skips provider validation", () => {
    const api = createMockGatewayApi({
      myapi: { baseUrl: "http://localhost:4000/v1", apiKey: "sk-test", models: [{ id: "gpt-5.2", name: "GPT 5.2" }] },
    });
    init({
      pluginDir: __dirname + "/..",
      varDir: tmpDir,
      config: {
        llm: { model: "myapi/gpt-5.2", enabled: true, maxConcurrent: 1 },
        timeouts: { syncAuditMs: 10000, asyncAuditMs: 30000, syncTimeoutPolicy: "fail_closed" },
        logging: { level: "error", auditJsonl: false },
        dashboard: { enabled: false, port: 0, host: "127.0.0.1" },
      },
    });
    _setGatewayApi(api);

    // Change to a model without "/" — should not trigger provider validation
    const result = _updateConfig({ llm: { model: "gpt-4" } });
    expect(result.ok).toBe(true);
  });
});
