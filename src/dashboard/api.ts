/**
 * Dashboard API endpoint handlers.
 * Routes: /api/logs, /api/logs/stream, /api/config, /api/health, /api/rules, /api/models
 */

import type * as http from "node:http";
import type { AuditLogEntry, ToolCallRecord } from "../audit-log.js";
import type { DashboardDeps } from "./server.js";
import { readSenderLabels, refreshSenderLabels } from "./sender-labels.js";
import {
  detectPlatform,
  runAllChecks,
  generateSummary,
  backupConfig,
  deployConfig,
  hardenPermissions,
  generateBaseline,
  hardenNpmrc,
  initGitBackup,
  runSchemaValidation,
  runSecurityAudit,
  deployChannelHint,
  deployAgents,
  immutableProtect,
  configureFirewall,
  checkDiskEncryption,
  deployAuditScript,
  deployVerifyHint,
} from "../hardening/index.js";
import type { HardenResult, HardeningReport } from "../hardening/index.js";

// ─── Helpers ───

function json(res: http.ServerResponse, status: number, data: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

// ─── Main Router ───

export function handleApiRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  url: URL,
  deps: DashboardDeps,
): void {
  const path = url.pathname;
  const method = req.method || "GET";

  if (path === "/api/logs/stream" && method === "GET") {
    handleLogsStream(req, res, url, deps);
  } else if (path === "/api/logs" && method === "GET") {
    handleGetLogs(res, url, deps);
  } else if (path === "/api/tool-calls/stream" && method === "GET") {
    handleToolCallsStream(req, res, url, deps);
  } else if (path === "/api/tool-calls" && method === "GET") {
    handleGetToolCalls(res, url, deps);
  } else if (path === "/api/config" && method === "GET") {
    handleGetConfig(res, deps);
  } else if (path === "/api/config" && method === "PUT") {
    handleUpdateConfig(req, res, deps);
  } else if (path === "/api/health/scan" && method === "GET") {
    handleHealthScan(res, deps);
  } else if (path === "/api/health/harden" && method === "POST") {
    handleHealthHarden(req, res, deps);
  } else if (path === "/api/health/report" && method === "GET") {
    handleHealthReport(res, deps);
  } else if (path === "/api/health" && method === "GET") {
    handleHealth(res);
  } else if (path === "/api/rules" && method === "GET") {
    handleGetRules(res, deps);
  } else if (path === "/api/models" && method === "GET") {
    handleGetModels(res, deps);
  } else if (path === "/api/sender-labels" && method === "GET") {
    handleGetSenderLabels(res, deps);
  } else if (path === "/api/sender-labels/refresh" && method === "POST") {
    handleRefreshSenderLabels(res, deps);
  } else {
    json(res, 404, { error: "Not found" });
  }
}

// ─── GET /api/logs ───

function handleGetLogs(
  res: http.ServerResponse,
  url: URL,
  deps: DashboardDeps,
): void {
  const limitParam = url.searchParams.get("limit");
  const limit = limitParam ? parseInt(limitParam, 10) : undefined;
  const tier = url.searchParams.get("tier") || undefined;
  const eventType = url.searchParams.get("eventType") || undefined;
  const toolName = url.searchParams.get("toolName") || undefined;

  let entries = deps.getAuditLog().getRecentEntries(limit);

  if (tier) {
    entries = entries.filter((e) => e.tier === tier);
  }
  if (eventType) {
    entries = entries.filter((e) => e.eventType === eventType);
  }
  if (toolName) {
    entries = entries.filter((e) => e.toolName === toolName);
  }

  json(res, 200, entries);
}

// ─── GET /api/logs/stream (SSE) ───

function handleLogsStream(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  url: URL,
  deps: DashboardDeps,
): void {
  const tier = url.searchParams.get("tier") || undefined;
  const eventType = url.searchParams.get("eventType") || undefined;
  const toolName = url.searchParams.get("toolName") || undefined;

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
  });
  res.flushHeaders();

  // Disable Nagle's algorithm to ensure immediate delivery of small SSE chunks
  res.socket?.setNoDelay?.(true);

  // Send initial connected event
  res.write("data: {}\n\n");

  const subscriber = (entry: AuditLogEntry): void => {
    if (tier && entry.tier !== tier) return;
    if (eventType && entry.eventType !== eventType) return;
    if (toolName && entry.toolName !== toolName) return;
    res.write(`data: ${JSON.stringify(entry)}\n\n`);
  };

  deps.getAuditLog().subscribe(subscriber);

  // Heartbeat every 30 seconds
  const heartbeat = setInterval(() => {
    res.write(": heartbeat\n\n");
  }, 30_000);

  // Cleanup on disconnect
  const cleanup = (): void => {
    clearInterval(heartbeat);
    deps.getAuditLog().unsubscribe(subscriber);
  };

  req.on("close", cleanup);
  req.on("error", cleanup);
}

// ─── GET /api/tool-calls ───

function handleGetToolCalls(
  res: http.ServerResponse,
  url: URL,
  deps: DashboardDeps,
): void {
  const limitParam = url.searchParams.get("limit");
  const limit = limitParam ? parseInt(limitParam, 10) : undefined;
  const tier = url.searchParams.get("tier") || undefined;
  const toolName = url.searchParams.get("toolName") || undefined;

  let records = deps.getAuditLog().getToolCallRecords(limit);

  if (tier) {
    records = records.filter((r) => r.tier === tier);
  }
  if (toolName) {
    records = records.filter((r) => r.toolName === toolName);
  }

  json(res, 200, records);
}

// ─── GET /api/tool-calls/stream (SSE) ───

function handleToolCallsStream(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  _url: URL,
  deps: DashboardDeps,
): void {
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "X-Accel-Buffering": "no",
  });
  res.flushHeaders();

  // Disable Nagle's algorithm to ensure immediate delivery of small SSE chunks
  res.socket?.setNoDelay?.(true);

  // Send initial connected event
  res.write("data: {}\n\n");

  const subscriber = (record: ToolCallRecord): void => {
    res.write(`data: ${JSON.stringify(record)}\n\n`);
  };

  deps.getAuditLog().subscribeToolCalls(subscriber);

  // Heartbeat every 30 seconds
  const heartbeat = setInterval(() => {
    res.write(": heartbeat\n\n");
  }, 30_000);

  // Cleanup on disconnect
  const cleanup = (): void => {
    clearInterval(heartbeat);
    deps.getAuditLog().unsubscribeToolCalls(subscriber);
  };

  req.on("close", cleanup);
  req.on("error", cleanup);
}

// ─── GET /api/config ───

function handleGetConfig(
  res: http.ServerResponse,
  deps: DashboardDeps,
): void {
  const config = deps.getConfig();
  json(res, 200, config);
}

// ─── PUT /api/config ───

async function handleUpdateConfig(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  deps: DashboardDeps,
): Promise<void> {
  try {
    const body = await readBody(req);
    const partial = JSON.parse(body);

    // Deprecated fields are no longer supported
    if (partial.llm?.apiKey !== undefined || partial.llm?.endpoint !== undefined) {
      json(res, 400, { ok: false, errors: ["llm.apiKey and llm.endpoint are no longer supported"] });
      return;
    }

    const result = deps.updateConfig(partial);
    if (result.ok) {
      json(res, 200, { ok: true });
    } else {
      json(res, 400, { ok: false, errors: result.errors });
    }
  } catch {
    json(res, 400, { error: "Invalid JSON body" });
  }
}

// ─── GET /api/health ───

function handleHealth(res: http.ServerResponse): void {
  json(res, 200, { status: "running" });
}

// ─── GET /api/rules ───

function handleGetRules(
  res: http.ServerResponse,
  deps: DashboardDeps,
): void {
  const rules = deps.getRuleEngine().getRules();
  json(res, 200, rules);
}

// ─── GET /api/models ───

function handleGetModels(
  res: http.ServerResponse,
  deps: DashboardDeps,
): void {
  json(res, 200, deps.getAvailableModels());
}

// ─── GET /api/sender-labels ───

function handleGetSenderLabels(
  res: http.ServerResponse,
  deps: DashboardDeps,
): void {
  const data = readSenderLabels(deps.getVarDir());
  json(res, 200, data);
}

// ─── POST /api/sender-labels/refresh ───

async function handleRefreshSenderLabels(
  res: http.ServerResponse,
  deps: DashboardDeps,
): Promise<void> {
  try {
    const data = await refreshSenderLabels(deps.getVarDir(), deps.getAuditLog(), deps.getWorkspacePath());
    json(res, 200, data);
  } catch {
    json(res, 500, { error: "Failed to refresh sender labels" });
  }
}

// ─── GET /api/health/scan ───

function handleHealthScan(
  res: http.ServerResponse,
  _deps: DashboardDeps,
): void {
  try {
    const platform = detectPlatform();
    const checks = runAllChecks(platform);
    const summary = generateSummary(checks);
    json(res, 200, { summary, checks, platform });
  } catch (err: any) {
    json(res, 500, { error: `Scan failed: ${err.message}` });
  }
}

// ─── POST /api/health/harden ───

const HIGH_RISK_ACTIONS = new Set([
  "firewall",
  "immutable-protect",
  "deploy-config",
  "permissions",
]);

const HARDEN_ACTIONS: Record<
  string,
  (mode?: "paranoid" | "balanced") => HardenResult
> = {
  backup: () => backupConfig(),
  "deploy-config": (mode) => deployConfig(mode || "balanced"),
  permissions: () => hardenPermissions(detectPlatform()),
  baseline: () => generateBaseline(),
  npmrc: () => hardenNpmrc(),
  "git-backup": () => initGitBackup(),
  validate: () => runSchemaValidation(),
  audit: () => runSecurityAudit(),
  "channel-hint": () => deployChannelHint(),
  "deploy-agents": () => deployAgents(),
  "immutable-protect": () => immutableProtect(detectPlatform()),
  firewall: () => configureFirewall(detectPlatform()),
  "disk-encryption": () => checkDiskEncryption(detectPlatform()),
  "deploy-audit": () => deployAuditScript(),
  "verify-hint": () => deployVerifyHint(),
};

async function handleHealthHarden(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  _deps: DashboardDeps,
): Promise<void> {
  try {
    const body = await readBody(req);
    const parsed = JSON.parse(body);
    const action: string = parsed.action;
    const mode: "paranoid" | "balanced" | undefined = parsed.mode;

    if (!action || !HARDEN_ACTIONS[action]) {
      json(res, 400, {
        error: `Unknown action: ${action}`,
        available: Object.keys(HARDEN_ACTIONS),
      });
      return;
    }

    const result = HARDEN_ACTIONS[action](mode);
    json(res, 200, {
      ...result,
      highRisk: HIGH_RISK_ACTIONS.has(action),
    });
  } catch (err: any) {
    json(res, 400, { error: `Invalid request: ${err.message}` });
  }
}

// ─── GET /api/health/report ───

function handleHealthReport(
  res: http.ServerResponse,
  _deps: DashboardDeps,
): void {
  try {
    const platform = detectPlatform();
    const checks = runAllChecks(platform);
    const summary = generateSummary(checks);
    const report: HardeningReport = {
      timestamp: new Date().toISOString(),
      platform,
      mode: "balanced",
      checks,
      summary,
    };
    json(res, 200, report);
  } catch (err: any) {
    json(res, 500, { error: `Report generation failed: ${err.message}` });
  }
}
