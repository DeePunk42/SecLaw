/**
 * Dashboard API endpoint handlers.
 * Routes: /api/logs, /api/logs/stream, /api/config, /api/health, /api/rules, /api/models
 */

import type * as http from "node:http";
import * as fs from "node:fs";
import * as path from "node:path";
import type { AuditLogEntry, ToolCallRecord } from "../audit-log.js";
import type { DashboardDeps } from "./server.js";
import type { SigmaRule, IntentContext } from "../config.js";
import { readSenderLabels, refreshSenderLabels } from "./sender-labels.js";
import { parse as parseYaml, stringify as stringifyYaml } from "yaml";
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

const RULE_FILE_NAME_RE = /^[A-Za-z0-9._-]+\.(ya?ml)$/i;
const RULE_TESTER_VALUE_FIELDS = new Set(["command", "path", "url", "query"]);
const RULE_TESTER_PATH_TOOLS = new Set([
  "fs_write",
  "write",
  "edit",
  "apply_patch",
  "fs_read",
  "read",
  "fs_delete",
  "fs_move",
]);

function getRulesDir(deps: DashboardDeps): string {
  return path.join(deps.getOpenClawDir(), "seclaw", "rules");
}

function normalizeRuleFileName(raw: string | null): string | null {
  if (!raw) return null;
  if (!RULE_FILE_NAME_RE.test(raw)) return null;
  if (raw.includes("/") || raw.includes("\\")) return null;
  return raw;
}

function listRuleFiles(deps: DashboardDeps): string[] {
  const rulesDir = getRulesDir(deps);
  if (!fs.existsSync(rulesDir)) return [];
  return fs
    .readdirSync(rulesDir, { withFileTypes: true })
    .filter((entry) => entry.isFile() && RULE_FILE_NAME_RE.test(entry.name))
    .map((entry) => entry.name)
    .sort((a, b) => a.localeCompare(b));
}

function inferRuleTestValueField(toolName: string): "command" | "path" | "url" | "query" {
  if (toolName === "exec" || toolName === "bash") return "command";
  if (toolName === "web_fetch") return "url";
  if (toolName === "web_search") return "query";
  if (RULE_TESTER_PATH_TOOLS.has(toolName)) return "path";
  return "path";
}

function buildRuleTestParams(
  toolName: string,
  value: string,
  valueField?: string,
): Record<string, unknown> {
  const field = valueField && RULE_TESTER_VALUE_FIELDS.has(valueField)
    ? valueField
    : inferRuleTestValueField(toolName);
  return { [field]: value };
}

function loadRulesFromYamlFile(filePath: string): SigmaRule[] {
  const content = fs.existsSync(filePath) ? fs.readFileSync(filePath, "utf-8") : "";
  if (!content.trim()) return [];
  const parsed = parseYaml(content);
  // Support both formats: plain array or { rules: [...] }
  if (Array.isArray(parsed)) return parsed as SigmaRule[];
  if (parsed && typeof parsed === "object" && Array.isArray((parsed as Record<string, unknown>).rules)) {
    return (parsed as Record<string, unknown>).rules as SigmaRule[];
  }
  throw new Error("Rule file must contain rules");
}

function saveRulesToYamlFile(filePath: string, rules: SigmaRule[]): void {
  const content = stringifyYaml(rules);
  const normalized = content.endsWith("\n") ? content : `${content}\n`;
  fs.writeFileSync(filePath, normalized, "utf-8");
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
  } else if (path === "/api/rules/files" && method === "GET") {
    handleGetRuleFiles(res, deps);
  } else if (path === "/api/rules/file" && method === "GET") {
    handleGetRuleFile(res, url, deps);
  } else if (path === "/api/rules/file" && method === "PUT") {
    handleSaveRuleFile(req, res, url, deps);
  } else if (path === "/api/rules/file/parse" && method === "POST") {
    handleParseRuleFile(req, res);
  } else if (path === "/api/rules/file/download" && method === "GET") {
    handleDownloadRuleFile(res, url, deps);
  } else if (path === "/api/rules/test" && method === "POST") {
    handleTestRule(req, res, deps);
  } else if (path === "/api/rules" && method === "GET") {
    handleGetRules(res, deps);
  } else if (path === "/api/models" && method === "GET") {
    handleGetModels(res, deps);
  } else if (path === "/api/models/test" && method === "POST") {
    handleTestModel(req, res, deps);
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
  // Mask apiKey before sending to dashboard
  const safeConfig = config.llm.apiKey
    ? { ...config, llm: { ...config.llm, apiKey: "***" } }
    : config;
  json(res, 200, safeConfig);
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
    if (partial.llm?.endpoint !== undefined) {
      json(res, 400, { ok: false, errors: ["llm.endpoint is no longer supported"] });
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
  const platform = deps.getRuleEngine().getPlatform();
  json(res, 200, { rules, platform });
}

// ─── POST /api/rules/test ───

async function handleTestRule(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  deps: DashboardDeps,
): Promise<void> {
  try {
    const body = await readBody(req);
    const parsed = JSON.parse(body);
    const toolName = typeof parsed.toolName === "string" ? parsed.toolName.trim() : "";
    if (!toolName) {
      json(res, 400, { error: "toolName is required" });
      return;
    }

    let params: Record<string, unknown> = {};
    if (typeof parsed.params === "string") {
      try {
        params = JSON.parse(parsed.params);
      } catch {
        json(res, 400, { error: "params must be valid JSON" });
        return;
      }
    } else if (parsed.params && typeof parsed.params === "object") {
      params = parsed.params as Record<string, unknown>;
    } else if ("value" in parsed) {
      if (typeof parsed.value !== "string" || parsed.value.trim() === "") {
        json(res, 400, { error: "value is required when params is omitted" });
        return;
      }
      const valueField = typeof parsed.valueField === "string"
        ? parsed.valueField.trim()
        : undefined;
      if (valueField && !RULE_TESTER_VALUE_FIELDS.has(valueField)) {
        json(res, 400, { error: "valueField must be one of: command, path, url, query" });
        return;
      }
      params = buildRuleTestParams(toolName, parsed.value.trim(), valueField);
    }

    const intentCtx: IntentContext = {
      userGoal: "rule test",
      stepIndex: 0,
      turnNumber: 0,
      recentToolCalls: [],
    };

    const result = deps.getRuleEngine().classify(
      toolName,
      params,
      intentCtx,
      deps.getWorkspacePath(),
    );
    json(res, 200, result);
  } catch {
    json(res, 400, { error: "Invalid JSON body" });
  }
}

// ─── GET /api/rules/files ───

function handleGetRuleFiles(
  res: http.ServerResponse,
  deps: DashboardDeps,
): void {
  const files = listRuleFiles(deps);
  json(res, 200, { files });
}

// ─── GET /api/rules/file?name=xxx.yaml ───

function handleGetRuleFile(
  res: http.ServerResponse,
  url: URL,
  deps: DashboardDeps,
): void {
  const fileName = normalizeRuleFileName(url.searchParams.get("name"));
  if (!fileName) {
    json(res, 400, { error: "Invalid rule file name" });
    return;
  }

  const filePath = path.join(getRulesDir(deps), fileName);
  try {
    const rules = loadRulesFromYamlFile(filePath);
    json(res, 200, { name: fileName, rules });
  } catch (err: any) {
    json(res, 400, { error: `Failed to parse rule file: ${err.message}` });
  }
}

// ─── POST /api/rules/file/parse ───

async function handleParseRuleFile(
  req: http.IncomingMessage,
  res: http.ServerResponse,
): Promise<void> {
  try {
    const body = await readBody(req);
    const parsed = JSON.parse(body);
    if (typeof parsed.content !== "string") {
      json(res, 400, { error: "content must be a string" });
      return;
    }
    const yamlParsed = parseYaml(parsed.content);
    let rules: unknown[];
    if (Array.isArray(yamlParsed)) {
      rules = yamlParsed;
    } else if (yamlParsed && typeof yamlParsed === "object" && Array.isArray((yamlParsed as Record<string, unknown>).rules)) {
      rules = (yamlParsed as Record<string, unknown>).rules as unknown[];
    } else {
      json(res, 400, { error: "Rule file must contain rules" });
      return;
    }
    json(res, 200, { rules });
  } catch (err: any) {
    json(res, 400, { error: `Invalid rule file: ${err.message}` });
  }
}

// ─── PUT /api/rules/file?name=xxx.yaml ───

async function handleSaveRuleFile(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  url: URL,
  deps: DashboardDeps,
): Promise<void> {
  const fileName = normalizeRuleFileName(url.searchParams.get("name"));
  if (!fileName) {
    json(res, 400, { error: "Invalid rule file name" });
    return;
  }

  try {
    const body = await readBody(req);
    const parsed = JSON.parse(body);
    if (!Array.isArray(parsed.rules)) {
      json(res, 400, { error: "rules must be an array" });
      return;
    }

    const rulesDir = getRulesDir(deps);
    fs.mkdirSync(rulesDir, { recursive: true });
    const filePath = path.join(rulesDir, fileName);
    saveRulesToYamlFile(filePath, parsed.rules as SigmaRule[]);
    json(res, 200, { ok: true });
  } catch (err: any) {
    json(res, 400, { error: `Failed to save rule file: ${err.message}` });
  }
}

// ─── GET /api/rules/file/download?name=xxx.yaml ───

function handleDownloadRuleFile(
  res: http.ServerResponse,
  url: URL,
  deps: DashboardDeps,
): void {
  const fileName = normalizeRuleFileName(url.searchParams.get("name"));
  if (!fileName) {
    json(res, 400, { error: "Invalid rule file name" });
    return;
  }

  const filePath = path.join(getRulesDir(deps), fileName);
  try {
    const content = fs.readFileSync(filePath, "utf-8");
    res.writeHead(200, {
      "Content-Type": "application/x-yaml; charset=utf-8",
      "Content-Disposition": `attachment; filename="${fileName}"`,
    });
    res.end(content);
  } catch (err: any) {
    json(res, 404, { error: `Cannot read rule file: ${err.message}` });
  }
}

// ─── GET /api/models ───

function handleGetModels(
  res: http.ServerResponse,
  deps: DashboardDeps,
): void {
  json(res, 200, deps.getAvailableModels());
}

// ─── POST /api/models/test ───

async function handleTestModel(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  deps: DashboardDeps,
): Promise<void> {
  try {
    const body = await readBody(req);
    const parsed = JSON.parse(body) as { model?: unknown };
    const model = typeof parsed.model === "string" ? parsed.model.trim() : "";
    if (!model) {
      json(res, 400, { ok: false, error: "model is required" });
      return;
    }
    if (!model.includes("/")) {
      json(res, 400, {
        ok: false,
        model,
        error: "model must be in provider/model format",
      });
      return;
    }

    const result = await deps.testModelAvailability(model);
    if (result.ok) {
      json(res, 200, result);
      return;
    }
    json(res, result.statusCode || 400, result);
  } catch {
    json(res, 400, { ok: false, error: "Invalid JSON body" });
  }
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
