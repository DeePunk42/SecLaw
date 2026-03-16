/**
 * Dashboard API endpoint handlers.
 * Routes: /api/logs, /api/logs/stream, /api/config, /api/health, /api/rules
 */

import type * as http from "node:http";
import type { AuditLogEntry } from "../audit-log.js";
import type { DashboardDeps } from "./server.js";

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

function maskApiKey(value: unknown): string {
  return typeof value === "string" && value.length > 0 ? "***" : "";
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
  } else if (path === "/api/config" && method === "GET") {
    handleGetConfig(res, deps);
  } else if (path === "/api/config" && method === "PUT") {
    handleUpdateConfig(req, res, deps);
  } else if (path === "/api/health" && method === "GET") {
    handleHealth(res);
  } else if (path === "/api/rules" && method === "GET") {
    handleGetRules(res, deps);
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
  });

  // Send initial connected event
  res.write("event: connected\ndata: {}\n\n");

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

// ─── GET /api/config ───

function handleGetConfig(
  res: http.ServerResponse,
  deps: DashboardDeps,
): void {
  const config = deps.getConfig();
  const sanitized = {
    ...config,
    llm: {
      ...config.llm,
      apiKey: maskApiKey(config.llm.apiKey),
      endpoint: config.llm.endpoint,
    },
  };
  json(res, 200, sanitized);
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

    // Security boundary: block apiKey/endpoint changes via web
    if (partial.llm?.apiKey !== undefined || partial.llm?.endpoint !== undefined) {
      json(res, 403, { error: "Cannot modify apiKey or endpoint via dashboard" });
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
