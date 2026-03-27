/**
 * Dashboard HTTP server — lifecycle management and request routing.
 * Uses node:http with zero external dependencies.
 */

import * as http from "node:http";
import { createHash, timingSafeEqual } from "node:crypto";
import type { DashboardConfig, SecLawConfig } from "../config.js";
import type { AuditLog } from "../audit-log.js";
import type { RuleEngine } from "../rule-engine.js";
import type { AsyncAuditQueue } from "../async-audit-queue.js";
import { handleApiRequest } from "./api.js";
import { getDashboardHtml } from "./html.js";

export interface ModelOption {
  value: string;
  label: string;
}

export interface ModelTestResult {
  ok: boolean;
  model: string;
  latencyMs?: number;
  preview?: string;
  error?: string;
  errorCode?: string;
  statusCode?: number;
}

export interface DashboardDeps {
  getConfig: () => SecLawConfig;
  updateConfig: (partial: Partial<SecLawConfig>) => { ok: boolean; errors?: string[] };
  getAuditLog: () => AuditLog;
  getRuleEngine: () => RuleEngine;
  getAsyncQueue: () => AsyncAuditQueue;
  getAvailableModels: () => ModelOption[];
  testModelAvailability: (model: string) => Promise<ModelTestResult>;
  getWorkspacePath: () => string | undefined;
  getVarDir: () => string;
  getOpenClawDir: () => string;
  getToken?: () => string | undefined;
  reloadRules?: () => void;
}

function verifyToken(provided: string | undefined, expected: string): boolean {
  if (typeof provided !== "string" || provided.length === 0) return false;
  const hash = (s: string) => createHash("sha256").update(s).digest();
  return timingSafeEqual(hash(provided), hash(expected));
}

let server: http.Server | null = null;

/**
 * Create a request handler for the dashboard routes.
 * Used by both the gateway route (production) and standalone server (testing).
 *
 * @param deps - Dashboard dependencies (config, audit log, rule engine, etc.)
 * @param basePath - URL prefix to strip (e.g. "/plugins/seclaw"); empty for standalone
 */
export function createDashboardRouteHandler(
  deps: DashboardDeps,
  basePath: string,
): (req: http.IncomingMessage, res: http.ServerResponse) => Promise<boolean> {
  let cachedHtml: string | null = null;
  return async (req, res) => {
    const rawUrl = req.url || "/";
    let path = rawUrl;
    if (basePath && rawUrl.startsWith(basePath)) {
      path = rawUrl.slice(basePath.length) || "/";
    }

    // CORS headers
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return true;
    }

    const url = new URL(path, "http://127.0.0.1");

    // API routes
    if (url.pathname.startsWith("/api/")) {
      const token = deps.getToken?.();
      if (token) {
        const authHeader = req.headers.authorization;
        const bearerToken = authHeader?.startsWith("Bearer ")
          ? authHeader.slice(7).trim()
          : undefined;
        const queryToken = url.searchParams.get("token") || undefined;
        const provided = bearerToken || queryToken;
        if (!verifyToken(provided, token)) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: { message: "Unauthorized", type: "unauthorized" } }));
          return true;
        }
        url.searchParams.delete("token");
      }
      handleApiRequest(req, res, url, deps);
      return true;
    }

    // Serve embedded HTML for all other routes (SPA)
    if (!cachedHtml) {
      cachedHtml = getDashboardHtml(basePath);
    }
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(cachedHtml);
    return true;
  };
}

/**
 * Start the dashboard HTTP server (standalone — used for testing).
 * Resolves with the actual port (useful when port=0 for OS-assigned port).
 */
export function startDashboard(
  dashboardConfig: DashboardConfig,
  deps: DashboardDeps,
): Promise<number> {
  const port = dashboardConfig.port ?? 19198;
  const host = dashboardConfig.host ?? "0.0.0.0";

  if (server) {
    const addr = server.address();
    const actualPort = addr && typeof addr !== "string" ? addr.port : port;
    return Promise.resolve(actualPort);
  }
  const handler = createDashboardRouteHandler(deps, "");

  return new Promise((resolve, reject) => {
    const srv = http.createServer((req, res) => {
      handler(req, res);
    });

    srv.unref(); // don't block process exit

    srv.on("error", (err) => {
      reject(err);
    });

    srv.listen(port, host, () => {
      server = srv;
      const addr = srv.address();
      const actualPort = addr && typeof addr !== "string" ? addr.port : port;
      resolve(actualPort);
    });
  });
}

export function stopDashboard(): Promise<void> {
  return new Promise((resolve) => {
    if (!server) {
      resolve();
      return;
    }
    const srv = server;
    server = null;
    srv.close(() => {
      resolve();
    });
  });
}
