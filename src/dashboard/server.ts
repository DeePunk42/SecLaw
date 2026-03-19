/**
 * Dashboard HTTP server — lifecycle management and request routing.
 * Uses node:http with zero external dependencies.
 */

import * as http from "node:http";
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
}

let server: http.Server | null = null;
let cachedHtml: string | null = null;

/**
 * Start the dashboard HTTP server.
 * Resolves with the actual port (useful when port=0 for OS-assigned port).
 */
export function startDashboard(
  dashboardConfig: DashboardConfig,
  deps: DashboardDeps,
): Promise<number> {
  if (server) {
    const addr = server.address();
    const port = addr && typeof addr !== "string" ? addr.port : dashboardConfig.port;
    return Promise.resolve(port);
  }

  const { host, port } = dashboardConfig;

  return new Promise((resolve, reject) => {
    const srv = http.createServer((req, res) => {
      // CORS headers for local development
      res.setHeader("Access-Control-Allow-Origin", "*");
      res.setHeader("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type");

      if (req.method === "OPTIONS") {
        res.writeHead(204);
        res.end();
        return;
      }

      const actualAddr = srv.address();
      const actualPort = actualAddr && typeof actualAddr !== "string" ? actualAddr.port : port;
      const url = new URL(req.url || "/", `http://${host}:${actualPort}`);

      // API routes
      if (url.pathname.startsWith("/api/")) {
        handleApiRequest(req, res, url, deps);
        return;
      }

      // Serve embedded HTML for all other routes (SPA)
      if (!cachedHtml) {
        cachedHtml = getDashboardHtml();
      }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(cachedHtml);
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
    cachedHtml = null;
    const srv = server;
    server = null;
    srv.close(() => {
      resolve();
    });
  });
}
