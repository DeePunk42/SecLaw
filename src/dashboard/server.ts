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
  getToken?: () => string | string[] | undefined;
  getPassword?: () => string | undefined;
  reloadRules?: () => void;
}

function verifyToken(provided: string | undefined, expected: string): boolean {
  if (typeof provided !== "string" || provided.length === 0) return false;
  const hash = (s: string) => createHash("sha256").update(s).digest();
  return timingSafeEqual(hash(provided), hash(expected));
}

// ─── Cookie session store ───

const COOKIE_NAME = "seclaw_pw";
const COOKIE_MAX_AGE = 30 * 24 * 3600; // 30 days

function parseCookie(req: http.IncomingMessage, name: string): string | undefined {
  const header = req.headers.cookie;
  if (!header) return undefined;
  const prefix = name + "=";
  for (const part of header.split(";")) {
    const trimmed = part.trim();
    if (trimmed.startsWith(prefix)) {
      try {
        return decodeURIComponent(trimmed.slice(prefix.length));
      } catch {
        return trimmed.slice(prefix.length);
      }
    }
  }
  return undefined;
}

function setPasswordCookie(res: http.ServerResponse, password: string, cookiePath: string): void {
  const encoded = encodeURIComponent(password);
  const p = cookiePath || "/";
  res.setHeader("Set-Cookie", `${COOKIE_NAME}=${encoded}; HttpOnly; SameSite=Strict; Path=${p}; Max-Age=${COOKIE_MAX_AGE}`);
}

// ─── Auth helpers ───

function isAuthorized(
  req: http.IncomingMessage,
  deps: DashboardDeps,
): boolean {
  const rawTokens = deps.getToken?.();
  const password = deps.getPassword?.();

  // No auth configured — open access
  if (!rawTokens && !password) return true;

  // Extract Bearer / query token
  const authHeader = req.headers.authorization;
  const bearerToken = authHeader?.startsWith("Bearer ")
    ? authHeader.slice(7).trim()
    : undefined;
  // Parse URL for query token
  const rawUrl = req.url || "/";
  const url = new URL(rawUrl, "http://127.0.0.1");
  const queryToken = url.searchParams.get("token") || undefined;
  const provided = bearerToken || queryToken;

  // Check Bearer/query token against configured tokens
  if (rawTokens && provided) {
    const validTokens = Array.isArray(rawTokens) ? rawTokens : [rawTokens];
    if (validTokens.some((t) => verifyToken(provided, t))) return true;
  }

  // Check password cookie
  if (password) {
    const cookiePw = parseCookie(req, COOKIE_NAME);
    if (cookiePw && verifyToken(cookiePw, password)) return true;
  }

  return false;
}

// ─── Route handler ───

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

    // POST /api/auth — password login endpoint (sets cookie)
    if (url.pathname === "/api/auth" && req.method === "POST") {
      const password = deps.getPassword?.();
      if (!password) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, message: "No password configured" }));
        return true;
      }
      const body = await new Promise<string>((resolve) => {
        const chunks: Buffer[] = [];
        req.on("data", (c: Buffer) => chunks.push(c));
        req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
      });
      let provided: string | undefined;
      try {
        provided = JSON.parse(body)?.password?.trim();
      } catch { /* invalid JSON */ }
      if (!provided || !verifyToken(provided, password)) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: { message: "Invalid password", type: "unauthorized" } }));
        return true;
      }
      setPasswordCookie(res, provided, basePath);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return true;
    }

    // API routes — require auth
    if (url.pathname.startsWith("/api/")) {
      if (!isAuthorized(req, deps)) {
        res.writeHead(401, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: { message: "Unauthorized", type: "unauthorized" } }));
        return true;
      }
      url.searchParams.delete("token");
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
