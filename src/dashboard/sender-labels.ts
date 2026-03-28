/**
 * Sender Labels persistence and log extraction.
 * Persists the registry at <varDir>/sender-labels.json (plugin-local storage).
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as readline from "node:readline";
import type { AuditLog } from "../audit-log.js";
import { sessionState } from "../session-state.js";

export interface SenderLabelsData {
  labels: string[];
  lastRefreshed: string;
}

const SENDER_LABELS_FILE = "sender-labels.json";
const AUDIT_LOG_PATH = ".openclaw/logs/seclaw-audit.jsonl";

function getSenderLabelsPath(varDir: string): string {
  return path.join(varDir, SENDER_LABELS_FILE);
}

/**
 * Read persisted sender labels from varDir. Returns empty data if file doesn't exist.
 */
export function readSenderLabels(varDir: string): SenderLabelsData {
  const filePath = getSenderLabelsPath(varDir);
  try {
    const raw = fs.readFileSync(filePath, "utf-8");
    const data = JSON.parse(raw) as SenderLabelsData;
    return {
      labels: Array.isArray(data.labels) ? data.labels : [],
      lastRefreshed: data.lastRefreshed || "",
    };
  } catch {
    return { labels: [], lastRefreshed: "" };
  }
}

/**
 * Scan sessions, ring buffer, and audit log for sender labels, merge with
 * persisted ones, and write the updated set to varDir/sender-labels.json.
 *
 * @param varDir        Plugin var directory for persistent storage (always available)
 * @param auditLog      In-memory audit log (ring buffer)
 * @param workspacePath Workspace directory (optional, used only to scan JSONL audit log)
 */
export async function refreshSenderLabels(
  varDir: string,
  auditLog: AuditLog,
  workspacePath?: string,
): Promise<SenderLabelsData> {
  const labels = new Set<string>();

  // 1. Merge existing persisted labels
  const existing = readSenderLabels(varDir);
  for (const l of existing.labels) {
    labels.add(l);
  }

  // 2. Scan active sessions for current sender labels
  for (const label of sessionState.getAllSenderLabels()) {
    labels.add(label);
  }

  // 3. Scan in-memory ring buffer
  const entries = auditLog.getRecentEntries();
  for (const entry of entries) {
    if (entry.eventType === "intent_context") {
      const ctx = entry.intentContext as Record<string, unknown> | undefined;
      const senderLabel = ctx?.senderLabel;
      if (typeof senderLabel === "string" && senderLabel.length > 0) {
        labels.add(senderLabel);
      }
    }
  }

  // 4. Scan JSONL audit log file (workspace-based, optional)
  if (workspacePath) {
    const jsonlPath = path.join(workspacePath, AUDIT_LOG_PATH);
    try {
      if (fs.existsSync(jsonlPath)) {
        await scanJsonlFile(jsonlPath, labels);
      }
    } catch {
      // Best-effort — file may not exist or be unreadable
    }
  }

  // Write sorted, deduplicated labels to varDir
  const result: SenderLabelsData = {
    labels: [...labels].sort(),
    lastRefreshed: new Date().toISOString(),
  };

  try {
    fs.mkdirSync(varDir, { recursive: true });
    fs.writeFileSync(getSenderLabelsPath(varDir), JSON.stringify(result, null, 2));
  } catch (err) {
    console.error("[seclaw] Failed to write sender-labels.json:", err);
  }

  return result;
}

/**
 * Seed sender-labels.json with default labels if the file doesn't exist.
 * Synchronous, best-effort — safe to call on every init.
 */
export function seedSenderLabels(varDir: string, defaultLabels: string[]): void {
  const filePath = getSenderLabelsPath(varDir);
  if (fs.existsSync(filePath)) return; // don't overwrite existing
  const data: SenderLabelsData = {
    labels: [...defaultLabels].sort(),
    lastRefreshed: new Date().toISOString(),
  };
  try {
    fs.mkdirSync(varDir, { recursive: true });
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
  } catch { /* best-effort */ }
}

/**
 * Stream-parse a JSONL file for sender labels.
 */
function scanJsonlFile(filePath: string, labels: Set<string>): Promise<void> {
  return new Promise((resolve, reject) => {
    const stream = fs.createReadStream(filePath, { encoding: "utf-8" });
    const rl = readline.createInterface({ input: stream, crlfDelay: Infinity });

    rl.on("line", (line) => {
      try {
        const entry = JSON.parse(line);
        if (entry.eventType === "intent_context") {
          const senderLabel = entry.intentContext?.senderLabel;
          if (typeof senderLabel === "string" && senderLabel.length > 0) {
            labels.add(senderLabel);
          }
        }
      } catch {
        // Skip malformed lines
      }
    });

    rl.on("close", resolve);
    rl.on("error", reject);
  });
}
