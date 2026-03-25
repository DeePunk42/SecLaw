/**
 * Script content audit — detects and audits script files that a command
 * will execute, using content-hash caching to avoid redundant LLM calls.
 */

import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import type { IntentContext, ScriptAuditConfig, AuditDecision } from "./config.js";
import type { LLMAuditor } from "./llm-auditor.js";
import type { AuditLog } from "./audit-log.js";
import { splitCommandChain } from "./patterns/command-patterns.js";

// ─── Types ───

export interface ScriptInfo {
  /** Absolute path (or synthetic key for inline scripts) */
  filePath: string;
  /** File content (or inline command text) */
  content: string;
  /** Human-readable description of why this file is being audited */
  source: string;
}

export interface ScriptAuditDetail {
  filePath: string;
  decision: AuditDecision;
  reason?: string;
  cached: boolean;
}

export interface ScriptAuditResult {
  block: boolean;
  blockReason?: string;
  details: ScriptAuditDetail[];
}

interface ScriptHashEntry {
  contentHash: string;
  decision: AuditDecision;
  reason?: string;
  auditedAt: number;
}

type HashCache = Record<string, ScriptHashEntry>;

// ─── Module state ───

let varDir = "";
let scriptAuditConfig: ScriptAuditConfig | undefined;
let hashCacheLoaded = false;
let hashCache: HashCache = {};
let auditLog: AuditLog | null = null;

// ─── Init ───

export function initScriptAudit(
  dir: string,
  config?: ScriptAuditConfig,
  log?: AuditLog,
): void {
  varDir = dir;
  scriptAuditConfig = config;
  auditLog = log ?? null;
  hashCacheLoaded = false;
  hashCache = {};
}

/** Reset module state (for testing). */
export function resetScriptAudit(): void {
  varDir = "";
  scriptAuditConfig = undefined;
  hashCacheLoaded = false;
  hashCache = {};
  auditLog = null;
}

// ─── Hash Cache I/O ───

function getCachePath(): string {
  return scriptAuditConfig?.hashCachePath || path.join(varDir, "script-hashes.json");
}

function loadHashCache(): void {
  if (hashCacheLoaded) return;
  hashCacheLoaded = true;
  try {
    const raw = fs.readFileSync(getCachePath(), "utf-8");
    hashCache = JSON.parse(raw);
  } catch {
    hashCache = {};
  }
}

function saveHashCache(): void {
  try {
    fs.writeFileSync(getCachePath(), JSON.stringify(hashCache, null, 2), "utf-8");
  } catch {
    // best-effort
  }
}

function computeSHA256(content: string): string {
  return crypto.createHash("sha256").update(content).digest("hex");
}

// ─── Script Detection ───

/** Interpreters and their typical script extensions */
const INTERPRETERS: Record<string, Set<string>> = {
  python: new Set([".py"]),
  python3: new Set([".py"]),
  node: new Set([".js", ".mjs", ".cjs", ".ts", ".mts"]),
  bash: new Set([".sh", ".bash"]),
  sh: new Set([".sh"]),
  zsh: new Set([".zsh", ".sh"]),
  ruby: new Set([".rb"]),
  perl: new Set([".pl"]),
  tsx: new Set([".ts", ".mts", ".tsx"]),
  "ts-node": new Set([".ts", ".mts"]),
  npx: new Set([".ts", ".js", ".mjs", ".cjs"]),
};

/** Flags that consume the next argument (inline code / module mode). */
const INLINE_FLAGS = new Set(["-c", "-e", "-m"]);

/** All auditable extensions. */
function getAuditableExtensions(): Set<string> {
  if (scriptAuditConfig?.extensions) {
    return new Set(scriptAuditConfig.extensions);
  }
  return new Set([".py", ".js", ".mjs", ".cjs", ".ts", ".mts", ".sh", ".bash", ".zsh", ".rb", ".pl"]);
}

/**
 * Detect scripts that a command will directly execute.
 * Returns script file paths resolved against the given cwd.
 */
export function detectDirectScripts(command: string, cwd: string): ScriptInfo[] {
  const segments = splitCommandChain(command);
  const scripts: ScriptInfo[] = [];
  const auditable = getAuditableExtensions();
  let effectiveCwd = cwd;

  for (const segment of segments) {
    const trimmed = segment.trim();
    if (!trimmed) continue;

    // Track cd for effective cwd
    const cdMatch = trimmed.match(/^cd\s+(.+)$/);
    if (cdMatch) {
      const dir = cdMatch[1].replace(/["']/g, "").trim();
      effectiveCwd = path.resolve(effectiveCwd, dir);
      continue;
    }

    const tokens = tokenize(trimmed);
    if (tokens.length === 0) continue;

    // Check for direct execution: ./script.sh or /path/to/script.py
    const first = tokens[0];
    if (first.startsWith("./") || first.startsWith("/")) {
      const ext = path.extname(first);
      if (auditable.has(ext)) {
        const resolved = path.resolve(effectiveCwd, first);
        scripts.push({ filePath: resolved, content: "", source: `direct execution: ${trimmed}` });
      }
      continue;
    }

    // Check for interpreter pattern
    const interpreterName = path.basename(first);
    const validExts = INTERPRETERS[interpreterName];
    if (!validExts) continue;

    // Skip flags, look for the script argument
    let foundInline = false;
    let scriptArg: string | null = null;
    for (let i = 1; i < tokens.length; i++) {
      const tok = tokens[i];
      if (INLINE_FLAGS.has(tok)) {
        foundInline = true;
        break;
      }
      // Skip flags (start with -)
      if (tok.startsWith("-")) continue;

      // npx special: first non-flag arg might be a package name, not a script
      // For npx tsx, we skip "tsx" and look for the next arg
      if (interpreterName === "npx" && i === 1) {
        // Check if this is a runner like tsx, ts-node
        if (tok === "tsx" || tok === "ts-node") continue;
        // Otherwise treat it as a script if it has an auditable extension
      }

      // First non-flag argument — is it a script?
      const ext = path.extname(tok);
      if (auditable.has(ext)) {
        scriptArg = tok;
      }
      break;
    }

    if (!foundInline && scriptArg) {
      const resolved = path.resolve(effectiveCwd, scriptArg);
      scripts.push({ filePath: resolved, content: "", source: `${interpreterName} execution: ${trimmed}` });
    }
  }

  return scripts;
}

/**
 * Simple shell tokenizer: splits on unquoted whitespace, strips quotes.
 */
function tokenize(cmd: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let inSingle = false;
  let inDouble = false;
  let escaped = false;

  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i];
    if (escaped) { current += ch; escaped = false; continue; }
    if (ch === "\\" && !inSingle) { escaped = true; continue; }
    if (ch === "'" && !inDouble) { inSingle = !inSingle; continue; }
    if (ch === '"' && !inSingle) { inDouble = !inDouble; continue; }
    if (!inSingle && !inDouble && /\s/.test(ch)) {
      if (current) { tokens.push(current); current = ""; }
      continue;
    }
    current += ch;
  }
  if (current) tokens.push(current);
  return tokens;
}

// ─── Package Manager Detection ───

interface LifecycleScripts {
  [name: string]: string;
}

/** npm/yarn/pnpm lifecycle script names for install-type commands. */
const INSTALL_LIFECYCLES = ["preinstall", "install", "postinstall", "prepare"];

/**
 * Detect scripts referenced by package manager lifecycle hooks.
 */
export function detectPackageManagerScripts(command: string, cwd: string): ScriptInfo[] {
  const segments = splitCommandChain(command);
  const scripts: ScriptInfo[] = [];
  let effectiveCwd = cwd;

  for (const segment of segments) {
    const trimmed = segment.trim();
    if (!trimmed) continue;

    const cdMatch = trimmed.match(/^cd\s+(.+)$/);
    if (cdMatch) {
      const dir = cdMatch[1].replace(/["']/g, "").trim();
      effectiveCwd = path.resolve(effectiveCwd, dir);
      continue;
    }

    const tokens = tokenize(trimmed);
    if (tokens.length === 0) continue;
    const cmd = tokens[0];

    // pip install . / pip install -e .
    if (cmd === "pip" || cmd === "pip3") {
      if (tokens.includes("install") && (tokens.includes(".") || tokens.includes("-e"))) {
        const setupPath = path.join(effectiveCwd, "setup.py");
        scripts.push({ filePath: setupPath, content: "", source: `pip install: ${trimmed}` });
      }
      continue;
    }

    // npm/yarn/pnpm
    if (cmd !== "npm" && cmd !== "yarn" && cmd !== "pnpm") continue;

    const subCmd = tokens[1] || "";
    let lifecycleNames: string[] = [];

    if (subCmd === "install" || subCmd === "ci" || (cmd === "yarn" && !subCmd) || (cmd === "pnpm" && subCmd === "install")) {
      lifecycleNames = INSTALL_LIFECYCLES;
    } else if (subCmd === "run" && tokens[2]) {
      const scriptName = tokens[2];
      lifecycleNames = [`pre${scriptName}`, scriptName, `post${scriptName}`];
    } else if (subCmd === "test") {
      lifecycleNames = ["pretest", "test", "posttest"];
    } else if (subCmd === "start") {
      lifecycleNames = ["prestart", "start", "poststart"];
    } else {
      continue;
    }

    const pkgPath = path.join(effectiveCwd, "package.json");
    let pkgScripts: LifecycleScripts = {};
    try {
      const raw = fs.readFileSync(pkgPath, "utf-8");
      const pkg = JSON.parse(raw);
      pkgScripts = pkg.scripts || {};
    } catch {
      continue;
    }

    for (const name of lifecycleNames) {
      const value = pkgScripts[name];
      if (!value) continue;

      // Try to extract referenced script files from the script value
      const referencedScripts = detectDirectScripts(value, effectiveCwd);
      for (const ref of referencedScripts) {
        ref.source = `package.json scripts.${name}: ${value}`;
        scripts.push(ref);
      }

      // If no script files found, audit the inline command as a virtual script
      if (referencedScripts.length === 0 && value.trim()) {
        scripts.push({
          filePath: `${pkgPath}::scripts.${name}`,
          content: value,
          source: `package.json scripts.${name} (inline)`,
        });
      }
    }
  }

  return scripts;
}

/**
 * Detect all scripts (direct + package manager) for a command.
 */
export function detectScripts(command: string, cwd: string): ScriptInfo[] {
  const direct = detectDirectScripts(command, cwd);
  const pkgManager = detectPackageManagerScripts(command, cwd);

  // Deduplicate by filePath
  const seen = new Set<string>();
  const result: ScriptInfo[] = [];
  for (const s of [...direct, ...pkgManager]) {
    if (seen.has(s.filePath)) continue;
    seen.add(s.filePath);
    result.push(s);
  }
  return result;
}

// ─── Audit Orchestration ───

/**
 * Audit detected scripts: read content, hash, check cache, LLM audit if needed.
 */
export async function auditScripts(
  scripts: ScriptInfo[],
  llmAuditor: LLMAuditor,
  sessionKey: string,
  intentCtx: IntentContext,
  triggerCommand: string,
  toolCallId?: string,
): Promise<ScriptAuditResult> {
  loadHashCache();

  const details: ScriptAuditDetail[] = [];
  const maxSize = scriptAuditConfig?.maxFileSizeBytes ?? 100_000;
  const dangerReasons: string[] = [];

  for (const script of scripts) {
    // Virtual scripts (inline commands) already have content
    const isVirtual = script.filePath.includes("::");

    if (!isVirtual) {
      // Read file content
      try {
        const stat = fs.statSync(script.filePath);
        if (stat.size > maxSize) {
          auditLog?.logScriptAuditSkipped(sessionKey, script.filePath, `file too large (${stat.size} bytes)`, toolCallId);
          continue;
        }
        script.content = fs.readFileSync(script.filePath, "utf-8");
      } catch (err: any) {
        if (err.code === "ENOENT") {
          auditLog?.logScriptAuditSkipped(sessionKey, script.filePath, "file not found", toolCallId);
        } else {
          auditLog?.logScriptAuditSkipped(sessionKey, script.filePath, `read error: ${err.message}`, toolCallId);
        }
        continue;
      }
    }

    if (!script.content) continue;

    // Compute hash and check cache
    const contentHash = computeSHA256(script.content);
    const cached = hashCache[script.filePath];

    if (cached && cached.contentHash === contentHash) {
      // Cache hit — skip LLM
      details.push({
        filePath: script.filePath,
        decision: cached.decision,
        reason: cached.reason,
        cached: true,
      });
      auditLog?.logScriptAudit(sessionKey, script.filePath, cached.decision, true, cached.reason, toolCallId);
      if (cached.decision === "DANGER") {
        dangerReasons.push(`${script.filePath}: ${cached.reason || "previously flagged as dangerous"}`);
      }
      continue;
    }

    // Cache miss — LLM audit
    const result = await llmAuditor.auditScriptWithTimeout({
      filePath: script.filePath,
      content: script.content,
      triggerCommand,
      intentContext: intentCtx,
      sessionKey,
    });

    // If it's a service error, skip caching but don't block
    if (result._errorInfo) {
      auditLog?.logScriptAuditSkipped(sessionKey, script.filePath, `LLM service error: ${result._errorInfo.message}`, toolCallId);
      // If fail_closed and this is an error result, treat as DANGER
      if (result.decision === "DANGER") {
        details.push({
          filePath: script.filePath,
          decision: "DANGER",
          reason: result.reason,
          cached: false,
        });
        dangerReasons.push(`${script.filePath}: ${result.reason || "LLM service error (fail_closed)"}`);
      }
      continue;
    }

    // Update cache
    hashCache[script.filePath] = {
      contentHash,
      decision: result.decision,
      reason: result.reason,
      auditedAt: Date.now(),
    };
    saveHashCache();

    details.push({
      filePath: script.filePath,
      decision: result.decision,
      reason: result.reason,
      cached: false,
    });
    auditLog?.logScriptAudit(sessionKey, script.filePath, result.decision, false, result.reason, toolCallId);

    if (result.decision === "DANGER") {
      dangerReasons.push(`${script.filePath}: ${result.reason || "flagged as dangerous"}`);
    }
  }

  if (dangerReasons.length > 0) {
    return {
      block: true,
      blockReason: `[SecLaw] Script audit: DANGER detected\n${dangerReasons.join("\n")}`,
      details,
    };
  }

  return { block: false, details };
}

// ─── Entry Point ───

/**
 * Main integration entry point for beforeToolCall.
 * Detects scripts, audits them, returns block decision.
 */
export async function checkScripts(
  command: string,
  cwd: string,
  llmAuditor: LLMAuditor,
  sessionKey: string,
  intentCtx: IntentContext,
  trusted: boolean,
  toolCallId?: string,
): Promise<ScriptAuditResult> {
  const scripts = detectScripts(command, cwd);
  if (scripts.length === 0) {
    return { block: false, details: [] };
  }

  return auditScripts(scripts, llmAuditor, sessionKey, intentCtx, command, toolCallId);
}
