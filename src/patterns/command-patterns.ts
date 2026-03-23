/**
 * Command parsing and decomposition for the Sigma-style rule engine.
 *
 * Provides structural decomposition of shell commands:
 * - splitCommandChain(): splits on |, &&, ||, ; (platform-aware)
 * - extractPrimaryCommand(): first command, skipping safe wrappers
 * - CommandDecomposition: { primary, all, segments }
 *
 * Security judgments (what is "dangerous", "sensitive") are NOT encoded here —
 * they belong in YAML rules.
 */

import type { Platform, CommandDecomposition } from "../config.js";

/**
 * Split a command string into chain segments by shell operators.
 * Respects quoting (single, double) and backslash escaping.
 */
export function splitCommandChain(cmd: string, platform: Platform = "linux"): string[] {
  const segments: string[] = [];
  let current = "";
  let inSingle = false;
  let inDouble = false;
  let escaped = false;
  let i = 0;

  while (i < cmd.length) {
    const ch = cmd[i];

    if (escaped) {
      current += ch;
      escaped = false;
      i++;
      continue;
    }
    if (ch === "\\" && !inSingle) {
      escaped = true;
      current += ch;
      i++;
      continue;
    }
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      current += ch;
      i++;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      current += ch;
      i++;
      continue;
    }

    // Only split outside quotes
    if (!inSingle && !inDouble) {
      // Check for || (all platforms)
      if (ch === "|" && i + 1 < cmd.length && cmd[i + 1] === "|") {
        const trimmed = current.trim();
        if (trimmed) segments.push(trimmed);
        current = "";
        i += 2;
        continue;
      }
      // Check for | (pipe, all platforms)
      if (ch === "|") {
        const trimmed = current.trim();
        if (trimmed) segments.push(trimmed);
        current = "";
        i++;
        continue;
      }
      // Check for && (all platforms)
      if (ch === "&" && i + 1 < cmd.length && cmd[i + 1] === "&") {
        const trimmed = current.trim();
        if (trimmed) segments.push(trimmed);
        current = "";
        i += 2;
        continue;
      }
      // Check for single & (Windows cmd.exe sequential execution)
      if (ch === "&" && platform === "windows") {
        const trimmed = current.trim();
        if (trimmed) segments.push(trimmed);
        current = "";
        i++;
        continue;
      }
      // Check for ; (all platforms — PowerShell uses it too)
      if (ch === ";") {
        const trimmed = current.trim();
        if (trimmed) segments.push(trimmed);
        current = "";
        i++;
        continue;
      }
    }

    current += ch;
    i++;
  }

  const trimmed = current.trim();
  if (trimmed) segments.push(trimmed);
  return segments;
}

/**
 * Extract the primary command from a shell command segment.
 * Skips safe wrappers (env, nohup, nice, etc.) but preserves sudo/su.
 * Strips leading env var assignments (VAR=val).
 */
export function extractPrimaryCommand(cmd: string): string | null {
  const trimmed = cmd.trim();
  if (!trimmed) return null;

  // Strip leading env vars like VAR=val
  let rest = trimmed.replace(/^(\w+=\S+\s+)+/, "");

  // Skip non-dangerous wrappers only (NOT sudo/su — those are security-relevant)
  const safeWrappers = ["nohup", "env", "nice", "ionice", "time", "strace"];
  const tokens = rest.split(/\s+/);
  let idx = 0;
  while (idx < tokens.length && safeWrappers.includes(tokens[idx])) {
    idx++;
    // skip flags
    while (idx < tokens.length && tokens[idx].startsWith("-")) {
      idx++;
    }
  }

  return idx < tokens.length ? tokens[idx] : null;
}

/**
 * Build a CommandDecomposition from a raw command string.
 */
export function decomposeCommand(command: string, platform: Platform = "linux"): CommandDecomposition {
  const segments = splitCommandChain(command, platform);
  const all: string[] = [];

  for (const seg of segments) {
    const cmd = extractPrimaryCommand(seg);
    if (cmd) all.push(cmd);
  }

  return {
    primary: all[0] ?? null,
    all,
    segments,
  };
}

/**
 * Check if a command starts with a given prefix (word boundary).
 */
export function commandStartsWith(command: string, prefix: string): boolean {
  const trimmed = command.trim();
  return trimmed === prefix || trimmed.startsWith(prefix + " ");
}

/**
 * Check if a command matches a regex pattern.
 */
export function commandMatchesPattern(command: string, pattern: string): boolean {
  try {
    return new RegExp(pattern).test(command);
  } catch {
    return false;
  }
}
