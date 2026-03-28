/**
 * Command parsing and decomposition for the Sigma-style rule engine.
 *
 * Provides structural decomposition of shell commands:
 * - splitCommandChain(): splits on |, &&, ||, ; (platform-aware)
 * - extractPrimaryCommand(): first command, skipping safe wrappers
 * - decomposeCommand(): full decomposition with sh -c "..." unwrapping
 *
 * Security judgments (what is "dangerous", "sensitive") are NOT encoded here —
 * they belong in YAML rules.
 */

import type { Platform, CommandDecomposition } from "../config.js";

/** Shells whose -c argument should be recursively decomposed. */
const SHELL_NAMES = new Set(["sh", "bash", "zsh", "dash", "ksh", "csh", "fish"]);

/** Max recursion depth for nested shell -c invocations. */
const MAX_SHELL_C_DEPTH = 2;

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
 *
 * Recursively unwraps `sh -c "..."` / `bash -c "..."` invocations so that
 * inner commands appear in `cmd.all` and `cmd.segments`. This prevents
 * attackers from hiding dangerous commands inside quoted shell -c arguments.
 */
export function decomposeCommand(command: string, platform: Platform = "linux"): CommandDecomposition {
  const segments = splitCommandChain(command, platform);
  const all: string[] = [];
  const allSegments = [...segments];
  const innerScripts: string[] = [];

  for (const seg of segments) {
    const cmd = extractPrimaryCommand(seg);
    if (cmd) all.push(cmd);

    // Recursively decompose shell -c "..." invocations
    const innerScript = extractShellCScript(seg);
    if (innerScript) {
      innerScripts.push(innerScript);
      const inner = decomposeShellCInner(innerScript, platform, 1);
      all.push(...inner.all);
      allSegments.push(...inner.segments);
      innerScripts.push(...inner.innerScripts);
    }
  }

  // script = full command + all unwrapped inner scripts (for regex matching)
  const scriptParts = [command, ...innerScripts];
  const script = scriptParts.join(" && ");

  return {
    primary: all[0] ?? null,
    all,
    segments: allSegments,
    script,
  };
}

// ─── shell -c unwrapping ───

/**
 * If a command segment is a `shell -c <script>` invocation, extract the inner script.
 *
 * Detects patterns:
 *   sh -c "cmd1 && cmd2"
 *   bash -c 'cmd1 && cmd2'
 *   bash -xc "cmd"            (combined flags, -c must be last)
 *   env sh -c "cmd"           (safe wrappers are transparent)
 *   sudo bash -c "cmd"        (sudo is transparent for this purpose)
 *
 * Returns null if the segment is not a shell -c pattern.
 */
function extractShellCScript(segment: string): string | null {
  // Match: word-boundary shell-name, then flags, then -c (or -<letters>c),
  // then the script argument.
  //
  // -c must be the LAST letter in combined flags because it consumes the
  // next argument (e.g. -xc is valid, -cx is NOT — 'x' would be taken
  // as the script).
  const match = segment.match(
    /\b(sh|bash|zsh|dash|ksh|csh|fish)\s+(?:-[a-zA-Z]*c)\s+([\s\S]+)$/,
  );
  if (!match) return null;

  const rawArg = match[2].trim();
  if (!rawArg) return null;

  // Extract the first shell argument (respecting quotes)
  return extractFirstShellArg(rawArg);
}

/**
 * Extract the first shell argument from a string, respecting quoting.
 *
 *   "cmd1 && cmd2"   → cmd1 && cmd2       (strip double quotes)
 *   'cmd1 && cmd2'   → cmd1 && cmd2       (strip single quotes)
 *   cmd              → cmd                (unquoted single word)
 */
function extractFirstShellArg(str: string): string | null {
  const s = str.trim();
  if (!s) return null;

  // Double-quoted argument
  if (s[0] === '"') {
    let i = 1;
    let escaped = false;
    while (i < s.length) {
      if (escaped) { escaped = false; i++; continue; }
      if (s[i] === "\\") { escaped = true; i++; continue; }
      if (s[i] === '"') return s.slice(1, i) || null;
      i++;
    }
    // Unmatched quote — take everything after the opening quote
    return s.slice(1) || null;
  }

  // Single-quoted argument (no escape processing in single quotes)
  if (s[0] === "'") {
    const end = s.indexOf("'", 1);
    if (end >= 0) return s.slice(1, end) || null;
    return s.slice(1) || null;
  }

  // Unquoted: take until whitespace
  const end = s.search(/\s/);
  return end >= 0 ? s.slice(0, end) : s;
}

/**
 * Recursively decompose the inner script of a shell -c invocation.
 */
function decomposeShellCInner(
  script: string,
  platform: Platform,
  depth: number,
): { all: string[]; segments: string[]; innerScripts: string[] } {
  if (depth > MAX_SHELL_C_DEPTH) return { all: [], segments: [], innerScripts: [] };

  const segs = splitCommandChain(script, platform);
  const all: string[] = [];
  const allSegs = [...segs];
  const innerScripts: string[] = [];

  for (const seg of segs) {
    const cmd = extractPrimaryCommand(seg);
    if (cmd) all.push(cmd);

    // Recurse into nested shell -c
    const nested = extractShellCScript(seg);
    if (nested) {
      innerScripts.push(nested);
      const inner = decomposeShellCInner(nested, platform, depth + 1);
      all.push(...inner.all);
      allSegs.push(...inner.segments);
      innerScripts.push(...inner.innerScripts);
    }
  }

  return { all, segments: allSegs, innerScripts };
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
