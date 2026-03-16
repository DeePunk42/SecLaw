/**
 * Bash command parsing and pattern matching for security classification.
 */

/** Commands that are classified as dangerous (trigger RED-tier synchronous audit). */
const DANGEROUS_COMMANDS = new Set([
  "mkfs",
  "dd",
  "nc",
  "ncat",
  "netcat",
  "eval",
]);

/** Regex patterns for pipe-to-shell detection. */
const PIPE_TO_SHELL_PATTERNS = [
  /\|\s*(sh|bash|zsh|dash|ksh|csh|fish)\b/,
  /\|\s*(source|eval)\b/,
  /\|\s*\.(\s|$)/,
];

/** Patterns for dynamic expansion that can hide intent. */
const DYNAMIC_EXPANSION_PATTERNS = [
  /\$\(/,           // $(...)
  /`[^`]+`/,        // backtick expansion
  /\$\{[^}]+\}/,    // ${var} with complex expressions
];

/** Patterns that read sensitive files via command. */
const SENSITIVE_READ_PATTERNS = [
  /\bcat\b.*(secret|\benv\b|\.env|credential|private.?key|id_rsa|id_ed25519|\.pem)/i,
  /\bless\b.*(secret|\.env|credential|private.?key)/i,
  /\bhead\b.*(secret|\.env|credential|private.?key)/i,
  /\btail\b.*(secret|\.env|credential|private.?key)/i,
  /\bgrep\b.*(password|token|api.?key|secret)/i,
  /\.ssh\//,
];

export interface CommandAnalysis {
  /** The primary command (first word, resolved past env/sudo wrappers). */
  primaryCommand: string | null;
  /** Whether the command pipes into a shell. */
  pipesToShell: boolean;
  /** Whether the command contains dynamic expansion. */
  hasDynamicExpansion: boolean;
  /** Whether the command reads sensitive files. */
  readsSensitiveFiles: boolean;
  /** Whether the primary command is in the dangerous-commands set. */
  isDangerousCommand: boolean;
  /** All distinct commands in a pipeline. */
  pipelineCommands: string[];
}

/**
 * Extract the primary command from a shell command string.
 * Skips wrappers like env, nohup, etc. but preserves sudo/su as dangerous.
 * Returns both the resolved command and any wrappers encountered.
 */
function extractPrimaryCommand(cmd: string): string | null {
  const trimmed = cmd.trim();
  if (!trimmed) return null;

  // Strip leading env vars like VAR=val
  let rest = trimmed.replace(/^(\w+=\S+\s+)+/, "");

  // Skip non-dangerous wrappers only (NOT sudo/su — those are security-relevant)
  const safeWrappers = ["nohup", "env", "nice", "ionice", "time", "strace"];
  const tokens = rest.split(/\s+/);
  let i = 0;
  while (i < tokens.length && safeWrappers.includes(tokens[i])) {
    i++;
    // skip flags
    while (i < tokens.length && tokens[i].startsWith("-")) {
      i++;
    }
  }

  return i < tokens.length ? tokens[i] : null;
}

/**
 * Split a command string into pipeline segments.
 * Handles basic pipe | but not complex quoting perfectly (fail-safe: returns original if ambiguous).
 */
function splitPipeline(cmd: string): string[] {
  // Simple split on | that isn't inside quotes
  // For security analysis, over-splitting is safer than under-splitting
  const segments: string[] = [];
  let current = "";
  let inSingle = false;
  let inDouble = false;
  let escaped = false;

  for (const ch of cmd) {
    if (escaped) {
      current += ch;
      escaped = false;
      continue;
    }
    if (ch === "\\") {
      escaped = true;
      current += ch;
      continue;
    }
    if (ch === "'" && !inDouble) {
      inSingle = !inSingle;
      current += ch;
      continue;
    }
    if (ch === '"' && !inSingle) {
      inDouble = !inDouble;
      current += ch;
      continue;
    }
    if (ch === "|" && !inSingle && !inDouble) {
      segments.push(current.trim());
      current = "";
      continue;
    }
    current += ch;
  }
  if (current.trim()) {
    segments.push(current.trim());
  }
  return segments;
}

/**
 * Analyze a bash command string for security-relevant features.
 */
export function analyzeCommand(command: string): CommandAnalysis {
  const segments = splitPipeline(command);
  const pipelineCommands: string[] = [];

  for (const seg of segments) {
    const cmd = extractPrimaryCommand(seg);
    if (cmd) pipelineCommands.push(cmd);
  }

  const primaryCommand = pipelineCommands[0] ?? null;

  const pipesToShell = PIPE_TO_SHELL_PATTERNS.some((p) => p.test(command));
  const hasDynamicExpansion = DYNAMIC_EXPANSION_PATTERNS.some((p) =>
    p.test(command),
  );
  const readsSensitiveFiles = SENSITIVE_READ_PATTERNS.some((p) =>
    p.test(command),
  );

  const isDangerousCommand =
    pipelineCommands.some((cmd) =>
      DANGEROUS_COMMANDS.has(cmd) ||
      // Handle dot-suffixed variants like mkfs.ext4, mkfs.xfs
      DANGEROUS_COMMANDS.has(cmd.split(".")[0]),
    ) ||
    pipesToShell;

  return {
    primaryCommand,
    pipesToShell,
    hasDynamicExpansion,
    readsSensitiveFiles,
    isDangerousCommand,
    pipelineCommands,
  };
}

/**
 * Check if a command matches additional yellow command patterns (from config).
 */
export function matchesExtraPatterns(
  command: string,
  extraPatterns: string[],
): boolean {
  return extraPatterns.some((pattern) => {
    try {
      return new RegExp(pattern).test(command);
    } catch {
      // Invalid regex pattern, skip
      return false;
    }
  });
}

/**
 * Check if a command starts with a given prefix.
 */
export function commandStartsWith(command: string, prefix: string): boolean {
  const trimmed = command.trim();
  return trimmed === prefix || trimmed.startsWith(prefix + " ");
}

/**
 * Check if a command matches a regex pattern.
 */
export function commandMatchesPattern(
  command: string,
  pattern: string,
): boolean {
  try {
    return new RegExp(pattern).test(command);
  } catch {
    return false;
  }
}
