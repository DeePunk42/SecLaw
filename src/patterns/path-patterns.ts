/**
 * File path sensitivity detection for security classification.
 */

import * as path from "path";

/** Glob-like patterns for sensitive file paths (write operations). */
const SENSITIVE_WRITE_PATTERNS = [
  /^~\/\.ssh\//,
  /^\/home\/[^/]+\/\.ssh\//,
  /^\/root\/\.ssh\//,
  /\/\.gitconfig$/,
  /^~\/\.gitconfig$/,
  /\/\.aws\//,
  /^~\/\.aws\//,
  /\/\.env$/,
  /\/\.env\./,
  /\/\.npmrc$/,
  /\/\.netrc$/,
  /\/\.docker\/config\.json$/,
  /\/\.kube\/config$/,
  /\/\.gnupg\//,
  /\/id_rsa$/,
  /\/id_ed25519$/,
  /\/authorized_keys$/,
  /\/known_hosts$/,
  /\/\.bash_history$/,
  /\/\.zsh_history$/,
  /\/etc\/passwd$/,
  /\/etc\/shadow$/,
  /\/etc\/sudoers/,
  /\/etc\/hosts$/,
  // Shell profiles — persistence attack vector
  /\/\.bashrc$/,
  /\/\.zshrc$/,
  /\/\.profile$/,
  /\/\.bash_profile$/,
  /\/\.zprofile$/,
];

/** Patterns for sensitive file reads (in command context). */
const SENSITIVE_READ_GLOBS = [
  /secret/i,
  /\.env$/,
  /\.env\./,
  /credential/i,
  /\.ssh\//,
  /private.*key/i,
  /id_rsa/,
  /id_ed25519/,
  /\.pem$/,
  /\.key$/,
  /token/i,
  /\.netrc$/,
  /\.npmrc$/,
];

/**
 * Normalize a file path for analysis.
 * Expands ~ to /home/<user> concept, resolves ../ etc.
 */
function normalizePath(filePath: string): string {
  let normalized = filePath.trim();
  // Keep ~ prefix for pattern matching
  if (!normalized.startsWith("~")) {
    normalized = path.normalize(normalized);
  }
  return normalized;
}

/**
 * Check if a file path is sensitive for write operations.
 */
export function isSensitiveWritePath(filePath: string): boolean {
  const normalized = normalizePath(filePath);
  return SENSITIVE_WRITE_PATTERNS.some((p) => p.test(normalized));
}

/**
 * Check if a file path is sensitive for read operations (command context).
 */
export function isSensitiveReadPath(filePath: string): boolean {
  const normalized = normalizePath(filePath);
  return SENSITIVE_READ_GLOBS.some((p) => p.test(normalized));
}

/**
 * Check if a file path matches any of the extra sensitive path patterns (from config).
 */
export function matchesExtraSensitivePaths(
  filePath: string,
  extraPatterns: string[],
): boolean {
  const normalized = normalizePath(filePath);
  return extraPatterns.some((pattern) => {
    try {
      return new RegExp(pattern).test(normalized);
    } catch {
      return false;
    }
  });
}

/**
 * Check if a path is within a given workspace directory.
 */
export function isPathInWorkspace(
  filePath: string,
  workspacePath: string | undefined,
): boolean {
  if (!workspacePath) return false;
  try {
    const resolved = filePath.startsWith("~")
      ? filePath // Can't resolve ~ without knowing home dir at runtime
      : path.resolve(filePath);
    const workspace = path.resolve(workspacePath);
    return resolved.startsWith(workspace + path.sep) || resolved === workspace;
  } catch {
    return false;
  }
}

/**
 * Extract file paths mentioned in a command string (best-effort).
 */
export function extractPathsFromCommand(command: string): string[] {
  const paths: string[] = [];
  // Match things that look like paths: start with /, ~/, or ./
  const pathRegex = /(?:^|\s)((?:\/|~\/|\.\/)\S+)/g;
  let match;
  while ((match = pathRegex.exec(command)) !== null) {
    paths.push(match[1]);
  }
  return paths;
}
