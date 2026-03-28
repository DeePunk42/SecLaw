/**
 * File path decomposition for the Sigma-style rule engine.
 *
 * Provides structural decomposition only:
 * - dir, name, ext from path
 * - inWorkspace (runtime-dependent, cannot be expressed statically in rules)
 *
 * Security judgments (which paths are "sensitive") belong in YAML rules.
 */

import * as nodePath from "path";
import type { FileDecomposition } from "../config.js";

/**
 * Decompose a file path into dir, name, ext, and inWorkspace.
 */
export function decomposePath(filePath: string, workspacePath?: string): FileDecomposition {
  const normalized = filePath.trim();
  const parsed = nodePath.parse(normalized);

  return {
    dir: parsed.dir || "",
    name: parsed.base || "",
    ext: parsed.ext || "",
    inWorkspace: isPathInWorkspace(normalized, workspacePath),
  };
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
      : nodePath.resolve(filePath);
    const workspace = nodePath.resolve(workspacePath);
    return resolved.startsWith(workspace + nodePath.sep) || resolved === workspace;
  } catch {
    return false;
  }
}

/**
 * Extract file paths mentioned in a command string (best-effort).
 */
export function extractPathsFromCommand(command: string): string[] {
  const paths: string[] = [];
  const pathRegex = /(?:^|\s)((?:\/|~\/|\.\/)\S+)/g;
  let match;
  while ((match = pathRegex.exec(command)) !== null) {
    paths.push(match[1]);
  }
  return paths;
}
