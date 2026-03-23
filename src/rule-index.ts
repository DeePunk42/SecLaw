/**
 * RuleIndex: indexes compiled rules by tool name and platform
 * for fast candidate selection during classify().
 */

import type { CompiledRule, Platform } from "./config.js";

export class RuleIndex {
  /** tool → rules sorted by priority descending */
  private toolIndex = new Map<string, CompiledRule[]>();
  /** rules that match all tools (no filtering) */
  private wildcardRules: CompiledRule[] = [];
  private allRules: CompiledRule[] = [];

  constructor(rules: CompiledRule[]) {
    this.allRules = [...rules].sort((a, b) => b.priority - a.priority);
    this.buildIndex();
  }

  /**
   * Get candidate rules for a given tool name and platform.
   * Returns rules sorted by priority descending.
   */
  getCandidates(toolName: string, platform: Platform): CompiledRule[] {
    const toolRules = this.toolIndex.get(toolName) ?? [];
    // Merge tool-specific + wildcard rules, already sorted by priority
    const candidates = mergeSorted(toolRules, this.wildcardRules);
    // Filter by platform
    return candidates.filter((rule) => {
      if (!rule.platform || rule.platform.length === 0) return true;
      return rule.platform.includes(platform);
    });
  }

  /**
   * Get all rules (for debugging/API).
   */
  getAllRules(): readonly CompiledRule[] {
    return this.allRules;
  }

  private buildIndex(): void {
    for (const rule of this.allRules) {
      if (rule.tool.includes("*")) {
        this.wildcardRules.push(rule);
        continue;
      }
      for (const tool of rule.tool) {
        const existing = this.toolIndex.get(tool);
        if (existing) {
          existing.push(rule);
        } else {
          this.toolIndex.set(tool, [rule]);
        }
      }
    }

    // Sort each tool's rules by priority descending
    for (const rules of this.toolIndex.values()) {
      rules.sort((a, b) => b.priority - a.priority);
    }
    this.wildcardRules.sort((a, b) => b.priority - a.priority);
  }
}

/**
 * Merge two sorted-by-priority-descending arrays into one.
 */
function mergeSorted(a: CompiledRule[], b: CompiledRule[]): CompiledRule[] {
  const result: CompiledRule[] = [];
  let i = 0, j = 0;
  while (i < a.length && j < b.length) {
    if (a[i].priority >= b[j].priority) {
      result.push(a[i++]);
    } else {
      result.push(b[j++]);
    }
  }
  while (i < a.length) result.push(a[i++]);
  while (j < b.length) result.push(b[j++]);
  return result;
}
