/**
 * Rule engine: loads YAML rules and matches tool calls against them.
 * Rules are evaluated in priority-descending order; first match wins.
 * Returns a tier (GREEN or YELLOW) — default is GREEN when no rule matches.
 */

import * as fs from "fs";
import * as path from "path";
import { parse as parseYaml } from "yaml";
import type { Rule, RuleCondition, RuleResult, IntentContext } from "./config.js";
import { analyzeCommand, commandMatchesPattern, commandStartsWith } from "./patterns/command-patterns.js";
import { isPathInWorkspace, extractPathsFromCommand, isSensitiveWritePath } from "./patterns/path-patterns.js";
import { analyzeURL } from "./patterns/url-patterns.js";

export class RuleEngine {
  private rules: Rule[] = [];

  constructor() {}

  /**
   * Load rules from multiple sources, merge and sort by priority descending.
   */
  loadRules(options: {
    defaultRulesPath?: string;
    workspaceRulesPath?: string;
    extraRules?: Rule[];
  }): void {
    const allRules: Rule[] = [];

    // 1. Built-in defaults
    if (options.defaultRulesPath) {
      const defaults = this.loadYamlRules(options.defaultRulesPath);
      allRules.push(...defaults);
    }

    // 2. Workspace overrides
    if (options.workspaceRulesPath) {
      const workspace = this.loadYamlRules(options.workspaceRulesPath);
      allRules.push(...workspace);
    }

    // 3. Inline extra rules from config
    if (options.extraRules) {
      allRules.push(...options.extraRules);
    }

    // Sort by priority descending (highest first)
    this.rules = allRules.sort((a, b) => b.priority - a.priority);
  }

  /**
   * Load rules directly (for testing or programmatic use).
   */
  setRules(rules: Rule[]): void {
    this.rules = [...rules].sort((a, b) => b.priority - a.priority);
  }

  /**
   * Classify a tool call against loaded rules.
   * Returns { tier, ruleId?, reason? }. Default: { tier: "GREEN" }.
   */
  classify(
    toolName: string,
    params: Record<string, unknown>,
    intentContext: IntentContext,
    workspacePath?: string,
  ): RuleResult {
    for (const rule of this.rules) {
      if (!this.toolMatches(toolName, rule.toolMatch)) continue;
      if (this.allConditionsMatch(rule.conditions, toolName, params, workspacePath)) {
        return {
          tier: rule.tier,
          ruleId: rule.id,
          reason: rule.reason,
        };
      }
    }

    // No rule matched — default GREEN (allow + async audit)
    return { tier: "GREEN" };
  }

  /**
   * Get all loaded rules (for debugging/inspection).
   */
  getRules(): readonly Rule[] {
    return this.rules;
  }

  // ─── Private helpers ───

  private loadYamlRules(filePath: string): Rule[] {
    try {
      const absPath = path.resolve(filePath);
      if (!fs.existsSync(absPath)) return [];
      const content = fs.readFileSync(absPath, "utf-8");
      const parsed = parseYaml(content);
      if (!Array.isArray(parsed)) return [];
      return parsed as Rule[];
    } catch {
      return [];
    }
  }

  private toolMatches(toolName: string, toolMatch: string[]): boolean {
    return toolMatch.includes(toolName) || toolMatch.includes("*");
  }

  private allConditionsMatch(
    conditions: RuleCondition[],
    toolName: string,
    params: Record<string, unknown>,
    workspacePath?: string,
  ): boolean {
    // Empty conditions array → unconditional match (tool-level rules)
    if (conditions.length === 0) return true;
    return conditions.every((cond) =>
      this.conditionMatches(cond, toolName, params, workspacePath),
    );
  }

  private conditionMatches(
    condition: RuleCondition,
    toolName: string,
    params: Record<string, unknown>,
    workspacePath?: string,
  ): boolean {
    const command = typeof params.command === "string" ? params.command : "";
    const filePath = typeof params.path === "string" ? params.path : "";

    switch (condition.type) {
      case "command_matches":
        return condition.pattern
          ? commandMatchesPattern(command, condition.pattern)
          : false;

      case "command_starts_with":
        return condition.prefix
          ? commandStartsWith(command, condition.prefix)
          : false;

      case "pipe_to_shell": {
        const analysis = analyzeCommand(command);
        return condition.value === true
          ? analysis.pipesToShell
          : !analysis.pipesToShell;
      }

      case "has_dynamic_expansion": {
        const cmdAnalysis = analyzeCommand(command);
        return condition.value === true
          ? cmdAnalysis.hasDynamicExpansion
          : !cmdAnalysis.hasDynamicExpansion;
      }

      case "is_yellow_command": {
        const cmdAnalysis = analyzeCommand(command);
        return condition.value === true
          ? cmdAnalysis.isYellowCommand
          : !cmdAnalysis.isYellowCommand;
      }

      case "reads_sensitive_files": {
        const cmdAnalysis = analyzeCommand(command);
        return condition.value === true
          ? cmdAnalysis.readsSensitiveFiles
          : !cmdAnalysis.readsSensitiveFiles;
      }

      case "is_sensitive_write_path": {
        return condition.value === true
          ? isSensitiveWritePath(filePath)
          : !isSensitiveWritePath(filePath);
      }

      case "path_in_workspace": {
        // For exec/bash, extract paths from command and check all are in workspace
        if (toolName === "exec" || toolName === "bash") {
          const paths = extractPathsFromCommand(command);
          if (paths.length === 0) return condition.value === true;
          const allInWorkspace = paths.every((p) =>
            isPathInWorkspace(p, workspacePath),
          );
          return condition.value === true
            ? allInWorkspace
            : !allInWorkspace;
        }
        // For fs_write/fs_delete/fs_move, check the path param
        return condition.value === true
          ? isPathInWorkspace(filePath, workspacePath)
          : !isPathInWorkspace(filePath, workspacePath);
      }

      case "path_matches":
        return condition.pattern
          ? commandMatchesPattern(filePath || command, condition.pattern)
          : false;

      case "url_is_internal": {
        const url = typeof params.url === "string" ? params.url : "";
        const urlAnalysis = analyzeURL(url);
        return condition.value === true
          ? urlAnalysis.isInternal
          : !urlAnalysis.isInternal;
      }

      case "url_is_metadata": {
        const url = typeof params.url === "string" ? params.url : "";
        const urlAnalysis = analyzeURL(url);
        return condition.value === true
          ? urlAnalysis.isMetadataEndpoint
          : !urlAnalysis.isMetadataEndpoint;
      }

      case "url_is_credential": {
        const url = typeof params.url === "string" ? params.url : "";
        const urlAnalysis = analyzeURL(url);
        return condition.value === true
          ? urlAnalysis.isCredentialEndpoint
          : !urlAnalysis.isCredentialEndpoint;
      }

      default:
        // Unknown condition type — fail-safe: condition doesn't match
        return false;
    }
  }
}
