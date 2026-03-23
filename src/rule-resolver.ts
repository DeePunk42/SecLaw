/**
 * Rule resolver: parses YAML rule files, expands lists and macros,
 * produces SigmaRule[] ready for compilation.
 */

import * as fs from "fs";
import * as path from "path";
import { parse as parseYaml } from "yaml";
import type { SigmaRule, DetectionBlock, RuleFile } from "./config.js";

/**
 * Load and resolve rules from a YAML file.
 * Returns { rules, lists } — lists are needed by the detection compiler.
 */
export function resolveRuleFile(filePath: string): {
  rules: SigmaRule[];
  lists: Map<string, string[]>;
} {
  try {
    const absPath = path.resolve(filePath);
    if (!fs.existsSync(absPath)) return { rules: [], lists: new Map() };
    const content = fs.readFileSync(absPath, "utf-8");
    return resolveRuleContent(content);
  } catch {
    return { rules: [], lists: new Map() };
  }
}

/**
 * Parse and resolve rule content from a YAML string.
 */
export function resolveRuleContent(yamlContent: string): {
  rules: SigmaRule[];
  lists: Map<string, string[]>;
} {
  const parsed = parseYaml(yamlContent);
  if (!parsed || typeof parsed !== "object") {
    return { rules: [], lists: new Map() };
  }

  // Handle both formats:
  // 1. { lists, macros, rules } — structured format
  // 2. Array of rules (legacy format)
  if (Array.isArray(parsed)) {
    // Legacy: plain array of rules
    return { rules: normalizeRules(parsed), lists: new Map() };
  }

  const ruleFile = parsed as RuleFile;
  const lists = new Map<string, string[]>();
  const macros = new Map<string, { detection: DetectionBlock }>();

  // Parse lists
  if (ruleFile.lists && typeof ruleFile.lists === "object") {
    for (const [name, values] of Object.entries(ruleFile.lists)) {
      if (Array.isArray(values)) {
        lists.set(name, values.map(String));
      }
    }
  }

  // Parse macros
  if (ruleFile.macros && typeof ruleFile.macros === "object") {
    for (const [name, def] of Object.entries(ruleFile.macros)) {
      if (def && typeof def === "object" && "detection" in def) {
        macros.set(name, def as { detection: DetectionBlock });
      }
    }
  }

  // Process rules
  const rules = normalizeRules(ruleFile.rules ?? []);

  // Expand $list: references in tool arrays
  for (const rule of rules) {
    rule.tool = expandListInArray(rule.tool, lists);
  }

  // Expand $list: references in detection values
  // (The actual $list: expansion in values is handled at compile time by detection-compiler)

  return { rules, lists };
}

/**
 * Merge resolved results from multiple rule files.
 */
export function mergeResolvedRules(
  ...results: Array<{ rules: SigmaRule[]; lists: Map<string, string[]> }>
): { rules: SigmaRule[]; lists: Map<string, string[]> } {
  const mergedLists = new Map<string, string[]>();
  const mergedRules: SigmaRule[] = [];

  for (const result of results) {
    for (const [name, values] of result.lists) {
      mergedLists.set(name, values);
    }
    mergedRules.push(...result.rules);
  }

  return { rules: mergedRules, lists: mergedLists };
}

// ─── Internal helpers ───

function normalizeRules(raw: unknown[]): SigmaRule[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((r): r is Record<string, unknown> => r != null && typeof r === "object")
    .map(normalizeRule)
    .filter((r): r is SigmaRule => r !== null);
}

function normalizeRule(raw: Record<string, unknown>): SigmaRule | null {
  const id = raw.id;
  const name = raw.name;
  const tier = raw.tier;
  const priority = raw.priority;

  if (typeof id !== "string" || typeof tier !== "string" || typeof priority !== "number") {
    return null;
  }

  // Normalize tool field (accept string, string[], or toolMatch for legacy)
  let tool: string[];
  if (Array.isArray(raw.tool)) {
    tool = raw.tool.map(String);
  } else if (typeof raw.tool === "string") {
    tool = [raw.tool];
  } else {
    return null;
  }

  // Normalize platform
  let platform: string[] | undefined;
  if (Array.isArray(raw.platform)) {
    platform = raw.platform.map(String);
  }

  // Normalize detection
  let detection: DetectionBlock;
  if (raw.detection && typeof raw.detection === "object") {
    detection = raw.detection as DetectionBlock;
  } else {
    // Default: unconditional match
    detection = { any: {}, condition: "any" };
  }

  return {
    id: String(id),
    name: typeof name === "string" ? name : String(id),
    tool,
    platform: platform as SigmaRule["platform"],
    tier: tier as SigmaRule["tier"],
    priority,
    reason: typeof raw.reason === "string" ? raw.reason : undefined,
    tags: Array.isArray(raw.tags) ? raw.tags.map(String) : undefined,
    detection,
  };
}

function expandListInArray(arr: string[], lists: Map<string, string[]>): string[] {
  const result: string[] = [];
  for (const item of arr) {
    if (item.startsWith("$list:")) {
      const listName = item.slice(6);
      const listValues = lists.get(listName);
      if (listValues) {
        result.push(...listValues);
      }
    } else {
      result.push(item);
    }
  }
  return result;
}
