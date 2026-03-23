/**
 * Sigma-style rule engine.
 *
 * Loads YAML rules, compiles detections, indexes by tool/platform,
 * and classifies tool calls. External API is compatible with the
 * previous engine: classify(toolName, params, intentCtx, workspacePath).
 */

import * as os from "os";
import type {
  SigmaRule,
  CompiledRule,
  MatchContext,
  Platform,
  RuleResult,
  IntentContext,
  PreClassifyHook,
} from "./config.js";
import { FieldRegistry, createDefaultFieldRegistry } from "./field-registry.js";
import { compileDetection } from "./detection-compiler.js";
import { resolveRuleFile, mergeResolvedRules } from "./rule-resolver.js";
import { RuleIndex } from "./rule-index.js";
import { decomposeCommand } from "./patterns/command-patterns.js";
import { decomposePath, isPathInWorkspace, extractPathsFromCommand } from "./patterns/path-patterns.js";
import { decomposeURL } from "./patterns/url-patterns.js";

export class RuleEngine {
  private index: RuleIndex = new RuleIndex([]);
  private fieldRegistry: FieldRegistry;
  private lists = new Map<string, string[]>();
  private platform: Platform;
  private preClassifyHooks: PreClassifyHook[] = [];

  constructor(platform?: Platform) {
    this.platform = platform ?? detectPlatform();
    this.fieldRegistry = createDefaultFieldRegistry();
  }

  /**
   * Load rules from multiple sources, merge and compile.
   */
  loadRules(options: {
    defaultRulesPath?: string;
    workspaceRulesPath?: string;
    extraRulePaths?: string[];
    extraRules?: SigmaRule[];
  }): void {
    const results: Array<{ rules: SigmaRule[]; lists: Map<string, string[]> }> = [];

    if (options.defaultRulesPath) {
      results.push(resolveRuleFile(options.defaultRulesPath));
    }

    if (options.extraRulePaths) {
      for (const p of options.extraRulePaths) {
        results.push(resolveRuleFile(p));
      }
    }

    if (options.workspaceRulesPath) {
      results.push(resolveRuleFile(options.workspaceRulesPath));
    }

    const merged = results.length > 0
      ? mergeResolvedRules(...results)
      : { rules: [], lists: new Map<string, string[]>() };

    // Add inline extra rules
    if (options.extraRules) {
      merged.rules.push(...options.extraRules);
    }

    this.lists = merged.lists;
    this.index = new RuleIndex(this.compileRules(merged.rules));
  }

  /**
   * Load rules directly (for testing or programmatic use).
   */
  setRules(rules: SigmaRule[], lists?: Map<string, string[]>): void {
    this.lists = lists ?? new Map();
    this.index = new RuleIndex(this.compileRules(rules));
  }

  /**
   * Classify a tool call against loaded rules.
   * Returns { tier, ruleId?, reason? }. Default: { tier: "YELLOW" }.
   */
  classify(
    toolName: string,
    params: Record<string, unknown>,
    _intentContext: IntentContext,
    workspacePath?: string,
  ): RuleResult {
    const ctx = this.buildContext(toolName, params, workspacePath);
    const candidates = this.index.getCandidates(toolName, this.platform);

    for (const rule of candidates) {
      if (rule.matcher(ctx)) {
        return {
          tier: rule.tier,
          ruleId: rule.id,
          reason: rule.reason,
        };
      }
    }

    return { tier: "YELLOW" };
  }

  /**
   * Register a pre-classify hook.
   */
  registerPreClassifyHook(hook: PreClassifyHook): void {
    this.preClassifyHooks.push(hook);
  }

  /**
   * Get all loaded rules (for debugging/inspection).
   */
  getRules(): readonly CompiledRule[] {
    return this.index.getAllRules();
  }

  /**
   * Get the field registry (for extension point registration).
   */
  getFieldRegistry(): FieldRegistry {
    return this.fieldRegistry;
  }

  /**
   * Get the current platform.
   */
  getPlatform(): Platform {
    return this.platform;
  }

  /**
   * Set the platform (for testing).
   */
  setPlatform(platform: Platform): void {
    this.platform = platform;
  }

  // ─── Private ───

  private compileRules(sigmaRules: SigmaRule[]): CompiledRule[] {
    return sigmaRules.map((rule): CompiledRule => ({
      id: rule.id,
      name: rule.name,
      tool: rule.tool,
      platform: rule.platform,
      tier: rule.tier,
      priority: rule.priority,
      reason: rule.reason,
      tags: rule.tags,
      matcher: compileDetection(rule.detection, this.fieldRegistry, this.lists),
    }));
  }

  private buildContext(
    toolName: string,
    params: Record<string, unknown>,
    workspacePath?: string,
  ): MatchContext {
    const command = typeof params.command === "string" ? params.command : undefined;
    const filePath = typeof params.path === "string" ? params.path : undefined;
    const url = typeof params.url === "string" ? params.url : undefined;

    const ctx: MatchContext = {
      tool: toolName,
      params,
      platform: this.platform,
      workspacePath,
      ext: {},

      // Raw param shortcuts
      command,
      path: filePath,
      url,
      action: typeof params.action === "string" ? params.action : undefined,
      host: typeof params.host === "string" ? params.host : undefined,
      elevated: typeof params.elevated === "boolean" ? params.elevated : undefined,
      content: typeof params.content === "string" ? params.content : undefined,
      query: typeof params.query === "string" ? params.query : undefined,
    };

    // Lazy decomposition: only compute when the tool has relevant params
    if (command !== undefined) {
      ctx.cmd = decomposeCommand(command, this.platform);
    }

    if (filePath !== undefined) {
      ctx.file = decomposePath(filePath, workspacePath);
    } else if (command !== undefined && toolName === "exec") {
      // For exec tool, also check paths in command for file.inWorkspace
      const paths = extractPathsFromCommand(command);
      if (paths.length > 0) {
        const allInWorkspace = paths.every((p) => isPathInWorkspace(p, workspacePath));
        ctx.file = {
          dir: "",
          name: "",
          ext: "",
          inWorkspace: allInWorkspace,
        };
      }
    }

    if (url !== undefined) {
      ctx.urlParsed = decomposeURL(url);
    }

    return ctx;
  }
}

/**
 * Detect the current platform.
 */
export function detectPlatform(): Platform {
  const p = os.platform();
  if (p === "darwin") return "macos";
  if (p === "win32") return "windows";
  return "linux";
}
