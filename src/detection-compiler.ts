/**
 * Detection compiler: parses Sigma-style detection blocks into matcher functions.
 *
 * Supports:
 * - Field modifiers: |re, |contains, |startswith, |endswith, |all
 * - Selection logic: multiple fields = AND, multiple values = OR
 * - Condition expressions: and, or, not, 1 of sel_*, all of sel_*
 * - Array field matching: any element matches = true
 */

import type { DetectionBlock, MatchContext } from "./config.js";
import type { FieldRegistry } from "./field-registry.js";

/** A compiled matcher function */
export type MatcherFn = (ctx: MatchContext) => boolean;

/**
 * Compile a detection block into a single matcher function.
 */
export function compileDetection(
  detection: DetectionBlock,
  fieldRegistry: FieldRegistry,
  lists: Map<string, string[]>,
): MatcherFn {
  // Extract the condition string
  const condition = detection.condition;
  if (typeof condition !== "string") {
    return () => false;
  }

  // Extract named selections (everything except "condition")
  const selections = new Map<string, MatcherFn>();
  for (const [name, fields] of Object.entries(detection)) {
    if (name === "condition") continue;
    if (typeof fields === "string") continue; // skip if it's somehow a string
    selections.set(name, compileSelection(fields as Record<string, unknown>, fieldRegistry, lists));
  }

  // Parse and compile the condition expression
  return compileCondition(condition, selections);
}

/**
 * Compile a selection (field → value mappings) into a matcher.
 * Multiple fields within one selection = AND.
 */
function compileSelection(
  fields: Record<string, unknown>,
  fieldRegistry: FieldRegistry,
  lists: Map<string, string[]>,
): MatcherFn {
  // Empty selection = unconditional match
  if (Object.keys(fields).length === 0) {
    return () => true;
  }

  const fieldMatchers: MatcherFn[] = [];

  for (const [rawKey, rawValue] of Object.entries(fields)) {
    const { fieldPath, modifier } = parseFieldKey(rawKey);
    const values = resolveValues(rawValue, lists);
    fieldMatchers.push(compileFieldMatcher(fieldPath, modifier, values, fieldRegistry));
  }

  // AND: all field matchers must match
  return (ctx) => fieldMatchers.every((fn) => fn(ctx));
}

/**
 * Parse a field key like "cmd.all|re" into { fieldPath: "cmd.all", modifier: "re" }.
 */
function parseFieldKey(key: string): { fieldPath: string; modifier: string } {
  const pipeIdx = key.indexOf("|");
  if (pipeIdx === -1) {
    return { fieldPath: key, modifier: "" };
  }
  return {
    fieldPath: key.slice(0, pipeIdx),
    modifier: key.slice(pipeIdx + 1),
  };
}

/**
 * Resolve values, expanding $list:name references.
 */
function resolveValues(rawValue: unknown, lists: Map<string, string[]>): unknown[] {
  if (Array.isArray(rawValue)) {
    const result: unknown[] = [];
    for (const v of rawValue) {
      if (typeof v === "string" && v.startsWith("$list:")) {
        const listName = v.slice(6);
        const listValues = lists.get(listName);
        if (listValues) result.push(...listValues);
      } else {
        result.push(v);
      }
    }
    return result;
  }
  if (typeof rawValue === "string" && rawValue.startsWith("$list:")) {
    const listName = rawValue.slice(6);
    const listValues = lists.get(listName);
    return listValues ?? [];
  }
  return [rawValue];
}

/**
 * Compile a field matcher with the given modifier.
 */
function compileFieldMatcher(
  fieldPath: string,
  modifier: string,
  values: unknown[],
  fieldRegistry: FieldRegistry,
): MatcherFn {
  // Pre-compile regex patterns
  if (modifier === "re") {
    const regexes = values.map((v) => {
      try {
        return compileRegex(String(v));
      } catch {
        return null;
      }
    }).filter((r): r is RegExp => r !== null);

    return (ctx) => {
      const fieldValue = fieldRegistry.resolve(fieldPath, ctx);
      return matchAgainstRegexes(fieldValue, regexes);
    };
  }

  if (modifier === "contains") {
    const needles = values.map(String);
    return (ctx) => {
      const fieldValue = fieldRegistry.resolve(fieldPath, ctx);
      return matchWithModifier(fieldValue, needles, (fv, needle) =>
        String(fv).includes(needle),
      );
    };
  }

  if (modifier === "startswith") {
    const prefixes = values.map(String);
    return (ctx) => {
      const fieldValue = fieldRegistry.resolve(fieldPath, ctx);
      return matchWithModifier(fieldValue, prefixes, (fv, prefix) =>
        String(fv).startsWith(prefix),
      );
    };
  }

  if (modifier === "endswith") {
    const suffixes = values.map(String);
    return (ctx) => {
      const fieldValue = fieldRegistry.resolve(fieldPath, ctx);
      return matchWithModifier(fieldValue, suffixes, (fv, suffix) =>
        String(fv).endsWith(suffix),
      );
    };
  }

  if (modifier === "all") {
    // All values must match (against any element if field is array)
    return (ctx) => {
      const fieldValue = fieldRegistry.resolve(fieldPath, ctx);
      return values.every((v) => matchExact(fieldValue, v));
    };
  }

  // No modifier: exact match (or boolean)
  return (ctx) => {
    const fieldValue = fieldRegistry.resolve(fieldPath, ctx);
    // OR: any value in the list matches
    return values.some((v) => matchExact(fieldValue, v));
  };
}

/**
 * Match a field value against regex patterns.
 * If fieldValue is an array, any element matching any regex = true.
 */
function matchAgainstRegexes(fieldValue: unknown, regexes: RegExp[]): boolean {
  if (fieldValue == null) return false;

  if (Array.isArray(fieldValue)) {
    return fieldValue.some((elem) =>
      regexes.some((re) => re.test(String(elem))),
    );
  }

  return regexes.some((re) => re.test(String(fieldValue)));
}

/**
 * Match a field value using a modifier function.
 * If fieldValue is an array, any element matching any needle = true.
 */
function matchWithModifier(
  fieldValue: unknown,
  needles: string[],
  matchFn: (fieldValue: unknown, needle: string) => boolean,
): boolean {
  if (fieldValue == null) return false;

  if (Array.isArray(fieldValue)) {
    return fieldValue.some((elem) =>
      needles.some((needle) => matchFn(elem, needle)),
    );
  }

  return needles.some((needle) => matchFn(fieldValue, needle));
}

/**
 * Exact match. Handles booleans, strings, numbers.
 * If fieldValue is an array, any element matching = true.
 */
function matchExact(fieldValue: unknown, expected: unknown): boolean {
  if (fieldValue == null && expected == null) return true;
  if (fieldValue == null) return false;

  if (Array.isArray(fieldValue)) {
    return fieldValue.some((elem) => elemEquals(elem, expected));
  }

  return elemEquals(fieldValue, expected);
}

function elemEquals(a: unknown, b: unknown): boolean {
  if (typeof a === typeof b) return a === b;
  // Coerce string/number comparison
  return String(a) === String(b);
}

/**
 * Compile a regex pattern string, handling (?i) prefix for case-insensitive.
 * JavaScript doesn't support inline (?i) — we extract it as a flag.
 */
function compileRegex(pattern: string): RegExp {
  let flags = "";
  let p = pattern;
  // Handle (?i) prefix for case-insensitive matching
  if (p.startsWith("(?i)")) {
    flags += "i";
    p = p.slice(4);
  }
  return new RegExp(p, flags);
}

// ─── Condition Expression Parser ───

/**
 * Compile a condition expression string into a matcher function.
 * Supports: and, or, not, parentheses, 1 of sel_*, all of sel_*
 */
function compileCondition(
  expr: string,
  selections: Map<string, MatcherFn>,
): MatcherFn {
  const tokens = tokenize(expr);
  const result = parseOr(tokens, 0, selections);
  return result.fn;
}

interface ParseResult {
  fn: MatcherFn;
  pos: number;
}

function tokenize(expr: string): string[] {
  const tokens: string[] = [];
  let i = 0;
  while (i < expr.length) {
    // Skip whitespace
    if (/\s/.test(expr[i])) { i++; continue; }
    // Parentheses
    if (expr[i] === "(" || expr[i] === ")") {
      tokens.push(expr[i]);
      i++;
      continue;
    }
    // Word or "1" or "all"
    let word = "";
    while (i < expr.length && !/[\s()]/.test(expr[i])) {
      word += expr[i];
      i++;
    }
    if (word) tokens.push(word);
  }
  return tokens;
}

function parseOr(tokens: string[], pos: number, selections: Map<string, MatcherFn>): ParseResult {
  let left = parseAnd(tokens, pos, selections);
  while (left.pos < tokens.length && tokens[left.pos] === "or") {
    const right = parseAnd(tokens, left.pos + 1, selections);
    const leftFn = left.fn;
    const rightFn = right.fn;
    left = {
      fn: (ctx) => leftFn(ctx) || rightFn(ctx),
      pos: right.pos,
    };
  }
  return left;
}

function parseAnd(tokens: string[], pos: number, selections: Map<string, MatcherFn>): ParseResult {
  let left = parseNot(tokens, pos, selections);
  while (left.pos < tokens.length && tokens[left.pos] === "and") {
    const right = parseNot(tokens, left.pos + 1, selections);
    const leftFn = left.fn;
    const rightFn = right.fn;
    left = {
      fn: (ctx) => leftFn(ctx) && rightFn(ctx),
      pos: right.pos,
    };
  }
  return left;
}

function parseNot(tokens: string[], pos: number, selections: Map<string, MatcherFn>): ParseResult {
  if (pos < tokens.length && tokens[pos] === "not") {
    const inner = parseNot(tokens, pos + 1, selections);
    const innerFn = inner.fn;
    return {
      fn: (ctx) => !innerFn(ctx),
      pos: inner.pos,
    };
  }
  return parsePrimary(tokens, pos, selections);
}

function parsePrimary(tokens: string[], pos: number, selections: Map<string, MatcherFn>): ParseResult {
  if (pos >= tokens.length) {
    return { fn: () => false, pos };
  }

  // Parenthesized expression
  if (tokens[pos] === "(") {
    const inner = parseOr(tokens, pos + 1, selections);
    // Skip closing paren
    const nextPos = inner.pos < tokens.length && tokens[inner.pos] === ")" ? inner.pos + 1 : inner.pos;
    return { fn: inner.fn, pos: nextPos };
  }

  // "1 of sel_*" or "all of sel_*"
  if ((tokens[pos] === "1" || tokens[pos] === "all") && pos + 2 < tokens.length && tokens[pos + 1] === "of") {
    const quantifier = tokens[pos];
    const pattern = tokens[pos + 2];
    const matchingSelections = getMatchingSelections(pattern, selections);

    if (quantifier === "1") {
      return {
        fn: (ctx) => matchingSelections.some((fn) => fn(ctx)),
        pos: pos + 3,
      };
    } else {
      return {
        fn: (ctx) => matchingSelections.every((fn) => fn(ctx)),
        pos: pos + 3,
      };
    }
  }

  // Named selection reference
  const name = tokens[pos];
  const selFn = selections.get(name);
  if (selFn) {
    return { fn: selFn, pos: pos + 1 };
  }

  // Unknown reference — always false
  return { fn: () => false, pos: pos + 1 };
}

/**
 * Get all selection matchers matching a glob pattern like "sel_*".
 */
function getMatchingSelections(pattern: string, selections: Map<string, MatcherFn>): MatcherFn[] {
  if (!pattern.includes("*")) {
    const fn = selections.get(pattern);
    return fn ? [fn] : [];
  }

  const prefix = pattern.replace("*", "");
  const result: MatcherFn[] = [];
  for (const [name, fn] of selections) {
    if (name.startsWith(prefix)) {
      result.push(fn);
    }
  }
  return result;
}
