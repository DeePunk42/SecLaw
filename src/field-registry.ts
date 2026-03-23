/**
 * FieldRegistry: resolves field paths to values from MatchContext.
 * Supports dotted paths like "cmd.primary", "file.ext", "url.host".
 * Extensible via register() for future fields (e.g., ext.scriptHash).
 */

import type { MatchContext } from "./config.js";

export type FieldResolver = (ctx: MatchContext) => unknown;

export class FieldRegistry {
  private resolvers = new Map<string, FieldResolver>();

  register(fieldPath: string, resolver: FieldResolver): void {
    this.resolvers.set(fieldPath, resolver);
  }

  resolve(fieldPath: string, ctx: MatchContext): unknown {
    // Check explicit resolvers first
    const resolver = this.resolvers.get(fieldPath);
    if (resolver) return resolver(ctx);

    // Fallback: param.<key> access
    if (fieldPath.startsWith("param.")) {
      const key = fieldPath.slice(6);
      return ctx.params[key];
    }

    // Fallback: ext.<key> access
    if (fieldPath.startsWith("ext.")) {
      const key = fieldPath.slice(4);
      return ctx.ext[key];
    }

    return undefined;
  }
}

/**
 * Create a FieldRegistry with all built-in field resolvers registered.
 */
export function createDefaultFieldRegistry(): FieldRegistry {
  const reg = new FieldRegistry();

  // Raw param fields
  reg.register("command", (ctx) => ctx.command);
  reg.register("path", (ctx) => ctx.path);
  reg.register("url", (ctx) => ctx.url);
  reg.register("action", (ctx) => ctx.action);
  reg.register("host", (ctx) => ctx.host);
  reg.register("elevated", (ctx) => ctx.elevated);
  reg.register("content", (ctx) => ctx.content);
  reg.register("query", (ctx) => ctx.query);

  // Command decomposition
  reg.register("cmd.primary", (ctx) => ctx.cmd?.primary);
  reg.register("cmd.all", (ctx) => ctx.cmd?.all);
  reg.register("cmd.segments", (ctx) => ctx.cmd?.segments);

  // File decomposition
  reg.register("file.dir", (ctx) => ctx.file?.dir);
  reg.register("file.name", (ctx) => ctx.file?.name);
  reg.register("file.ext", (ctx) => ctx.file?.ext);
  reg.register("file.inWorkspace", (ctx) => ctx.file?.inWorkspace);

  // URL decomposition
  reg.register("url.host", (ctx) => ctx.urlParsed?.host);
  reg.register("url.port", (ctx) => ctx.urlParsed?.port);
  reg.register("url.path", (ctx) => ctx.urlParsed?.path);
  reg.register("url.scheme", (ctx) => ctx.urlParsed?.scheme);
  reg.register("url.isPrivateIP", (ctx) => ctx.urlParsed?.isPrivateIP);

  return reg;
}
