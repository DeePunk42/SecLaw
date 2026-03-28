import { describe, it, expect } from "vitest";
import {
  decomposePath,
  isPathInWorkspace,
  extractPathsFromCommand,
} from "../src/patterns/path-patterns.js";

describe("decomposePath", () => {
  it("decomposes absolute path", () => {
    const result = decomposePath("/home/user/.ssh/id_rsa");
    expect(result.dir).toBe("/home/user/.ssh");
    expect(result.name).toBe("id_rsa");
    expect(result.ext).toBe("");
  });

  it("decomposes path with extension", () => {
    const result = decomposePath("/app/src/index.ts");
    expect(result.dir).toBe("/app/src");
    expect(result.name).toBe("index.ts");
    expect(result.ext).toBe(".ts");
  });

  it("computes inWorkspace = true", () => {
    const result = decomposePath("/workspace/src/file.ts", "/workspace");
    expect(result.inWorkspace).toBe(true);
  });

  it("computes inWorkspace = false for outside path", () => {
    const result = decomposePath("/etc/passwd", "/workspace");
    expect(result.inWorkspace).toBe(false);
  });
});

describe("isPathInWorkspace", () => {
  it("returns true for path within workspace", () => {
    expect(isPathInWorkspace("/workspace/src/file.ts", "/workspace")).toBe(true);
  });

  it("returns false for path outside workspace", () => {
    expect(isPathInWorkspace("/etc/passwd", "/workspace")).toBe(false);
  });

  it("returns false for path traversal attempt", () => {
    expect(
      isPathInWorkspace("/workspace/../etc/passwd", "/workspace"),
    ).toBe(false);
  });

  it("returns false when no workspace is specified", () => {
    expect(isPathInWorkspace("/workspace/file.ts", undefined)).toBe(false);
  });

  it("returns true for workspace root itself", () => {
    expect(isPathInWorkspace("/workspace", "/workspace")).toBe(true);
  });
});

describe("extractPathsFromCommand", () => {
  it("extracts absolute paths", () => {
    const paths = extractPathsFromCommand("rm -rf /tmp/test /var/log/app.log");
    expect(paths).toContain("/tmp/test");
    expect(paths).toContain("/var/log/app.log");
  });

  it("extracts relative paths", () => {
    const paths = extractPathsFromCommand("cat ./config.json");
    expect(paths).toContain("./config.json");
  });

  it("extracts home-relative paths", () => {
    const paths = extractPathsFromCommand("cat ~/.ssh/id_rsa");
    expect(paths).toContain("~/.ssh/id_rsa");
  });

  it("returns empty for commands without paths", () => {
    const paths = extractPathsFromCommand("echo hello");
    expect(paths).toEqual([]);
  });
});
