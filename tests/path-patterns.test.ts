import { describe, it, expect } from "vitest";
import {
  isSensitiveWritePath,
  isSensitiveReadPath,
  isPathInWorkspace,
  extractPathsFromCommand,
} from "../src/patterns/path-patterns.js";

describe("isSensitiveWritePath", () => {
  it("detects ~/.ssh/ paths", () => {
    expect(isSensitiveWritePath("~/.ssh/authorized_keys")).toBe(true);
    expect(isSensitiveWritePath("~/.ssh/config")).toBe(true);
  });

  it("detects /home/user/.ssh/ paths", () => {
    expect(isSensitiveWritePath("/home/user/.ssh/id_rsa")).toBe(true);
  });

  it("detects .gitconfig", () => {
    expect(isSensitiveWritePath("~/.gitconfig")).toBe(true);
    expect(isSensitiveWritePath("/home/user/.gitconfig")).toBe(true);
  });

  it("detects .env files", () => {
    expect(isSensitiveWritePath("/app/.env")).toBe(true);
    expect(isSensitiveWritePath("/project/.env.local")).toBe(true);
  });

  it("detects .aws paths", () => {
    expect(isSensitiveWritePath("~/.aws/credentials")).toBe(true);
    expect(isSensitiveWritePath("~/.aws/config")).toBe(true);
  });

  it("detects etc system files", () => {
    expect(isSensitiveWritePath("/etc/passwd")).toBe(true);
    expect(isSensitiveWritePath("/etc/shadow")).toBe(true);
    expect(isSensitiveWritePath("/etc/sudoers")).toBe(true);
  });

  it("allows normal workspace paths", () => {
    expect(isSensitiveWritePath("/workspace/src/index.ts")).toBe(false);
    expect(isSensitiveWritePath("/project/package.json")).toBe(false);
  });
});

describe("isSensitiveReadPath", () => {
  it("detects secret files", () => {
    expect(isSensitiveReadPath("/app/secret.json")).toBe(true);
  });

  it("detects .env files", () => {
    expect(isSensitiveReadPath(".env")).toBe(true);
  });

  it("detects credential files", () => {
    expect(isSensitiveReadPath("/app/credentials.json")).toBe(true);
  });

  it("detects private key files", () => {
    expect(isSensitiveReadPath("/app/private.key")).toBe(true);
    expect(isSensitiveReadPath("server.pem")).toBe(true);
  });

  it("allows normal files", () => {
    expect(isSensitiveReadPath("README.md")).toBe(false);
    expect(isSensitiveReadPath("src/index.ts")).toBe(false);
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
