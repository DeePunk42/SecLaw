import { describe, it, expect } from "vitest";
import {
  splitCommandChain,
  extractPrimaryCommand,
  decomposeCommand,
  commandStartsWith,
  commandMatchesPattern,
} from "../src/patterns/command-patterns.js";

describe("splitCommandChain", () => {
  it("splits on pipe |", () => {
    expect(splitCommandChain("cat file | grep foo | wc -l")).toEqual([
      "cat file",
      "grep foo",
      "wc -l",
    ]);
  });

  it("splits on && and ||", () => {
    expect(splitCommandChain("echo ok && rm -rf / || true")).toEqual([
      "echo ok",
      "rm -rf /",
      "true",
    ]);
  });

  it("splits on ;", () => {
    expect(splitCommandChain("echo ok ; rm -rf / ; ls")).toEqual([
      "echo ok",
      "rm -rf /",
      "ls",
    ]);
  });

  it("does not split inside single quotes", () => {
    expect(splitCommandChain("echo 'a | b && c'")).toEqual(["echo 'a | b && c'"]);
  });

  it("does not split inside double quotes", () => {
    expect(splitCommandChain('echo "a | b && c"')).toEqual(['echo "a | b && c"']);
  });

  it("handles backslash escaping", () => {
    expect(splitCommandChain("echo a \\| b")).toEqual(["echo a \\| b"]);
  });

  it("handles empty input", () => {
    expect(splitCommandChain("")).toEqual([]);
  });

  it("handles single command", () => {
    expect(splitCommandChain("ls -la")).toEqual(["ls -la"]);
  });

  it("Windows: splits on single & when platform is windows", () => {
    expect(splitCommandChain("dir & del file.txt", "windows")).toEqual([
      "dir",
      "del file.txt",
    ]);
  });

  it("Linux: does NOT split on single & (background)", () => {
    // On Linux, single & is background operator, not a separator
    expect(splitCommandChain("sleep 10 & ls", "linux")).toEqual(["sleep 10 & ls"]);
  });
});

describe("extractPrimaryCommand", () => {
  it("extracts simple command", () => {
    expect(extractPrimaryCommand("rm -rf /")).toBe("rm");
  });

  it("skips env var prefix", () => {
    expect(extractPrimaryCommand("NODE_ENV=production npm start")).toBe("npm");
  });

  it("skips safe wrappers (env, nohup)", () => {
    expect(extractPrimaryCommand("env rm -rf /")).toBe("rm");
    expect(extractPrimaryCommand("nohup npm start")).toBe("npm");
  });

  it("does NOT skip sudo (security-relevant)", () => {
    expect(extractPrimaryCommand("sudo apt install vim")).toBe("sudo");
  });

  it("returns null for empty input", () => {
    expect(extractPrimaryCommand("")).toBeNull();
    expect(extractPrimaryCommand("  ")).toBeNull();
  });
});

describe("decomposeCommand", () => {
  it("decomposes simple pipeline", () => {
    const result = decomposeCommand("cat file.txt | grep pattern | wc -l");
    expect(result.primary).toBe("cat");
    expect(result.all).toEqual(["cat", "grep", "wc"]);
    expect(result.segments).toEqual(["cat file.txt", "grep pattern", "wc -l"]);
  });

  it("decomposes command chain with && and ;", () => {
    const result = decomposeCommand("echo ok && rm -rf / ; ls");
    expect(result.primary).toBe("echo");
    expect(result.all).toEqual(["echo", "rm", "ls"]);
    expect(result.segments).toEqual(["echo ok", "rm -rf /", "ls"]);
  });

  it("handles env var prefix", () => {
    const result = decomposeCommand("NODE_ENV=production npm start");
    expect(result.primary).toBe("npm");
    expect(result.all).toEqual(["npm"]);
  });

  it("handles empty command", () => {
    const result = decomposeCommand("");
    expect(result.primary).toBeNull();
    expect(result.all).toEqual([]);
    expect(result.segments).toEqual([]);
  });

  it("handles mkfs.ext4", () => {
    const result = decomposeCommand("mkfs.ext4 /dev/sda1");
    expect(result.primary).toBe("mkfs.ext4");
    expect(result.all).toEqual(["mkfs.ext4"]);
  });
});

describe("commandStartsWith", () => {
  it("matches exact command prefix", () => {
    expect(commandStartsWith("rm -rf node_modules", "rm")).toBe(true);
  });

  it("matches exact command (no args)", () => {
    expect(commandStartsWith("rm", "rm")).toBe(true);
  });

  it("does not match partial prefix", () => {
    expect(commandStartsWith("rmdir /tmp/test", "rm")).toBe(false);
  });

  it("handles leading whitespace", () => {
    expect(commandStartsWith("  rm -rf stuff", "rm")).toBe(true);
  });
});

describe("commandMatchesPattern", () => {
  it("matches regex pattern", () => {
    expect(
      commandMatchesPattern(
        "rm -rf /home/user",
        "rm\\s+.*(-rf|-fr)\\s+(/|~|/etc|/usr|/home)",
      ),
    ).toBe(true);
  });

  it("does not match non-matching command", () => {
    expect(commandMatchesPattern("ls -la", "rm\\s+.*(-rf|-fr)")).toBe(false);
  });

  it("handles invalid regex gracefully", () => {
    expect(commandMatchesPattern("test", "[invalid regex")).toBe(false);
  });
});
