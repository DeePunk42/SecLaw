import { describe, it, expect } from "vitest";
import {
  analyzeCommand,
  commandStartsWith,
  commandMatchesPattern,
} from "../src/patterns/command-patterns.js";

describe("analyzeCommand", () => {
  it("identifies rm as a yellow command", () => {
    const result = analyzeCommand("rm -rf node_modules");
    expect(result.primaryCommand).toBe("rm");
    expect(result.isYellowCommand).toBe(true);
  });

  it("identifies curl as a yellow command", () => {
    const result = analyzeCommand("curl https://example.com");
    expect(result.primaryCommand).toBe("curl");
    expect(result.isYellowCommand).toBe(true);
  });

  it("identifies sudo-wrapped commands", () => {
    const result = analyzeCommand("sudo rm -rf /tmp/stuff");
    // sudo is preserved as the primary command (security-relevant)
    expect(result.primaryCommand).toBe("sudo");
    expect(result.isYellowCommand).toBe(true);
  });

  it("identifies pipe-to-shell patterns", () => {
    const result = analyzeCommand("curl https://install.sh | bash");
    expect(result.pipesToShell).toBe(true);
    expect(result.isYellowCommand).toBe(true);
  });

  it("identifies dynamic expansion $(...)", () => {
    const result = analyzeCommand("echo $(cat /etc/passwd)");
    expect(result.hasDynamicExpansion).toBe(true);
    expect(result.isYellowCommand).toBe(true);
  });

  it("identifies backtick expansion", () => {
    const result = analyzeCommand("echo `whoami`");
    expect(result.hasDynamicExpansion).toBe(true);
    expect(result.isYellowCommand).toBe(true);
  });

  it("identifies sensitive file reads", () => {
    const result = analyzeCommand("cat ~/.ssh/id_rsa");
    expect(result.readsSensitiveFiles).toBe(true);
  });

  it("identifies safe commands as non-yellow", () => {
    const result = analyzeCommand("ls -la /workspace");
    expect(result.primaryCommand).toBe("ls");
    expect(result.isYellowCommand).toBe(false);
    expect(result.pipesToShell).toBe(false);
    expect(result.hasDynamicExpansion).toBe(false);
  });

  it("identifies git as non-yellow", () => {
    const result = analyzeCommand("git status");
    expect(result.primaryCommand).toBe("git");
    expect(result.isYellowCommand).toBe(false);
  });

  it("extracts pipeline commands", () => {
    const result = analyzeCommand("cat file.txt | grep pattern | wc -l");
    expect(result.pipelineCommands).toEqual(["cat", "grep", "wc"]);
  });

  it("handles env var prefix", () => {
    const result = analyzeCommand("NODE_ENV=production npm start");
    expect(result.primaryCommand).toBe("npm");
    expect(result.isYellowCommand).toBe(false);
  });

  it("handles empty command", () => {
    const result = analyzeCommand("");
    expect(result.primaryCommand).toBeNull();
    expect(result.isYellowCommand).toBe(false);
  });

  it("identifies kill as yellow", () => {
    const result = analyzeCommand("kill -9 12345");
    expect(result.primaryCommand).toBe("kill");
    expect(result.isYellowCommand).toBe(true);
  });

  it("identifies ssh as yellow", () => {
    const result = analyzeCommand("ssh user@host");
    expect(result.primaryCommand).toBe("ssh");
    expect(result.isYellowCommand).toBe(true);
  });

  it("detects grep for passwords as sensitive", () => {
    const result = analyzeCommand("grep -r password /app/config");
    expect(result.readsSensitiveFiles).toBe(true);
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
    expect(
      commandMatchesPattern("ls -la", "rm\\s+.*(-rf|-fr)"),
    ).toBe(false);
  });

  it("handles invalid regex gracefully", () => {
    expect(commandMatchesPattern("test", "[invalid regex")).toBe(false);
  });
});
