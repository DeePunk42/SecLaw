// ============================================================
// Platform detection utilities
// Detects OS / WSL2 / Node version / OpenClaw version
// ============================================================
import { execSync, spawn } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { platform, arch, homedir, hostname } from "node:os";
import { join } from "node:path";
import type { Platform } from "./types.js";

/** Detect current runtime platform */
export function detectPlatform(): Platform {
  const os = platform();
  let isWSL2 = false;

  if (os === "linux") {
    try {
      const procVersion = readFileSync("/proc/version", "utf-8");
      if (/microsoft|wsl/i.test(procVersion) || process.env.WSL_DISTRO_NAME) {
        isWSL2 = true;
      }
    } catch {
      /* ignore */
    }
  }

  let openclawVersion: string | undefined;
  const cliBins = ["openclaw"];

  // Windows: search common install paths if not in global PATH
  if (os === "win32") {
    const appData = process.env.APPDATA || "";
    const localAppData = process.env.LOCALAPPDATA || "";
    const home = process.env.USERPROFILE || "";
    const extraPaths = [
      join(appData, "npm", "openclaw.cmd"),
      join(appData, "npm", "openclaw"),
      join(localAppData, "pnpm", "openclaw.cmd"),
      join(home, ".local", "bin", "openclaw"),
    ];
    for (const p of extraPaths) {
      if (existsSync(p)) { cliBins.push(p); break; }
    }
  }

  for (const bin of cliBins) {
    try {
      const output = execSync(`"${bin}" --version`, {
        encoding: "utf-8",
        timeout: 8000,
        windowsHide: true,
      });
      const match = output.match(/(\d+\.\d+\.\d+)/);
      if (match) { openclawVersion = match[1]; break; }
    } catch {
      /* CLI not available */
    }
  }

  return {
    os: os as Platform["os"],
    isWSL2,
    nodeVersion: process.version,
    openclawVersion,
    arch: arch(),
    hostname: hostname(),
  };
}

/** Get OpenClaw config directory */
export function getOpenClawDir(): string {
  const override = process.env.OPENCLAW_HOME;
  if (override && override.trim()) {
    return override;
  }
  if (platform() === "win32") {
    return join(process.env.USERPROFILE || homedir(), ".openclaw");
  }
  return join(homedir(), ".openclaw");
}

/** Safe command execution with timeout and error handling */
export function safeExec(
  cmd: string,
  timeout = 30000,
): { ok: boolean; stdout: string; stderr: string } {
  try {
    const env: Record<string, string | undefined> = { ...process.env, CI: "1", FORCE_COLOR: "0" };
    delete env.ELECTRON_RUN_AS_NODE;
    delete env.ELECTRON_NO_ATTACH_CONSOLE;

    const stdout = execSync(cmd, {
      encoding: "utf-8",
      timeout,
      env,
      stdio: ["pipe", "pipe", "pipe"],
      windowsHide: true,
      maxBuffer: 1024 * 1024 * 10, // 10MB
    });
    return { ok: true, stdout: stdout.trim(), stderr: "" };
  } catch (err: any) {
    const stdoutStr = err.stdout?.toString()?.trim() || "";
    const stderrStr = err.stderr?.toString()?.trim() || "";
    let output = stderrStr || stdoutStr || err.message;

    if (err.message?.includes("ETIMEDOUT")) {
      output = `Execution timed out (${timeout / 1000}s)!\n[captured]:\n${stdoutStr || "(no output)"}\n${stderrStr || ""}`;
    }

    return { ok: false, stdout: stdoutStr, stderr: output };
  }
}

/** Async safe command execution (spawn-based, prevents pipe deadlock) */
export function safeExecAsync(
  cmd: string,
  timeout = 30000,
): Promise<{ ok: boolean; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    const env: Record<string, string | undefined> = { ...process.env, CI: "1", FORCE_COLOR: "0" };
    delete env.ELECTRON_RUN_AS_NODE;
    delete env.ELECTRON_NO_ATTACH_CONSOLE;

    let isDone = false;
    const child = spawn(cmd, { shell: true, env, windowsHide: true });
    if (child.stdin) child.stdin.end();

    const timer = setTimeout(() => {
      if (isDone) return;
      isDone = true;
      child.kill("SIGKILL");
      resolve({
        ok: false,
        stdout: stdout.trim(),
        stderr: `Execution timed out (${timeout / 1000}s)!\n[partial output]:\n${stderr}\n${stdout}`,
      });
    }, timeout);

    child.stdout.on("data", (data) => (stdout += data.toString()));
    child.stderr.on("data", (data) => (stderr += data.toString()));

    child.on("error", (err) => {
      if (isDone) return;
      isDone = true;
      clearTimeout(timer);
      resolve({ ok: false, stdout: stdout.trim(), stderr: `Process spawn failed: ${err.message}` });
    });

    // Listen on exit event only — avoids deadlock from child processes keeping stdout pipe open
    child.on("exit", (code) => {
      if (isDone) return;
      isDone = true;
      clearTimeout(timer);
      resolve({ ok: code === 0, stdout: stdout.trim(), stderr: stderr.trim() });
    });
  });
}
