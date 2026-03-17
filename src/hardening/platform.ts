// ============================================================
// Platform detection utilities
// Detects OS / WSL2 / Node version / OpenClaw version
// ============================================================
import { execSync } from "node:child_process";
import { readFileSync, existsSync } from "node:fs";
import { platform, arch, homedir } from "node:os";
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
  try {
    const output = execSync("openclaw --version", {
      encoding: "utf-8",
      timeout: 5000,
    });
    const match = output.match(/(\d+\.\d+\.\d+)/);
    if (match) openclawVersion = match[1];
  } catch {
    /* CLI not available */
  }

  return {
    os: os as Platform["os"],
    isWSL2,
    nodeVersion: process.version,
    openclawVersion,
    arch: arch(),
  };
}

/** Get OpenClaw config directory */
export function getOpenClawDir(): string {
  if (platform() === "win32") {
    return join(process.env.USERPROFILE || homedir(), ".openclaw");
  }
  return join(homedir(), ".openclaw");
}

/** Safe command execution with timeout and error handling */
export function safeExec(
  cmd: string,
  timeout = 10000,
): { ok: boolean; stdout: string; stderr: string } {
  try {
    const stdout = execSync(cmd, {
      encoding: "utf-8",
      timeout,
      stdio: ["pipe", "pipe", "pipe"],
    });
    return { ok: true, stdout: stdout.trim(), stderr: "" };
  } catch (err: any) {
    return {
      ok: false,
      stdout: "",
      stderr: err.stderr?.toString() || err.message,
    };
  }
}
