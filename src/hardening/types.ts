// ============================================================
// Hardening type definitions
// Based on openclaw-hardening-integrated plugin types
// ============================================================

/** Risk severity level */
export type Severity = "critical" | "warning" | "info" | "pass";

/** Single check result */
export interface CheckResult {
  id: string;
  domain: string;
  name: string;
  severity: Severity;
  status: "pass" | "fail" | "warn" | "skip";
  message: string;
  current?: string;
  expected?: string;
  fix?: string;
}

/** Hardening operation result */
export interface HardenResult {
  id: string;
  name: string;
  success: boolean;
  message: string;
  changed: boolean;
  rollback?: string;
}

/** Full hardening report */
export interface HardeningReport {
  timestamp: string;
  platform: Platform;
  mode: "paranoid" | "balanced";
  checks: CheckResult[];
  summary: {
    total: number;
    pass: number;
    fail: number;
    warn: number;
    skip: number;
    score: number;
  };
}

/** Platform information */
export interface Platform {
  os: "linux" | "darwin" | "win32";
  isWSL2: boolean;
  nodeVersion: string;
  openclawVersion?: string;
  arch: string;
}
