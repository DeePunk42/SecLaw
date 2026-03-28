// ============================================================
// Hardening type definitions
// Based on openclaw-hardening-integrated plugin types
// ============================================================

/** Risk severity level */
export type Severity = "critical" | "warning" | "info" | "pass";

/** Security score grade */
export type Grade = "A" | "B" | "C" | "D" | "F";

/** Single check result */
export interface CheckResult {
  id: string;
  domain: string;
  name: string;
  severity: Severity;
  status: "pass" | "fail" | "warn" | "skip" | "n/a";
  message: string;
  current?: string;
  expected?: string;
  fix?: string;
  category?: "core" | "recommended";
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
    na: number;
    score: number;
    grade: Grade;
    hasCriticalFail: boolean;
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
