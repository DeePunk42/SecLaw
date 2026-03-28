// ============================================================
// Hardening type definitions
// Based on openclaw-hardening-integrated plugin types
// ============================================================

/** Risk severity level */
export type Severity = "critical" | "warning" | "info" | "pass";

/** Security score grade */
export type Grade = "S" | "A" | "B" | "C" | "D";

/** Single check result */
export interface CheckResult {
  id: string;
  domain: string;
  name: string;
  severity: Severity;
  status: "pass" | "fail" | "warn" | "skip" | "n/a" | "unknown";
  message: string;
  current?: string;
  expected?: string;
  fix?: string;
  category?: "core" | "recommended";
}

/** Hardening action definition */
export interface HardenAction {
  id: string;
  name: string;
  domain: string;
  description: string;
  risk: "low" | "medium" | "high";
  category: "core" | "recommended";
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

/** Scan summary with sub-scores */
export interface ScanSummary {
  total: number;
  pass: number;
  fail: number;
  warn: number;
  skip: number;
  na: number;
  unknown: number;
  score: number;
  grade: Grade;
  hasCriticalFail: boolean;
  limitations: number;
  configScore: number;
  structuralCeiling: number;
}

/** Full hardening report */
export interface HardeningReport {
  timestamp: string;
  platform: Platform;
  mode: "paranoid" | "balanced";
  checks: CheckResult[];
  summary: ScanSummary;
}

/** Platform information */
export interface Platform {
  os: "linux" | "darwin" | "win32";
  isWSL2: boolean;
  nodeVersion: string;
  openclawVersion?: string;
  arch: string;
  hostname: string;
}
