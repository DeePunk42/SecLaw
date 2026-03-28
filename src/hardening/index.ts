// Barrel export for hardening modules
export type {
  Severity,
  Grade,
  CheckResult,
  HardenAction,
  HardenResult,
  ScanSummary,
  HardeningReport,
  Platform,
} from "./types.js";

export { detectPlatform, getOpenClawDir, safeExec, safeExecAsync } from "./platform.js";
export { detectOpenClaw, runAllChecks, generateSummary } from "./checker.js";
export {
  backupConfig,
  deployConfig,
  hardenPermissions,
  generateBaseline,
  hardenNpmrc,
  initGitBackup,
  runSchemaValidation,
  runSchemaValidationAsync,
  runSecurityAudit,
  runSecurityAuditAsync,
  deployChannelHint,
  deployAgents,
  immutableProtect,
  configureFirewall,
  checkDiskEncryption,
  deployAuditScript,
  deployVerifyHint,
  listBackups,
  restoreBackup,
} from "./hardener.js";
