// Barrel export for hardening modules
export type {
  Severity,
  Grade,
  CheckResult,
  HardenResult,
  HardeningReport,
  Platform,
} from "./types.js";

export { detectPlatform, getOpenClawDir, safeExec } from "./platform.js";
export { runAllChecks, generateSummary } from "./checker.js";
export {
  backupConfig,
  deployConfig,
  hardenPermissions,
  generateBaseline,
  hardenNpmrc,
  initGitBackup,
  runSchemaValidation,
  runSecurityAudit,
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
