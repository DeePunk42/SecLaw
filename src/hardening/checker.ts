// ============================================================
// Security checker — 9 domains, 33+ items
// Read-only: reads config, checks permissions, compares baselines
// v2.0: Three-level danger distinction, async, recommended bonus
// ============================================================
import { readFileSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";
import { platform } from "node:os";
import { createHash } from "node:crypto";
import type { CheckResult, Grade, Platform, ScanSummary } from "./types.js";
import { getOpenClawDir, safeExec, safeExecAsync } from "./platform.js";

// Balanced mode baseline safeBins
const BALANCED_SAFEBINS = [
  "ls", "cat", "head", "tail", "grep", "find",
  "wc", "echo", "pwd", "whoami", "date",
  "git", "node", "python3",
  "jq", "sha256sum", "diff",
  "mkdir", "cp", "mv",
];

// Dangerous commands that should not be in safeBins
const DANGEROUS_BINS = [
  "curl",
  "wget",
  "npm",
  "pip",
  "pip3",
  "sudo",
  "rm",
  "dd",
  "nc",
  "ncat",
];

/** Detect whether OpenClaw is installed */
export function detectOpenClaw(): {
  installed: boolean;
  configDir: string;
  hasConfig: boolean;
  version: string | null;
} {
  const ocDir = getOpenClawDir();
  const configPath = join(ocDir, "openclaw.json");
  const dirExists = existsSync(ocDir);
  const configExists = dirExists && existsSync(configPath);

  let version: string | null = null;
  const cliBins = ["openclaw"];

  // Windows: search common install paths
  if (platform() === "win32") {
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
      const result = safeExec(`"${bin}" --version`, 8000);
      if (result.ok && result.stdout.trim()) {
        version = result.stdout.trim();
        break;
      }
    } catch { /* ignore */ }
  }

  const installed = dirExists && (configExists || version !== null);
  return { installed, configDir: ocDir, hasConfig: configExists, version };
}

/** Yield event loop to prevent UI freeze in Electron contexts */
const yieldTick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));

/** Run all security checks (async to prevent event loop blocking) */
export async function runAllChecks(pf: Platform): Promise<CheckResult[]> {
  const detection = detectOpenClaw();
  const ocDir = detection.configDir;
  const results: CheckResult[] = [];

  // Pre-check: is OpenClaw installed?
  if (!detection.installed) {
    results.push({
      id: "openclaw-detect",
      domain: "环境探测",
      name: "OpenClaw 安装检测",
      severity: "critical",
      status: "fail",
      current: "未安装",
      message: `未检测到 OpenClaw 安装 (检查路径: ${ocDir})`,
      fix: "请先安装 OpenClaw: https://openclaw.ai/docs/install",
    });
    return results;
  }

  results.push({
    id: "openclaw-detect",
    domain: "环境探测",
    name: "OpenClaw 安装检测",
    severity: "pass",
    status: "pass",
    current: detection.version || "已安装",
    message: `OpenClaw 已检测到${detection.version ? ` (${detection.version})` : ""} ✓`,
  });

  // Read current config
  let config: Record<string, any> = {};
  const configPath = join(ocDir, "openclaw.json");
  if (existsSync(configPath)) {
    try {
      config = JSON.parse(readFileSync(configPath, "utf-8"));
    } catch {
      /* cannot parse */
    }
  } else {
    results.push({
      id: "openclaw-config",
      domain: "环境探测",
      name: "配置文件检测",
      severity: "warning",
      status: "warn",
      current: "不存在",
      message: `配置文件不存在: ${configPath}`,
      fix: "运行 openclaw 生成默认配置, 或手动创建 openclaw.json",
    });
  }
  await yieldTick();

  // Domain 1: Network isolation
  results.push(...checkNetworkIsolation(config, pf));
  await yieldTick();
  // Domain 2: Authentication
  results.push(...checkAuthentication(config));
  await yieldTick();
  // Domain 3: Exec security
  results.push(...checkExecSecurity(config));
  await yieldTick();
  // Domain 4: Filesystem security
  results.push(...checkFileSystem(ocDir, pf));
  await yieldTick();
  // Domain 5: Supply chain security
  results.push(...checkSupplyChain(config));
  await yieldTick();
  // Domain 6: Channel/PI defense
  results.push(...checkChannelSecurity(config));
  await yieldTick();
  // Domain 7: Agent behavior
  results.push(...checkAgentBehavior(config, ocDir));
  await yieldTick();
  // Domain 8: Monitoring & audit
  results.push(...(await checkMonitoring(ocDir, pf)));
  await yieldTick();
  // Domain 9: Runtime environment
  results.push(...checkRuntime(pf));

  return results;
}

/** Generate check report summary (v3.1 scoring with recommended bonus) */
export function generateSummary(checks: CheckResult[]): ScanSummary {
  const total = checks.length;
  const pass = checks.filter((c) => c.status === "pass").length;
  const fail = checks.filter((c) => c.status === "fail").length;
  const warn = checks.filter((c) => c.status === "warn").length;
  const skip = checks.filter((c) => c.status === "skip").length;
  const na = checks.filter((c) => c.status === "n/a").length;
  const unknown = checks.filter((c) => c.status === "unknown").length;

  // Core items only (exclude recommended, skip, n/a, and limit- structural checks)
  const coreChecks = checks.filter(
    (c) =>
      c.category !== "recommended" &&
      c.status !== "skip" &&
      c.status !== "n/a" &&
      !c.id.startsWith("limit-"),
  );
  const corePass = coreChecks.filter((c) => c.status === "pass").length;
  const coreWarn = coreChecks.filter((c) => c.status === "warn").length;
  const coreScored = coreChecks.length;

  // Score: pass=100%, warn=30%, fail=0%
  let configScore =
    coreScored > 0 ? Math.round(((corePass + coreWarn * 0.3) / coreScored) * 100) : 100;

  // Recommended item bonus: +2 per pass (capped at 100)
  const recPass = checks.filter(
    (c) => c.category === "recommended" && c.status === "pass",
  ).length;
  configScore = Math.min(100, configScore + recPass * 2);

  // Structural ceiling: each unmitigated limit- item deducts 5 points
  const limitChecks = checks.filter((c) => c.id.startsWith("limit-"));
  const unmitigatedLimits = limitChecks.filter((c) => c.status !== "pass").length;
  const limitations = unmitigatedLimits;
  const structuralCeiling = 100 - unmitigatedLimits * 5;

  let score = Math.min(configScore, structuralCeiling);

  // Two-level critical fail penalties:
  // - explicitDanger (intentionally dangerous config): hard cap at 59 (D)
  // - regular critical fail (unconfigured): soft cap at 74 (C)
  const hasExplicitDanger = checks.some(
    (c) => c.status === "fail" && c.severity === "critical" && (c as any).explicitDanger,
  );
  const hasCriticalFail = checks.some(
    (c) => c.status === "fail" && c.severity === "critical",
  );
  if (hasExplicitDanger && score > 59) {
    score = 59;
  } else if (hasCriticalFail && score > 74) {
    score = 74;
  }

  // Grade: S >= 90, A >= 75, B >= 60, C >= 40, D < 40
  const grade: Grade =
    score >= 90 ? "S" : score >= 75 ? "A" : score >= 60 ? "B" : score >= 40 ? "C" : "D";

  return {
    total,
    pass,
    fail,
    warn,
    skip,
    na,
    unknown,
    score,
    grade,
    hasCriticalFail,
    limitations,
    configScore,
    structuralCeiling,
  };
}

// ════════════════════════════════════════════════════════════
// Domain 1: Network isolation
// ════════════════════════════════════════════════════════════
function checkNetworkIsolation(config: any, pf: Platform): CheckResult[] {
  const results: CheckResult[] = [];

  const bind = config?.gateway?.bind;
  const bindOk = bind === "loopback";
  const bindTailnet = bind === "tailnet";
  const bindDangerous = bind === "lan" || bind === "custom";
  results.push({
    id: "net-bind",
    domain: "横向移动",
    name: "Gateway 绑定地址",
    severity: bindDangerous ? "critical" : (bindOk || bindTailnet) ? "pass" : "warning",
    status: bindDangerous ? "fail" : (bindOk || bindTailnet) ? "pass" : "warn",
    current: bind || "(未设置/auto)",
    expected: "loopback",
    message: bindOk
      ? "仅监听本地回环 ✓"
      : bindTailnet
        ? "Tailnet 绑定 (VPN 隔离网络) ✓"
        : bindDangerous
          ? `⚠ 绑定 "${bind}" — 暴露到网络!`
          : "默认 auto 模式, 建议显式设为 loopback",
    fix: '设置 gateway.bind = "loopback"',
  });

  const proxies = config?.gateway?.trustedProxies;
  const proxyOk = Array.isArray(proxies) && proxies.length === 0;
  results.push({
    id: "net-proxies",
    domain: "横向移动",
    name: "代理信任列表",
    severity: proxyOk ? "pass" : "warning",
    status: proxyOk ? "pass" : "warn",
    current: JSON.stringify(proxies ?? "(未设置)"),
    expected: "[]",
    message: proxyOk ? "不信任任何代理 ✓" : "代理列表非空或未设置",
    fix: "设置 gateway.trustedProxies = []",
  });

  const mdns = config?.discovery?.mdns?.mode;
  const mdnsOk = mdns === "off" || mdns === "minimal";
  results.push({
    id: "net-mdns",
    domain: "横向移动",
    name: "mDNS 服务发现",
    severity: mdnsOk ? "pass" : "warning",
    status: mdnsOk ? "pass" : "warn",
    current: mdns || "(未设置)",
    expected: '"off" 或 "minimal"',
    message: mdnsOk
      ? `mDNS 模式: ${mdns} ✓`
      : '"full" 模式会泄露服务信息',
    fix: '设置 discovery.mdns.mode = "off"',
  });

  if (pf.isWSL2) {
    results.push({
      id: "net-wsl2-portproxy",
      domain: "横向移动",
      name: "WSL2 端口转发风险",
      severity: "warning",
      status: "warn",
      message: "WSL2 环境: bind=loopback 可能被 Windows portproxy 穿透",
      fix: "在 Windows 执行: netsh interface portproxy show all",
    });
  }

  // Firewall rules check
  let fwDetected = false;
  if (pf.os === "win32") {
    const fw = safeExec('netsh advfirewall firewall show rule name="Block OpenClaw External" 2>nul');
    fwDetected = fw.ok && fw.stdout.includes("Block OpenClaw");
  } else if (pf.os === "linux") {
    // Short timeout: iptables without root can hang
    const fw = safeExec("iptables -L INPUT -n 2>/dev/null | grep 18789 || ufw status 2>/dev/null | grep 18789", 3000);
    fwDetected = fw.ok && fw.stdout.length > 0;
  } else if (pf.os === "darwin") {
    const fw = safeExec("/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate");
    fwDetected = fw.ok && fw.stdout.includes("enabled");
  }
  results.push({
    id: "net-firewall",
    domain: "横向移动",
    name: "防火墙规则",
    severity: fwDetected ? "pass" : "warning",
    status: fwDetected ? "pass" : "warn",
    current: fwDetected ? "已配置" : "未检测到",
    message: fwDetected ? "防火墙规则已配置 ✓" : "未检测到 OpenClaw 端口防火墙规则",
    fix: "执行加固操作: 防火墙规则",
  });

  return results;
}

// ════════════════════════════════════════════════════════════
// Domain 2: Authentication
// v2.0: Three-level distinction — explicit danger vs unconfigured vs safe
// ════════════════════════════════════════════════════════════
function checkAuthentication(config: any): CheckResult[] {
  const results: CheckResult[] = [];
  const auth = config?.gateway?.auth;

  // auth.mode: undefined → runtime default is "token" (safe) → warning only
  // "none" → explicit danger → critical + explicitDanger
  // "token"/"password" → pass
  const mode = auth?.mode;
  const authExplicitlyDangerous = mode === "none";
  const authOk = mode === "token" || mode === "password";
  results.push({
    id: "auth-mode",
    domain: "凭证窃取",
    name: "认证模式",
    severity: authExplicitlyDangerous ? "critical" : authOk ? "pass" : "warning",
    status: authExplicitlyDangerous ? "fail" : authOk ? "pass" : "warn",
    current: mode || "(未设置/运行时默认)",
    expected: "token",
    message: authExplicitlyDangerous
      ? "⚠ 认证已显式禁用 — 任何人可直接控制!"
      : authOk
        ? `认证模式: ${mode} ✓`
        : "未显式配置认证模式, 建议设为 token",
    fix: '设置 gateway.auth.mode = "token"',
    ...(authExplicitlyDangerous ? { explicitDanger: true } : {}),
  } as any);

  const token = auth?.token;
  const isSecretRef =
    token && typeof token === "object" && token.source === "env";
  results.push({
    id: "auth-token-ref",
    domain: "凭证窃取",
    name: "Token 存储方式",
    severity: isSecretRef ? "pass" : "warning",
    status: isSecretRef ? "pass" : "warn",
    current: isSecretRef ? `SecretRef (env: ${token.id})` : typeof token,
    expected: 'SecretRef { source: "env" }',
    message: isSecretRef
      ? "Token 通过环境变量引用 ✓"
      : "Token 可能明文存储",
    fix: '设置 gateway.auth.token = { source: "env", provider: "default", id: "OPENCLAW_GATEWAY_TOKEN" }',
  });

  const rate = auth?.rateLimit;
  const rateOk = rate && rate.maxAttempts && rate.maxAttempts <= 10;
  results.push({
    id: "auth-ratelimit",
    domain: "凭证窃取",
    name: "暴力破解防护",
    severity: rateOk ? "pass" : "warning",
    status: rateOk ? "pass" : "warn",
    current: rate
      ? `${rate.maxAttempts} 次/${rate.windowMs}ms`
      : "(未配置)",
    expected: "maxAttempts ≤ 10",
    message: rateOk
      ? `Rate Limit 已启用: ${rate.maxAttempts} 次 ✓`
      : "Rate Limit 未配置或过宽",
    fix: "设置 gateway.auth.rateLimit.maxAttempts = 10",
  });

  // controlUi.allowInsecureAuth: default is false (safe)
  // Only dangerous if explicitly set to true
  const insecure = config?.gateway?.controlUi?.allowInsecureAuth;
  const insecureOk = insecure !== true; // undefined or false = safe
  results.push({
    id: "auth-insecure",
    domain: "凭证窃取",
    name: "禁止 HTTP 明文认证",
    severity: insecureOk ? "pass" : "critical",
    status: insecureOk ? "pass" : "fail",
    current: insecure === true ? "true (危险!)" : String(insecure ?? "(未设置/默认false)"),
    expected: "false",
    message: insecure === true
      ? "⚠ HTTP 明文认证已启用!"
      : "禁止 HTTP 明文认证 ✓",
    fix: "设置 controlUi.allowInsecureAuth = false",
  });

  // dangerouslyDisableDeviceAuth: default is false (safe)
  const noDevAuth =
    config?.gateway?.controlUi?.dangerouslyDisableDeviceAuth;
  const devAuthOk = noDevAuth !== true; // undefined or false = safe
  results.push({
    id: "auth-device",
    domain: "凭证窃取",
    name: "设备认证",
    severity: devAuthOk ? "pass" : "critical",
    status: devAuthOk ? "pass" : "fail",
    current: noDevAuth === true ? "true (危险!)" : String(noDevAuth ?? "(未设置/默认false)"),
    expected: "false",
    message: noDevAuth === true ? "⚠ 设备认证已禁用!" : "设备认证启用 ✓",
    fix: "设置 controlUi.dangerouslyDisableDeviceAuth = false",
  });

  return results;
}

// ════════════════════════════════════════════════════════════
// Domain 3: Exec security
// v2.0: Three-level distinction
// ════════════════════════════════════════════════════════════
function checkExecSecurity(config: any): CheckResult[] {
  const results: CheckResult[] = [];
  const exec = config?.tools?.exec;

  // exec.security: undefined → runtime default is "allowlist" (safe) → warning
  // "none"/"open" → explicit danger → critical + explicitDanger
  // "allowlist" → pass
  const security = exec?.security;
  const execExplicitlyDangerous = security === "none" || security === "open";
  const execOk = security === "allowlist";
  results.push({
    id: "exec-security",
    domain: "代码执行",
    name: "命令执行策略",
    severity: execExplicitlyDangerous ? "critical" : execOk ? "pass" : "warning",
    status: execExplicitlyDangerous ? "fail" : execOk ? "pass" : "warn",
    current: security || "(未设置/运行时默认)",
    expected: "allowlist",
    message: execExplicitlyDangerous
      ? "⚠ 执行安全已显式关闭 — AI 可执行任意命令!"
      : execOk
        ? "白名单模式 ✓"
        : "未显式配置白名单策略, 建议设为 allowlist",
    fix: '设置 tools.exec.security = "allowlist"',
    ...(execExplicitlyDangerous ? { explicitDanger: true } : {}),
  } as any);

  const ask = exec?.ask;
  const askOk = ask === "always" || ask === "on-miss";
  results.push({
    id: "exec-ask",
    domain: "代码执行",
    name: "人工审批",
    severity: askOk ? "pass" : "warning",
    status: askOk ? "pass" : "warn",
    current: ask || "(未设置)",
    expected: '"always" 或 "on-miss"',
    message: askOk ? `审批模式: ${ask} ✓` : "未启用人工审批",
    fix: '设置 tools.exec.ask = "on-miss"',
  });

  const safeBins: string[] = exec?.safeBins || [];
  const dangerousFound = safeBins.filter((b: string) =>
    DANGEROUS_BINS.includes(b),
  );
  results.push({
    id: "exec-dangerous-bins",
    domain: "代码执行",
    name: "safeBins 危险命令检查",
    severity: dangerousFound.length === 0 ? "pass" : "warning",
    status: dangerousFound.length === 0 ? "pass" : "warn",
    current:
      dangerousFound.length > 0
        ? `含: ${dangerousFound.join(", ")}`
        : `${safeBins.length} 个安全命令`,
    expected: "不含 curl/npm/pip/wget/sudo/rm",
    message:
      dangerousFound.length > 0
        ? `⚠ safeBins 含高危命令: ${dangerousFound.join(", ")} — 数据外泄/供应链风险`
        : "safeBins 无高危命令 ✓",
    fix: `从 safeBins 移除: ${dangerousFound.join(", ")}`,
  });

  // workspaceOnly: undefined → runtime default is true (safe) → warning
  // false → explicit danger → critical + explicitDanger
  // true → pass
  const wsOnly = config?.tools?.fs?.workspaceOnly;
  const wsExplicitlyDangerous = wsOnly === false;
  results.push({
    id: "exec-workspace",
    domain: "代码执行",
    name: "文件操作工作区限制",
    severity: wsExplicitlyDangerous ? "critical" : wsOnly === true ? "pass" : "warning",
    status: wsExplicitlyDangerous ? "fail" : wsOnly === true ? "pass" : "warn",
    current: String(wsOnly ?? "(未设置/运行时默认)"),
    expected: "true",
    message: wsExplicitlyDangerous
      ? "⚠ 工作区限制已显式关闭 — AI 可读写任意文件!"
      : wsOnly === true
        ? "工作区限制 ✓"
        : "未显式配置工作区限制, 建议设为 true",
    fix: "设置 tools.fs.workspaceOnly = true",
    ...(wsExplicitlyDangerous ? { explicitDanger: true } : {}),
  } as any);

  const patchWs = exec?.applyPatch?.workspaceOnly;
  results.push({
    id: "exec-patch",
    domain: "代码执行",
    name: "Patch 工作区限制",
    severity: patchWs === true ? "pass" : "warning",
    status: patchWs === true ? "pass" : "warn",
    current: String(patchWs ?? "(未设置)"),
    expected: "true",
    message: patchWs
      ? "Patch 工作区限制 ✓"
      : "Patch 未限制在工作区",
    fix: "设置 tools.exec.applyPatch.workspaceOnly = true",
  });

  // CSRF: default is false (safe). Only dangerous if explicitly true.
  const csrfFlag =
    config?.gateway?.controlUi
      ?.dangerouslyAllowHostHeaderOriginFallback;
  const csrfOk = csrfFlag !== true; // undefined or false = safe
  results.push({
    id: "exec-csrf",
    domain: "代码执行",
    name: "CSRF/WS 劫持防护",
    severity: csrfOk ? "pass" : "critical",
    status: csrfOk ? "pass" : "fail",
    current: csrfFlag === true ? "true (危险!)" : String(csrfFlag ?? "(未设置/默认false)"),
    expected: "false",
    message: csrfFlag === true
      ? "⚠ CSRF 防护已禁用!"
      : "CSRF 防护启用 ✓",
    fix: "设置 controlUi.dangerouslyAllowHostHeaderOriginFallback = false",
  });

  return results;
}

// ════════════════════════════════════════════════════════════
// Domain 4: Filesystem security
// ════════════════════════════════════════════════════════════
function checkFileSystem(ocDir: string, pf: Platform): CheckResult[] {
  const results: CheckResult[] = [];

  if (pf.os !== "win32") {
    const configPath = join(ocDir, "openclaw.json");
    if (existsSync(configPath)) {
      const stat = statSync(configPath);
      const mode = (stat.mode & 0o777).toString(8);
      const permOk = mode === "600";
      results.push({
        id: "fs-config-perm",
        domain: "文件篡改",
        name: "openclaw.json 权限",
        severity: permOk ? "pass" : "warning",
        status: permOk ? "pass" : "warn",
        current: mode,
        expected: "600",
        message: permOk ? "权限 600 ✓" : `权限过宽: ${mode}`,
        fix: `chmod 600 ${configPath}`,
      });
    }

    if (existsSync(ocDir)) {
      const dirStat = statSync(ocDir);
      const dirMode = (dirStat.mode & 0o777).toString(8);
      const dirOk = dirMode === "700";
      results.push({
        id: "fs-dir-perm",
        domain: "文件篡改",
        name: ".openclaw 目录权限",
        severity: dirOk ? "pass" : "warning",
        status: dirOk ? "pass" : "warn",
        current: dirMode,
        expected: "700",
        message: dirOk ? "目录权限 700 ✓" : `目录权限过宽: ${dirMode}`,
        fix: `chmod 700 ${ocDir}`,
      });
    }
  } else {
    // Windows: check NTFS ACL
    const configPath = join(ocDir, "openclaw.json");
    if (existsSync(configPath)) {
      const aclResult = safeExec(`icacls "${configPath}" 2>nul`);
      // Check both English names and well-known SIDs for non-English Windows
      const aclDangerous = aclResult.ok &&
        (aclResult.stdout.includes("Everyone") ||
         aclResult.stdout.includes("BUILTIN\\Users") ||
         aclResult.stdout.includes("S-1-1-0") ||
         aclResult.stdout.includes("S-1-5-32-545"));
      results.push({
        id: "fs-win-acl",
        domain: "文件篡改",
        name: "文件权限 (Windows ACL)",
        severity: aclDangerous ? "warning" : "pass",
        status: aclDangerous ? "warn" : aclResult.ok ? "pass" : "warn",
        current: aclDangerous ? "ACL 过宽" : "仅授权用户",
        message: aclDangerous
          ? "NTFS ACL 过宽: Everyone/Users 可访问"
          : aclResult.ok
            ? "NTFS ACL 已加固 ✓"
            : "无法检测 ACL",
        fix: "执行加固操作: 文件权限加固",
      });
    }
  }

  // Hash baseline
  const baselinePath = join(ocDir, ".config-baseline.sha256");
  const baselineJsonPath = join(ocDir, ".config-baseline.json");
  const hasBaseline =
    existsSync(baselinePath) || existsSync(baselineJsonPath);
  results.push({
    id: "fs-baseline",
    domain: "文件篡改",
    name: "配置哈希基线",
    severity: hasBaseline ? "pass" : "info",
    status: hasBaseline ? "pass" : "n/a",
    message: hasBaseline ? "哈希基线存在 ✓" : "未找到哈希基线文件 (加分项)",
    fix: "部署哈希基线可获得 bonus 分",
    category: "recommended",
  });

  if (hasBaseline) {
    const configPath = join(ocDir, "openclaw.json");
    if (existsSync(configPath)) {
      const content = readFileSync(configPath);
      const currentHash = createHash("sha256").update(content).digest("hex");

      let baselineHash = "";
      if (existsSync(baselineJsonPath)) {
        try {
          const baseline = JSON.parse(
            readFileSync(baselineJsonPath, "utf-8"),
          );
          baselineHash = baseline["openclaw.json"] || "";
        } catch {
          /* ignore */
        }
      }

      if (baselineHash) {
        const match = currentHash === baselineHash;
        results.push({
          id: "fs-integrity",
          domain: "文件篡改",
          name: "配置完整性",
          severity: match ? "pass" : "warning",
          status: match ? "pass" : "warn",
          current: currentHash.slice(0, 16) + "...",
          expected: baselineHash.slice(0, 16) + "...",
          message: match
            ? "配置文件未被篡改 ✓"
            : "⚠ 配置文件哈希与基线不匹配!",
          fix: "检查配置是否被意外修改; 更新基线: 重新运行部署脚本",
        });
      }
    }
  }

  // Disk encryption detection
  let encrypted = false;
  if (pf.os === "win32") {
    const r = safeExec("manage-bde -status C: 2>nul");
    encrypted = r.ok && r.stdout.includes("Protection On");
  } else if (pf.os === "darwin") {
    const r = safeExec("fdesetup status");
    encrypted = r.ok && r.stdout.toLowerCase().includes("on");
  } else if (!pf.isWSL2) {
    const r = safeExec("lsblk -f 2>/dev/null");
    encrypted = r.ok && /crypt|luks/i.test(r.stdout);
  } else {
    encrypted = true; // WSL2: depends on Windows BitLocker, skip
  }
  results.push({
    id: "fs-disk-encryption",
    domain: "文件篡改",
    name: "磁盘加密",
    severity: encrypted ? "pass" : "warning",
    status: encrypted ? "pass" : "warn",
    current: encrypted ? "已启用" : "未检测到",
    message: encrypted ? "磁盘加密已启用 ✓" : "未检测到磁盘加密 (建议启用)",
    fix: pf.os === "win32" ? "启用 BitLocker" : pf.os === "darwin" ? "启用 FileVault" : "启用 LUKS",
  });

  return results;
}

// ════════════════════════════════════════════════════════════
// Domain 5: Supply chain security
// ════════════════════════════════════════════════════════════
function checkSupplyChain(config: any): CheckResult[] {
  const results: CheckResult[] = [];

  const allow = config?.plugins?.allow;
  if (allow === undefined || allow === null) {
    results.push({
      id: "supply-plugins",
      domain: "供应链投毒",
      name: "插件白名单",
      severity: "info",
      status: "n/a",
      message: "插件白名单未配置 (功能未启用)",
      fix: "如需安装插件, 建议先设置 plugins.allow = []",
    });
  } else {
    const pluginOk = Array.isArray(allow);
    results.push({
      id: "supply-plugins",
      domain: "供应链投毒",
      name: "插件白名单",
      severity: pluginOk ? "pass" : "warning",
      status: pluginOk ? "pass" : "warn",
      current: pluginOk ? `${allow.length} 个` : String(allow),
      message: pluginOk
        ? `插件白名单已启用 (${allow.length} 个) ✓`
        : "插件白名单格式错误",
      fix: "设置 plugins.allow = []",
    });
  }

  const npmrcPath = join(
    process.env.HOME || process.env.USERPROFILE || "",
    ".npmrc",
  );
  let npmrcOk = false;
  if (existsSync(npmrcPath)) {
    const content = readFileSync(npmrcPath, "utf-8");
    npmrcOk = content.includes("ignore-scripts=true");
  }
  results.push({
    id: "supply-npmrc",
    domain: "供应链投毒",
    name: ".npmrc ignore-scripts",
    severity: npmrcOk ? "pass" : "warning",
    status: npmrcOk ? "pass" : "warn",
    message: npmrcOk
      ? ".npmrc ignore-scripts=true ✓"
      : ".npmrc 未设置 ignore-scripts=true",
    fix: 'echo "ignore-scripts=true" >> ~/.npmrc',
  });

  return results;
}

// ════════════════════════════════════════════════════════════
// Domain 6: Channel/PI defense
// ════════════════════════════════════════════════════════════
function checkChannelSecurity(config: any): CheckResult[] {
  const results: CheckResult[] = [];

  // Pre-check: are channels configured?
  const channels = config?.channels;
  const hasChannels =
    channels && typeof channels === "object" && Object.keys(channels).length > 0;

  if (!hasChannels) {
    results.push({
      id: "channel-owner",
      domain: "Agent 滥用",
      name: "Owner 身份限制",
      severity: "info",
      status: "n/a",
      message: "Channel 功能未配置, 无需设置 ownerAllowFrom (N/A)",
    });
    return results;
  }

  const owner = config?.commands?.ownerAllowFrom;
  const ownerSet = Array.isArray(owner) && owner.length > 0;
  results.push({
    id: "channel-owner",
    domain: "Agent 滥用",
    name: "Owner 身份限制",
    severity: ownerSet ? "pass" : "critical",
    status: ownerSet ? "pass" : "fail",
    current: ownerSet ? `${owner.length} 个 UID` : "[] (空!)",
    message: ownerSet
      ? `ownerAllowFrom 已配置 (${owner.length} UID) ✓`
      : "⚠ 已配置 Channel 但 ownerAllowFrom 为空 — PI→RCE 核心防线失效!",
    fix: '设置 commands.ownerAllowFrom = ["你的UID"]',
  });

  for (const [name, ch] of Object.entries<any>(channels)) {
    const af = ch?.allowFrom;
    const afSet = Array.isArray(af) && af.length > 0;
    results.push({
      id: `channel-${name}-allow`,
      domain: "Agent 滥用",
      name: `${name} allowFrom`,
      severity: afSet ? "pass" : "warning",
      status: afSet ? "pass" : "warn",
      current: afSet ? `${af.length} 个 UID` : "[] (空)",
      message: afSet
        ? `${name} allowFrom 已配置 ✓`
        : `${name} allowFrom 为空 — 需填入授权用户 UID`,
      fix: `设置 channels.${name}.allowFrom = ["UID"]`,
    });

    const dm = ch?.dmPolicy;
    const dmOk = dm === "disabled" || dm === "pairing";
    results.push({
      id: `channel-${name}-dm`,
      domain: "Agent 滥用",
      name: `${name} DM 策略`,
      severity: dmOk ? "pass" : "warning",
      status: dmOk ? "pass" : "warn",
      current: dm || "(未设置)",
      message: dmOk
        ? `DM 策略: ${dm} ✓`
        : "DM 策略未设置安全值",
      fix: `设置 channels.${name}.dmPolicy = "pairing"`,
    });
  }

  return results;
}

// ════════════════════════════════════════════════════════════
// Domain 7: Agent behavior
// ════════════════════════════════════════════════════════════
function checkAgentBehavior(
  config: any,
  ocDir: string,
): CheckResult[] {
  const results: CheckResult[] = [];

  // Pre-check: is agents section configured?
  const agentsSection = config?.agents;
  const sandbox = agentsSection?.defaults?.sandbox?.mode;
  const dockerAvailable = safeExec("docker --version", 5000).ok;

  if (!agentsSection) {
    results.push({
      id: "agent-sandbox",
      domain: "Agent 滥用",
      name: "容器沙箱",
      severity: "info",
      status: "n/a",
      message: "Agent 功能未配置 (N/A)",
    });
  } else {
    const sandboxOk = sandbox === "all" || sandbox === "non-main";
    if (sandboxOk && !dockerAvailable) {
      // Sandbox enabled but Docker missing → will cause fatal startup error
      results.push({
        id: "agent-sandbox",
        domain: "Agent 滥用",
        name: "容器沙箱",
        severity: "critical",
        status: "fail",
        current: sandbox,
        message: `⚠ sandbox.mode="${sandbox}" 但未检测到 Docker — Agent 启动时会报错!`,
        fix: '安装 Docker, 或设置 agents.defaults.sandbox.mode = "off" 以禁用沙箱',
      });
    } else if (sandboxOk) {
      results.push({
        id: "agent-sandbox",
        domain: "Agent 滥用",
        name: "容器沙箱",
        severity: "pass",
        status: "pass",
        current: sandbox,
        message: `沙箱模式: ${sandbox} ✓`,
      });
    } else if (!dockerAvailable) {
      // No sandbox, no Docker → can't recommend what won't work
      results.push({
        id: "agent-sandbox",
        domain: "Agent 滥用",
        name: "容器沙箱",
        severity: "info",
        status: "n/a",
        current: "Docker 不可用",
        message: "未检测到 Docker, 容器沙箱不可用 (跳过)",
      });
    } else {
      results.push({
        id: "agent-sandbox",
        domain: "Agent 滥用",
        name: "容器沙箱",
        severity: "warning",
        status: "warn",
        current: sandbox || "(未设置)",
        expected: '"all" 或 "non-main"',
        message: "未启用容器沙箱",
        fix: '设置 agents.defaults.sandbox.mode = "non-main" (需要 Docker)',
      });
    }
  }

  const agentsPath = join(ocDir, "workspace", "AGENTS.md");
  const hasAgents = existsSync(agentsPath);
  if (!hasAgents) {
    results.push({
      id: "agent-rules",
      domain: "Agent 滥用",
      name: "AGENTS.md 安全规则",
      severity: "info",
      status: "n/a",
      message: "AGENTS.md 不存在 (加分项, 部署后 +bonus)",
      fix: "部署 AGENTS.md 模板",
      category: "recommended",
    });
  } else {
    const content = readFileSync(agentsPath, "utf-8");
    const hasSecurityRules =
      content.includes("安全行为规则") ||
      content.includes("Red Line") ||
      content.includes("红线") ||
      content.includes("禁止读取工作区外的文件");
    results.push({
      id: "agent-rules",
      domain: "Agent 滥用",
      name: "AGENTS.md 安全规则",
      severity: hasSecurityRules ? "pass" : "warning",
      status: hasSecurityRules ? "pass" : "warn",
      message: hasSecurityRules
        ? "AGENTS.md 包含安全规则 ✓"
        : "AGENTS.md 存在但无安全规则",
      fix: "部署 AGENTS.md 模板",
    });
  }

  // Structural limitation checks (limit-* prefix, contributes to ceiling)
  // These represent architectural constraints that cannot be fully mitigated by config alone

  // PI defense: check for known PI defense tools
  const piDefenseTools = [
    ...(Array.isArray(config?.plugins?.allow) ? config.plugins.allow : []),
  ];
  const piPluginInstalled = piDefenseTools.some((p: string) =>
    /agent[-_]?smith|llm[-_]?guard|nemo[-_]?guardrails|prompt[-_]?guard|rebuff/i.test(String(p)),
  );
  const hasLlmGuard = (() => {
    const r = safeExec("pip show llm-guard 2>&1", 5000);
    return r.ok && r.stdout.includes("Name:");
  })();
  const piMitigated = piPluginInstalled || hasLlmGuard;

  results.push({
    id: "limit-prompt-injection",
    domain: "Agent 滥用",
    name: "Prompt Injection 防御",
    severity: piMitigated ? "pass" : "warning",
    status: piMitigated ? "pass" : "warn",
    message: piMitigated
      ? "已检测到 PI 防御措施, 天花板已解除 ✓"
      : "无专用 PI 防御工具 (Agent Smith, llm-guard 等); 依赖 AGENTS.md 规则和人工审查",
    fix: piMitigated ? undefined : "安装 PI 防护工具 (agent-smith, llm-guard, nemo-guardrails) 可解除天花板",
  });

  const hasGitTracking = existsSync(join(ocDir, ".git"));
  const pluginAllow = config?.plugins?.allow;
  const hasPluginWhitelist = Array.isArray(pluginAllow);
  const skillsPoisonOk = hasGitTracking && hasPluginWhitelist;
  results.push({
    id: "limit-skills-poison",
    domain: "Agent 滥用",
    name: "Skills/插件投毒防御",
    severity: skillsPoisonOk ? "pass" : "warning",
    status: skillsPoisonOk ? "pass" : "warn",
    current: `Git: ${hasGitTracking ? "✓" : "✗"}, 白名单: ${hasPluginWhitelist ? "✓" : "✗"}`,
    message: skillsPoisonOk
      ? "Git 追踪 + 插件白名单已启用 ✓"
      : "建议同时启用 Git 灾备追踪和插件白名单",
    fix: "启用 Git 灾备 + 设置 plugins.allow 白名单",
  });

  const sandboxForLimit = sandbox === "all" || sandbox === "non-main";
  if (sandboxForLimit && dockerAvailable) {
    results.push({
      id: "limit-model-behavior",
      domain: "Agent 滥用",
      name: "模型行为控制",
      severity: "pass",
      status: "pass",
      message: "沙箱模式已启用, 模型行为受限 ✓",
    });
  } else if (!dockerAvailable) {
    results.push({
      id: "limit-model-behavior",
      domain: "Agent 滥用",
      name: "模型行为控制",
      severity: "warning",
      status: "warn",
      message: "无沙箱隔离 (Docker 不可用); 依赖 exec.allowlist + ask 模式防护",
      fix: "安装 Docker 后可启用 agents.defaults.sandbox.mode",
    });
  } else {
    results.push({
      id: "limit-model-behavior",
      domain: "Agent 滥用",
      name: "模型行为控制",
      severity: "warning",
      status: "warn",
      message: "无沙箱隔离, 模型可直接操作宿主环境",
      fix: '设置 agents.defaults.sandbox.mode = "non-main" (需要 Docker)',
    });
  }

  return results;
}

// ════════════════════════════════════════════════════════════
// Domain 8: Monitoring & audit
// ════════════════════════════════════════════════════════════
async function checkMonitoring(ocDir: string, pf: Platform): Promise<CheckResult[]> {
  const results: CheckResult[] = [];

  // Recommended items: pass = bonus, not pass = no penalty
  const auditSh = join(
    ocDir,
    "workspace",
    "scripts",
    "nightly-security-audit.sh",
  );
  const auditPs = join(
    ocDir,
    "workspace",
    "scripts",
    "nightly-security-audit.ps1",
  );
  const hasAudit = existsSync(auditSh) || existsSync(auditPs);
  results.push({
    id: "monitor-audit",
    domain: "痕迹隐匿",
    name: "夜间审计脚本",
    severity: hasAudit ? "pass" : "info",
    status: hasAudit ? "pass" : "n/a",
    message: hasAudit ? "审计脚本已部署 ✓" : "未部署审计脚本 (加分项)",
    fix: "部署审计脚本可获得 bonus 分",
    category: "recommended",
  });

  const hasGit = existsSync(join(ocDir, ".git"));
  results.push({
    id: "monitor-git",
    domain: "痕迹隐匿",
    name: "Git 灾备",
    severity: hasGit ? "pass" : "info",
    status: hasGit ? "pass" : "n/a",
    message: hasGit ? "Git 灾备仓库存在 ✓" : "未初始化 Git 灾备 (加分项)",
    fix: `cd ${ocDir} && git init`,
    category: "recommended",
  });

  if (pf.openclawVersion) {
    const result = await safeExecAsync("openclaw security audit --deep 2>&1", 15000);
    if (result.ok) {
      const hasWarnings =
        result.stdout.includes("warn") || result.stdout.includes("critical");
      results.push({
        id: "monitor-oc-audit",
        domain: "痕迹隐匿",
        name: "OpenClaw 安全审计",
        severity: hasWarnings ? "warning" : "pass",
        status: hasWarnings ? "warn" : "pass",
        message: hasWarnings
          ? "安全审计报告有警告项"
          : "安全审计全部通过 ✓",
        current: result.stdout.slice(0, 200),
      });
    }
  }

  return results;
}

// ════════════════════════════════════════════════════════════
// Domain 9: Runtime environment
// ════════════════════════════════════════════════════════════
function checkRuntime(pf: Platform): CheckResult[] {
  const results: CheckResult[] = [];

  // Node.js version check
  const nodeVer = pf.nodeVersion?.replace("v", "") || "";
  const nodeMajor = parseInt(nodeVer.split(".")[0] || "0");
  const nodeOk = nodeMajor >= 18;
  results.push({
    id: "runtime-node",
    domain: "环境探测",
    name: "Node.js 版本",
    severity: nodeOk ? "pass" : "warning",
    status: nodeOk ? "pass" : "warn",
    current: pf.nodeVersion || "未知",
    expected: ">= 18.x",
    message: nodeOk
      ? `Node.js ${pf.nodeVersion} ✓`
      : `Node.js ${pf.nodeVersion} 版本过低, 建议升级到 18+`,
    fix: "升级 Node.js: https://nodejs.org/",
  });

  // OpenClaw version display
  if (pf.openclawVersion) {
    results.push({
      id: "runtime-openclaw",
      domain: "环境探测",
      name: "OpenClaw 版本",
      severity: "pass",
      status: "pass",
      current: pf.openclawVersion,
      message: `OpenClaw ${pf.openclawVersion} ✓`,
    });
  }

  // OS info (display only)
  results.push({
    id: "runtime-os",
    domain: "环境探测",
    name: "操作系统",
    severity: "info",
    status: "n/a",
    current: `${pf.os} ${pf.arch}`,
    message: `${pf.os} (${pf.arch})${pf.isWSL2 ? " [WSL2]" : ""}`,
  });

  return results;
}
