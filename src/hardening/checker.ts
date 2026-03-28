// ============================================================
// Security checker — 8 domains, 29 items
// Read-only: reads config, checks permissions, compares baselines
// ============================================================
import { readFileSync, existsSync, statSync } from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import type { CheckResult, Grade, Platform } from "./types.js";
import { getOpenClawDir, safeExec } from "./platform.js";

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

/** Run all security checks */
export function runAllChecks(pf: Platform): CheckResult[] {
  const ocDir = getOpenClawDir();
  const results: CheckResult[] = [];

  // Read current config
  let config: Record<string, any> = {};
  const configPath = join(ocDir, "openclaw.json");
  if (existsSync(configPath)) {
    try {
      config = JSON.parse(readFileSync(configPath, "utf-8"));
    } catch {
      /* cannot parse */
    }
  }

  // Domain 1: Network isolation
  results.push(...checkNetworkIsolation(config, pf));
  // Domain 2: Authentication
  results.push(...checkAuthentication(config));
  // Domain 3: Exec security
  results.push(...checkExecSecurity(config));
  // Domain 4: Filesystem security
  results.push(...checkFileSystem(ocDir, pf));
  // Domain 5: Supply chain security
  results.push(...checkSupplyChain(config));
  // Domain 6: Channel/PI defense
  results.push(...checkChannelSecurity(config));
  // Domain 7: Agent behavior
  results.push(...checkAgentBehavior(config, ocDir));
  // Domain 8: Monitoring & audit
  results.push(...checkMonitoring(ocDir, pf));

  return results;
}

/** Generate check report summary */
export function generateSummary(checks: CheckResult[]) {
  const total = checks.length;
  const pass = checks.filter((c) => c.status === "pass").length;
  const fail = checks.filter((c) => c.status === "fail").length;
  const warn = checks.filter((c) => c.status === "warn").length;
  const skip = checks.filter((c) => c.status === "skip").length;
  const na = checks.filter((c) => c.status === "n/a").length;

  // Score: pass=100%, warn=50%, fail=0%, skip/n/a=not counted
  const scored = total - skip - na;
  let score =
    scored > 0 ? Math.round(((pass + warn * 0.5) / scored) * 100) : 100;

  // Critical FAIL penalty: cap at 59
  const hasCriticalFail = checks.some(
    (c) => c.status === "fail" && c.severity === "critical",
  );
  if (hasCriticalFail && score > 59) {
    score = 59;
  }

  // Grade calculation
  const grade: Grade =
    score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";

  return { total, pass, fail, warn, skip, na, score, grade, hasCriticalFail };
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
    domain: "网络隔离",
    name: "Gateway 绑定地址",
    severity: bindDangerous ? "critical" : (bindOk || bindTailnet) ? "pass" : "warning",
    status: bindDangerous ? "fail" : (bindOk || bindTailnet) ? "pass" : "warn",
    current: bind || "(未设置)",
    expected: "loopback",
    message: bindOk
      ? "仅监听本地回环 ✓"
      : bindTailnet
        ? "Tailnet 绑定 (VPN 隔离网络) ✓"
        : bindDangerous
          ? `当前绑定 "${bind}" — 可能暴露到网络!`
          : `当前绑定 "${bind}" — 建议设为 loopback`,
    fix: '设置 gateway.bind = "loopback"',
  });

  const proxies = config?.gateway?.trustedProxies;
  const proxyOk = Array.isArray(proxies) && proxies.length === 0;
  results.push({
    id: "net-proxies",
    domain: "网络隔离",
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
    domain: "网络隔离",
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
      domain: "网络隔离",
      name: "WSL2 端口转发风险",
      severity: "warning",
      status: "warn",
      message: "WSL2 环境: bind=loopback 可能被 Windows portproxy 穿透",
      fix: "在 Windows 执行: netsh interface portproxy show all",
    });
  }

  return results;
}

// ════════════════════════════════════════════════════════════
// Domain 2: Authentication
// ════════════════════════════════════════════════════════════
function checkAuthentication(config: any): CheckResult[] {
  const results: CheckResult[] = [];
  const auth = config?.gateway?.auth;

  const mode = auth?.mode;
  results.push({
    id: "auth-mode",
    domain: "认证",
    name: "认证模式",
    severity: mode === "token" ? "pass" : "critical",
    status: mode === "token" || mode === "password" ? "pass" : "fail",
    current: mode || "(未设置)",
    expected: "token",
    message:
      mode === "none"
        ? "⚠ 无认证 — 任何人可直接控制!"
        : `认证模式: ${mode} ✓`,
    fix: '设置 gateway.auth.mode = "token"',
  });

  const token = auth?.token;
  const isSecretRef =
    token && typeof token === "object" && token.source === "env";
  results.push({
    id: "auth-token-ref",
    domain: "认证",
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
    domain: "认证",
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

  const insecure = config?.gateway?.controlUi?.allowInsecureAuth;
  results.push({
    id: "auth-insecure",
    domain: "认证",
    name: "禁止 HTTP 明文认证",
    severity: insecure === false ? "pass" : "critical",
    status: insecure === false ? "pass" : "fail",
    current: String(insecure ?? "(未设置)"),
    expected: "false",
    message: insecure
      ? "⚠ HTTP 明文认证已启用!"
      : "禁止 HTTP 明文认证 ✓",
    fix: "设置 controlUi.allowInsecureAuth = false",
  });

  const noDevAuth =
    config?.gateway?.controlUi?.dangerouslyDisableDeviceAuth;
  results.push({
    id: "auth-device",
    domain: "认证",
    name: "设备认证",
    severity: noDevAuth === false ? "pass" : "critical",
    status: noDevAuth === false ? "pass" : "fail",
    current: String(noDevAuth ?? "(未设置)"),
    expected: "false",
    message: noDevAuth ? "⚠ 设备认证已禁用!" : "设备认证启用 ✓",
    fix: "设置 controlUi.dangerouslyDisableDeviceAuth = false",
  });

  return results;
}

// ════════════════════════════════════════════════════════════
// Domain 3: Exec security
// ════════════════════════════════════════════════════════════
function checkExecSecurity(config: any): CheckResult[] {
  const results: CheckResult[] = [];
  const exec = config?.tools?.exec;

  const security = exec?.security;
  results.push({
    id: "exec-security",
    domain: "执行安全",
    name: "命令执行策略",
    severity: security === "allowlist" ? "pass" : "critical",
    status: security === "allowlist" ? "pass" : "fail",
    current: security || "(未设置)",
    expected: "allowlist",
    message:
      security === "allowlist"
        ? "白名单模式 ✓"
        : "⚠ 非白名单模式 — AI 可执行任意命令!",
    fix: '设置 tools.exec.security = "allowlist"',
  });

  const ask = exec?.ask;
  const askOk = ask === "always" || ask === "on-miss";
  results.push({
    id: "exec-ask",
    domain: "执行安全",
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
    domain: "执行安全",
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

  const wsOnly = config?.tools?.fs?.workspaceOnly;
  results.push({
    id: "exec-workspace",
    domain: "执行安全",
    name: "文件操作工作区限制",
    severity: wsOnly === true ? "pass" : "critical",
    status: wsOnly === true ? "pass" : "fail",
    current: String(wsOnly ?? "(未设置)"),
    expected: "true",
    message: wsOnly
      ? "工作区限制 ✓"
      : "⚠ 文件操作未限制在工作区!",
    fix: "设置 tools.fs.workspaceOnly = true",
  });

  const patchWs = exec?.applyPatch?.workspaceOnly;
  results.push({
    id: "exec-patch",
    domain: "执行安全",
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

  const csrfFlag =
    config?.gateway?.controlUi
      ?.dangerouslyAllowHostHeaderOriginFallback;
  results.push({
    id: "exec-csrf",
    domain: "执行安全",
    name: "CSRF/WS 劫持防护",
    severity: csrfFlag === false ? "pass" : "critical",
    status: csrfFlag === false ? "pass" : "fail",
    current: String(csrfFlag ?? "(未设置)"),
    expected: "false",
    message: csrfFlag
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
        domain: "文件系统",
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
        domain: "文件系统",
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
    results.push({
      id: "fs-perm-win",
      domain: "文件系统",
      name: "文件权限 (Windows)",
      severity: "info",
      status: "skip",
      message: "Windows 使用 NTFS ACL, 请通过 icacls 检查",
    });
  }

  const baselinePath = join(ocDir, ".config-baseline.sha256");
  const baselineJsonPath = join(ocDir, ".config-baseline.json");
  const hasBaseline =
    existsSync(baselinePath) || existsSync(baselineJsonPath);
  results.push({
    id: "fs-baseline",
    domain: "文件系统",
    name: "配置哈希基线",
    severity: hasBaseline ? "pass" : "warning",
    status: hasBaseline ? "pass" : "warn",
    message: hasBaseline ? "哈希基线存在 ✓" : "未找到哈希基线文件",
    fix: "运行部署脚本生成基线",
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
          domain: "文件系统",
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
      domain: "供应链",
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
      domain: "供应链",
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
    domain: "供应链",
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
      domain: "代理行为",
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
    domain: "代理行为",
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
      domain: "代理行为",
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
      domain: "代理行为",
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
  if (!agentsSection) {
    results.push({
      id: "agent-sandbox",
      domain: "代理行为",
      name: "容器沙箱",
      severity: "info",
      status: "n/a",
      message: "Agent 功能未配置 (N/A)",
    });
  } else {
    const sandboxOk = sandbox === "all" || sandbox === "non-main";
    results.push({
      id: "agent-sandbox",
      domain: "代理行为",
      name: "容器沙箱",
      severity: sandboxOk ? "pass" : "warning",
      status: sandboxOk ? "pass" : "warn",
      current: sandbox || "(未设置)",
      expected: '"all" 或 "non-main"',
      message: sandboxOk
        ? `沙箱模式: ${sandbox} ✓`
        : "未启用容器沙箱",
      fix: '设置 agents.defaults.sandbox.mode = "non-main"',
    });
  }

  const agentsPath = join(ocDir, "workspace", "AGENTS.md");
  const hasAgents = existsSync(agentsPath);
  if (!hasAgents) {
    results.push({
      id: "agent-rules",
      domain: "代理行为",
      name: "AGENTS.md 安全规则",
      severity: "info",
      status: "n/a",
      message: "AGENTS.md 不存在 (建议创建并添加安全规则)",
      fix: "部署 AGENTS.md 模板",
      category: "recommended",
    });
  } else {
    const content = readFileSync(agentsPath, "utf-8");
    const hasSecurityRules =
      content.includes("安全行为规则") ||
      content.includes("Red Line") ||
      content.includes("红线");
    results.push({
      id: "agent-rules",
      domain: "代理行为",
      name: "AGENTS.md 安全规则",
      severity: hasSecurityRules ? "pass" : "warning",
      status: hasSecurityRules ? "pass" : "warn",
      message: hasSecurityRules
        ? "AGENTS.md 包含安全规则 ✓"
        : "AGENTS.md 存在但无安全规则",
      fix: "部署 AGENTS.md 模板",
    });
  }

  return results;
}

// ════════════════════════════════════════════════════════════
// Domain 8: Monitoring & audit
// ════════════════════════════════════════════════════════════
function checkMonitoring(ocDir: string, pf: Platform): CheckResult[] {
  const results: CheckResult[] = [];

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
    domain: "监控",
    name: "夜间审计脚本",
    severity: hasAudit ? "pass" : "warning",
    status: hasAudit ? "pass" : "warn",
    message: hasAudit ? "审计脚本已部署 ✓" : "未找到审计脚本",
    fix: "运行部署脚本部署审计脚本",
    category: "recommended",
  });

  const hasGit = existsSync(join(ocDir, ".git"));
  results.push({
    id: "monitor-git",
    domain: "监控",
    name: "Git 灾备",
    severity: hasGit ? "pass" : "warning",
    status: hasGit ? "pass" : "warn",
    message: hasGit ? "Git 灾备仓库存在 ✓" : "未初始化 Git 灾备",
    fix: `cd ${ocDir} && git init`,
    category: "recommended",
  });

  if (pf.openclawVersion) {
    const result = safeExec("openclaw security audit --deep 2>&1", 15000);
    if (result.ok) {
      const hasWarnings =
        result.stdout.includes("warn") || result.stdout.includes("critical");
      results.push({
        id: "monitor-oc-audit",
        domain: "监控",
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
