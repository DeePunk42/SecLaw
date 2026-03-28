// ============================================================
// Hardening executor — performs actual hardening operations
// ⚠️ High privilege: modifies files, permissions, config
// ============================================================
import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
  copyFileSync,
  chmodSync,
} from "node:fs";
import { join, dirname } from "node:path";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import type { HardenResult, Platform } from "./types.js";
import { getOpenClawDir, safeExec } from "./platform.js";

// ──────────────── Template directory resolution ────────────────

/** Get the SecLaw package root directory */
function getPackageRoot(): string {
  try {
    // src/hardening/hardener.ts → ../../ = extensions/seclaw/
    const resolved = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
    // When running from dist/src/hardening/, ../../ lands on dist/ — go up one more
    if (resolved.endsWith("/dist") || resolved.endsWith("\\dist")) {
      return dirname(resolved);
    }
    return resolved;
  } catch {
    return join(__dirname, "..", "..");
  }
}

/** Get config templates directory */
function getConfigDir(): string {
  return join(getPackageRoot(), "configs");
}

/** Get templates directory */
function getTemplatesDir(): string {
  return join(getPackageRoot(), "templates");
}

/** Get scripts directory */
function getScriptsDir(): string {
  return join(getPackageRoot(), "scripts");
}

// Default AGENTS.md security rules (fallback if template not found)
const DEFAULT_AGENTS_RULES = `# 安全行为规则

## 🔴 红线 (绝对禁止)
- 禁止读取工作区外的文件 (尤其 ~/.ssh, /etc/shadow, 环境变量)
- 禁止执行 rm -rf, chmod 777 等破坏性命令
- 禁止将 Token、密钥、凭证等明文输出或发送到外部
- 禁止在未经用户确认的情况下安装 npm/pip 包
- 禁止主动发起网络请求传输用户数据

## 🟡 黄线 (需要确认)
- 修改配置文件前必须告知用户
- 安装依赖前必须说明包名和来源
- 涉及网络请求时必须说明目标 URL 和目的

## ✅ 绿线 (鼓励)
- 主动检查命令安全性
- 对可疑输入进行转义处理
- 使用 SHA256 校验下载的文件
`;

// ════════════════════════════════════════════════════════════
// Hardening operations
// ════════════════════════════════════════════════════════════

/** Backup current configuration */
export function backupConfig(): HardenResult {
  const ocDir = getOpenClawDir();
  const timestamp = new Date()
    .toISOString()
    .replace(/[:.]/g, "-")
    .slice(0, 19);
  const backupDir = join(ocDir, ".backups", timestamp);

  try {
    mkdirSync(backupDir, { recursive: true });

    const filesToBackup = ["openclaw.json", join("workspace", "AGENTS.md")];
    for (const rel of filesToBackup) {
      const src = join(ocDir, rel);
      if (existsSync(src)) {
        const dst = join(backupDir, rel.replace(/[\\/]/g, "_"));
        copyFileSync(src, dst);
      }
    }

    return {
      id: "backup",
      name: "创建备份",
      success: true,
      changed: true,
      message: `备份已保存到 ${backupDir}`,
      rollback: `cp ${backupDir}/* ${ocDir}/`,
    };
  } catch (err: any) {
    return {
      id: "backup",
      name: "创建备份",
      success: false,
      changed: false,
      message: `备份失败: ${err.message}`,
    };
  }
}

/** Deploy security configuration (merge mode) */
export function deployConfig(
  mode: "paranoid" | "balanced",
): HardenResult {
  const ocDir = getOpenClawDir();
  const configPath = join(ocDir, "openclaw.json");
  const templatePath = join(getConfigDir(), `${mode}-mode.json`);

  if (!existsSync(templatePath)) {
    return {
      id: "deploy-config",
      name: "部署配置",
      success: false,
      changed: false,
      message: `模板不存在: ${templatePath}`,
    };
  }

  try {
    const template = JSON.parse(readFileSync(templatePath, "utf-8"));

    if (existsSync(configPath)) {
      const existing = JSON.parse(readFileSync(configPath, "utf-8"));

      const merged: any = {
        ...existing,
        gateway: {
          ...(existing.gateway || {}),
          bind: template.gateway.bind,
          controlUi: template.gateway.controlUi,
          auth: {
            ...(existing.gateway?.auth || {}),
            ...template.gateway.auth,
          },
          trustedProxies: template.gateway.trustedProxies,
        },
        tools: template.tools,
        plugins: template.plugins,
        agents: template.agents,
        discovery: template.discovery,
        commands: {
          ...(existing.commands || {}),
          ...(template.commands || {}),
        },
      };

      // Preserve user UIDs in channels (don't overwrite allowFrom)
      if (existing.channels) {
        merged.channels = existing.channels;
        for (const [ch, chConf] of Object.entries<any>(
          template.channels || {},
        )) {
          if (merged.channels[ch]) {
            merged.channels[ch].dmPolicy = chConf.dmPolicy;
          }
        }
      } else {
        merged.channels = template.channels;
      }

      writeFileSync(configPath, JSON.stringify(merged, null, 2), "utf-8");
      return {
        id: "deploy-config",
        name: "部署配置",
        success: true,
        changed: true,
        message: `配置已合并 (${mode} 模式) — ⚠ tools/plugins/agents/discovery 已被替换`,
        rollback:
          "cp ~/.openclaw/.backups/最新/openclaw.json ~/.openclaw/openclaw.json",
      };
    } else {
      writeFileSync(configPath, readFileSync(templatePath, "utf-8"));
      return {
        id: "deploy-config",
        name: "部署配置",
        success: true,
        changed: true,
        message: `配置已部署 (${mode} 模式)`,
      };
    }
  } catch (err: any) {
    return {
      id: "deploy-config",
      name: "部署配置",
      success: false,
      changed: false,
      message: `部署失败: ${err.message}`,
    };
  }
}

/** File permission hardening */
export function hardenPermissions(pf: Platform): HardenResult {
  const ocDir = getOpenClawDir();

  if (pf.os === "win32") {
    const user = process.env.USERNAME || "SYSTEM";
    try {
      safeExec(`icacls "${ocDir}" /inheritance:r`);
      safeExec(`icacls "${ocDir}" /grant:r "${user}:(OI)(CI)F"`);
      safeExec(`icacls "${ocDir}" /grant:r "SYSTEM:(OI)(CI)F"`);
      safeExec(`icacls "${ocDir}" /grant:r "BUILTIN\\Administrators:(OI)(CI)F"`);
      return {
        id: "file-permissions",
        name: "文件权限加固",
        success: true,
        changed: true,
        message: `NTFS ACL 已加固: 仅 ${user}, Administrators 和 SYSTEM 有权访问`,
      };
    } catch (err: any) {
      return {
        id: "file-permissions",
        name: "文件权限加固",
        success: false,
        changed: false,
        message: `权限设置失败: ${err.message}`,
      };
    }
  } else {
    try {
      chmodSync(ocDir, 0o700);
      const configPath = join(ocDir, "openclaw.json");
      if (existsSync(configPath)) chmodSync(configPath, 0o600);
      const pairedPath = join(ocDir, "devices", "paired.json");
      if (existsSync(pairedPath)) chmodSync(pairedPath, 0o600);

      return {
        id: "file-permissions",
        name: "文件权限加固",
        success: true,
        changed: true,
        message: "目录 700, 配置 600 ✓",
        rollback: `chmod 755 ${ocDir}; chmod 644 ${join(ocDir, "openclaw.json")}`,
      };
    } catch (err: any) {
      return {
        id: "file-permissions",
        name: "文件权限加固",
        success: false,
        changed: false,
        message: `权限设置失败: ${err.message}`,
      };
    }
  }
}

/** Generate hash baseline */
export function generateBaseline(): HardenResult {
  const ocDir = getOpenClawDir();
  const baselinePath = join(ocDir, ".config-baseline.json");

  try {
    const hashes: Record<string, string> = {};
    const files = ["openclaw.json", join("workspace", "AGENTS.md")];

    for (const rel of files) {
      const fullPath = join(ocDir, rel);
      if (existsSync(fullPath)) {
        const content = readFileSync(fullPath);
        hashes[rel] = createHash("sha256").update(content).digest("hex");
      }
    }

    writeFileSync(baselinePath, JSON.stringify(hashes, null, 2), "utf-8");

    return {
      id: "hash-baseline",
      name: "哈希基线",
      success: true,
      changed: true,
      message: `基线已生成: ${Object.keys(hashes).length} 个文件`,
      rollback: `rm ${baselinePath}`,
    };
  } catch (err: any) {
    return {
      id: "hash-baseline",
      name: "哈希基线",
      success: false,
      changed: false,
      message: `基线生成失败: ${err.message}`,
    };
  }
}

/** Set .npmrc ignore-scripts */
export function hardenNpmrc(): HardenResult {
  const npmrcPath = join(
    process.env.HOME || process.env.USERPROFILE || "",
    ".npmrc",
  );

  try {
    if (existsSync(npmrcPath)) {
      const content = readFileSync(npmrcPath, "utf-8");
      if (content.includes("ignore-scripts=true")) {
        return {
          id: "npmrc",
          name: ".npmrc 加固",
          success: true,
          changed: false,
          message: "ignore-scripts=true 已存在 ✓",
        };
      }
      writeFileSync(
        npmrcPath,
        content + "\nignore-scripts=true\n",
        "utf-8",
      );
    } else {
      writeFileSync(npmrcPath, "ignore-scripts=true\n", "utf-8");
    }

    return {
      id: "npmrc",
      name: ".npmrc 加固",
      success: true,
      changed: true,
      message: "已添加 ignore-scripts=true",
      rollback: `编辑 ${npmrcPath} 移除该行`,
    };
  } catch (err: any) {
    return {
      id: "npmrc",
      name: ".npmrc 加固",
      success: false,
      changed: false,
      message: `设置失败: ${err.message}`,
    };
  }
}

/** Initialize Git disaster recovery */
export function initGitBackup(): HardenResult {
  const ocDir = getOpenClawDir();
  const gitDir = join(ocDir, ".git");

  if (existsSync(gitDir)) {
    const result = safeExec(
      `cd "${ocDir}" && git add -A && git commit -m "Security snapshot - ${new Date().toISOString()}"`,
    );
    return {
      id: "git-backup",
      name: "Git 灾备",
      success: true,
      changed: result.ok,
      message: result.ok
        ? "已创建安全快照 ✓"
        : "Git 仓库已存在 (无新变更)",
    };
  }

  try {
    safeExec(`cd "${ocDir}" && git init -q`);

    const gitignore = [
      "devices/*.tmp",
      "media/",
      "logs/",
      "completions/",
      "canvas/",
      "*.bak*",
      "*.tmp",
      "node_modules/",
      ".backups/",
    ].join("\n");
    writeFileSync(join(ocDir, ".gitignore"), gitignore, "utf-8");

    safeExec(
      `cd "${ocDir}" && git add -A && git commit -q -m "Initial security baseline"`,
    );

    return {
      id: "git-backup",
      name: "Git 灾备",
      success: true,
      changed: true,
      message: "Git 灾备仓库已初始化 ✓",
      rollback: `rm -rf ${gitDir}`,
    };
  } catch (err: any) {
    return {
      id: "git-backup",
      name: "Git 灾备",
      success: false,
      changed: false,
      message: `Git 初始化失败: ${err.message}`,
    };
  }
}

/** Run schema validation */
export function runSchemaValidation(): HardenResult {
  const result = safeExec("openclaw config validate", 15000);
  return {
    id: "schema-validate",
    name: "Schema 校验",
    success: result.ok,
    changed: false,
    message: result.ok
      ? "Schema 校验通过 ✓"
      : `校验失败: ${result.stderr || result.stdout}`,
  };
}

/** Run security audit */
export function runSecurityAudit(): HardenResult {
  const result = safeExec("openclaw security audit --deep", 30000);
  return {
    id: "security-audit",
    name: "安全审计",
    success: result.ok,
    changed: false,
    message: result.ok
      ? `审计完成:\n${result.stdout.slice(0, 500)}`
      : `审计失败: ${result.stderr || "openclaw CLI 不可用"}`,
  };
}

/** Channel UID configuration hint (output only, no modifications) */
export function deployChannelHint(): HardenResult {
  // Pre-check: are channels configured?
  const ocDir = getOpenClawDir();
  const configPath = join(ocDir, "openclaw.json");
  let hasChannels = false;
  if (existsSync(configPath)) {
    try {
      const config = JSON.parse(readFileSync(configPath, "utf-8"));
      hasChannels =
        config?.channels &&
        typeof config.channels === "object" &&
        Object.keys(config.channels).length > 0;
    } catch {
      /* ignore */
    }
  }

  if (!hasChannels) {
    return {
      id: "deploy-channel",
      name: "Channel UID 配置提示",
      success: true,
      changed: false,
      message:
        "Channel 功能未配置, 无需设置 UID (如需使用 Telegram/Discord Channel, 请先在 openclaw.json 中配置 channels 块)",
    };
  }

  const lines = [
    "以下配置需手动完成 (涉及个人 UID, 脚本无法自动填入):",
    "",
    "  commands.ownerAllowFrom — 填入你的 Telegram/Discord UID",
    "  channels.*.allowFrom   — 填入允许交互的用户 UID",
    '  channels.*.dmPolicy    — Paranoid: "disabled", Balanced: "pairing"',
    "",
    "操作方法:",
    "  1. 在对应平台查看你的 UID (Telegram: @userinfobot, Discord: 开发者模式)",
    "  2. 编辑 ~/.openclaw/openclaw.json 填入 UID",
    "  3. 运行 openclaw config validate 确认",
  ];
  return {
    id: "deploy-channel",
    name: "Channel UID 配置提示",
    success: true,
    changed: false,
    message: lines.join("\n"),
  };
}

/** Deploy AGENTS.md security rules */
export function deployAgents(): HardenResult {
  const ocDir = getOpenClawDir();
  const src = join(getTemplatesDir(), "AGENTS.md");
  const dstDir = join(ocDir, "workspace");
  const dst = join(dstDir, "AGENTS.md");

  try {
    mkdirSync(dstDir, { recursive: true });

    if (existsSync(dst)) {
      const content = readFileSync(dst, "utf-8");
      if (
        content.includes("安全行为规则") ||
        content.includes("Red Line") ||
        content.includes("红线")
      ) {
        return {
          id: "deploy-agents",
          name: "部署 AGENTS.md",
          success: true,
          changed: false,
          message: "AGENTS.md 已包含安全规则 (跳过)",
        };
      }
      const rulesContent = existsSync(src)
        ? readFileSync(src, "utf-8")
        : DEFAULT_AGENTS_RULES;
      writeFileSync(dst, content + "\n" + rulesContent, "utf-8");
      return {
        id: "deploy-agents",
        name: "部署 AGENTS.md",
        success: true,
        changed: true,
        message: "安全规则已追加到现有 AGENTS.md",
      };
    }

    const rulesContent = existsSync(src)
      ? readFileSync(src, "utf-8")
      : DEFAULT_AGENTS_RULES;
    writeFileSync(dst, rulesContent, "utf-8");
    return {
      id: "deploy-agents",
      name: "部署 AGENTS.md",
      success: true,
      changed: true,
      message: "已部署 AGENTS.md 安全规则模板",
    };
  } catch (err: any) {
    return {
      id: "deploy-agents",
      name: "部署 AGENTS.md",
      success: false,
      changed: false,
      message: `部署失败: ${err.message}`,
    };
  }
}

/** Immutable protection for audit script — HIGH RISK */
export function immutableProtect(pf: Platform): HardenResult {
  const ocDir = getOpenClawDir();
  const target = join(
    ocDir,
    "workspace",
    "scripts",
    "nightly-security-audit.sh",
  );

  if (!existsSync(target)) {
    return {
      id: "immutable-protect",
      name: "不可变保护",
      success: false,
      changed: false,
      message: "审计脚本不存在, 请先执行审计脚本部署",
    };
  }

  if (pf.os === "win32") {
    const result = safeExec(`icacls "${target}" /deny Everyone:(W)`);
    return {
      id: "immutable-protect",
      name: "不可变保护",
      success: result.ok,
      changed: result.ok,
      message: result.ok
        ? "NTFS Deny Write 已设置 ✓"
        : `设置失败: ${result.stderr}`,
      rollback: `icacls "${target}" /remove:d Everyone`,
    };
  }

  if (pf.os === "darwin") {
    const result = safeExec(`sudo chflags uchg "${target}"`);
    return {
      id: "immutable-protect",
      name: "不可变保护",
      success: result.ok,
      changed: result.ok,
      message: result.ok
        ? "chflags uchg 已设置 ✓"
        : `设置失败: ${result.stderr}`,
      rollback: `sudo chflags nouchg "${target}"`,
    };
  }

  if (pf.isWSL2) {
    return {
      id: "immutable-protect",
      name: "不可变保护",
      success: true,
      changed: false,
      message: [
        "WSL2: chattr +i 在 NTFS 挂载点无效",
        `  ext4 路径可执行: sudo chattr +i ${target}`,
        "  NTFS 路径请在 Windows 侧设置 icacls",
      ].join("\n"),
    };
  }

  const result = safeExec(`sudo chattr +i "${target}"`);
  return {
    id: "immutable-protect",
    name: "不可变保护",
    success: result.ok,
    changed: result.ok,
    message: result.ok
      ? "chattr +i 已设置 ✓"
      : `设置失败: ${result.stderr}`,
    rollback: `sudo chattr -i "${target}"`,
  };
}

/** Firewall rules configuration — HIGH RISK */
export function configureFirewall(pf: Platform): HardenResult {
  const port = 18789;

  if (pf.os === "win32") {
    const r1 = safeExec(
      `netsh advfirewall firewall add rule name="Block OpenClaw External" dir=in action=block protocol=tcp localport=${port}`,
    );
    const r2 = safeExec(
      `netsh advfirewall firewall add rule name="Allow OpenClaw Loopback" dir=in action=allow protocol=tcp localport=${port} remoteip=127.0.0.1`,
    );
    return {
      id: "firewall",
      name: "防火墙规则",
      success: r1.ok && r2.ok,
      changed: r1.ok,
      message: r1.ok
        ? `Windows Firewall: 端口 ${port} 仅允许本地访问 ✓`
        : `配置失败: ${r1.stderr}`,
      rollback: `netsh advfirewall firewall delete rule name="Block OpenClaw External";\nnetsh advfirewall firewall delete rule name="Allow OpenClaw Loopback"`,
    };
  }

  if (pf.isWSL2) {
    return {
      id: "firewall",
      name: "防火墙规则",
      success: true,
      changed: false,
      message: [
        "WSL2: 防火墙规则需在 Windows 宿主侧配置",
        "请在 PowerShell (管理员) 中执行:",
        `  New-NetFirewallRule -DisplayName "Block OpenClaw External" -Direction Inbound -Protocol TCP -LocalPort ${port} -Action Block`,
        `  New-NetFirewallRule -DisplayName "Allow OpenClaw Loopback" -Direction Inbound -Protocol TCP -LocalPort ${port} -RemoteAddress 127.0.0.1 -Action Allow`,
      ].join("\n"),
    };
  }

  if (pf.os === "darwin") {
    return {
      id: "firewall",
      name: "防火墙规则",
      success: true,
      changed: false,
      message: [
        "macOS: 防火墙需手动配置 /etc/pf.conf",
        `  添加规则: block in proto tcp from any to any port ${port}`,
        "  执行: sudo pfctl -f /etc/pf.conf && sudo pfctl -e",
      ].join("\n"),
    };
  }

  // Linux: try ufw then iptables
  const ufw = safeExec("which ufw");
  if (ufw.ok) {
    const result = safeExec(`sudo ufw deny ${port}/tcp`);
    return {
      id: "firewall",
      name: "防火墙规则",
      success: result.ok,
      changed: result.ok,
      message: result.ok
        ? `ufw: 已阻止外部访问端口 ${port} ✓`
        : `ufw 配置失败: ${result.stderr}`,
      rollback: `sudo ufw delete deny ${port}/tcp`,
    };
  }

  const ipt = safeExec("which iptables");
  if (ipt.ok) {
    safeExec(
      `sudo iptables -A INPUT -p tcp --dport ${port} -s 127.0.0.1 -j ACCEPT`,
    );
    const result = safeExec(
      `sudo iptables -A INPUT -p tcp --dport ${port} -j DROP`,
    );
    return {
      id: "firewall",
      name: "防火墙规则",
      success: result.ok,
      changed: result.ok,
      message: result.ok
        ? "iptables: 规则已添加 ✓"
        : `iptables 配置失败: ${result.stderr}`,
      rollback: `sudo iptables -D INPUT -p tcp --dport ${port} -j DROP`,
    };
  }

  return {
    id: "firewall",
    name: "防火墙规则",
    success: false,
    changed: false,
    message: "未检测到 ufw/iptables, 请手动配置防火墙",
  };
}

/** Disk encryption detection (read-only) */
export function checkDiskEncryption(pf: Platform): HardenResult {
  if (pf.os === "win32") {
    const result = safeExec("manage-bde -status C:");
    const encrypted = result.ok && result.stdout.includes("Protection On");
    return {
      id: "disk-encryption",
      name: "磁盘加密检测",
      success: true,
      changed: false,
      message: encrypted
        ? "BitLocker 已启用 ✓"
        : "BitLocker 未启用或无法检测。建议在系统设置中启用",
    };
  }

  if (pf.isWSL2) {
    return {
      id: "disk-encryption",
      name: "磁盘加密检测",
      success: true,
      changed: false,
      message:
        "WSL2: 磁盘加密取决于 Windows BitLocker\n  请在 Windows 上检查: manage-bde -status C:",
    };
  }

  if (pf.os === "darwin") {
    const result = safeExec("fdesetup status");
    const encrypted =
      result.ok && result.stdout.toLowerCase().includes("on");
    return {
      id: "disk-encryption",
      name: "磁盘加密检测",
      success: true,
      changed: false,
      message: encrypted
        ? "FileVault 已启用 ✓"
        : "FileVault 未启用。建议在系统设置中启用",
    };
  }

  const result = safeExec("lsblk -f 2>/dev/null");
  const encrypted = result.ok && /crypt|luks/i.test(result.stdout);
  return {
    id: "disk-encryption",
    name: "磁盘加密检测",
    success: true,
    changed: false,
    message: encrypted
      ? "检测到磁盘加密已启用 ✓"
      : "未检测到磁盘加密。建议启用 LUKS",
  };
}

/** Deploy nightly audit script */
export function deployAuditScript(): HardenResult {
  const ocDir = getOpenClawDir();
  const src = join(getScriptsDir(), "nightly-security-audit.sh");
  const dstDir = join(ocDir, "workspace", "scripts");
  const dst = join(dstDir, "nightly-security-audit.sh");

  try {
    mkdirSync(dstDir, { recursive: true });

    if (existsSync(src)) {
      copyFileSync(src, dst);
      try {
        chmodSync(dst, 0o700);
      } catch {
        /* Windows noop */
      }
      return {
        id: "deploy-audit",
        name: "部署审计脚本",
        success: true,
        changed: true,
        message: `审计脚本已部署: ${dst}`,
      };
    }

    return {
      id: "deploy-audit",
      name: "部署审计脚本",
      success: false,
      changed: false,
      message: `审计脚本模板不存在: ${src}`,
    };
  } catch (err: any) {
    return {
      id: "deploy-audit",
      name: "部署审计脚本",
      success: false,
      changed: false,
      message: `部署失败: ${err.message}`,
    };
  }
}

/** Cron deployment verification hint (output only) */
export function deployVerifyHint(): HardenResult {
  const lines = [
    "部署审计 Cron 后, 必须手动验证整条管线:",
    "",
    "  1) 手动触发: openclaw cron run <jobId>",
    "  2) 查看状态: openclaw cron runs --id <jobId>",
    "  3) 确认清单:",
    '     ✓ status ≠ "error"',
    '     ✓ deliveryStatus = "delivered"',
    "     ✓ 收到推送消息 (Telegram/Discord)",
    "     ✓ /tmp/openclaw/security-reports/ 有报告文件",
    "",
    "  如果使用 --tz 参数, 确认时区正确",
    "  如果使用 --message, 确认模板渲染正常",
  ];
  return {
    id: "deploy-verify-hint",
    name: "Cron 验证提示",
    success: true,
    changed: false,
    message: lines.join("\n"),
  };
}
