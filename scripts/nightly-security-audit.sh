#!/usr/bin/env bash
# ============================================================
# OpenClaw 夜间安全审计脚本 (Linux / macOS)
# 版本: 1.0
# 用途: 自动化执行 13 项安全审计指标，生成审计报告
# 调度: cron "0 3 * * *" 或 openclaw cron
# ============================================================
set -uo pipefail

# ──────────────────── 配置 ────────────────────
OC="${HOME}/.openclaw"
REPORT_DIR="${OC}/workspace/security-reports"
TIMESTAMP=$(date +%Y-%m-%d_%H%M%S)
REPORT_FILE="${REPORT_DIR}/audit-${TIMESTAMP}.md"

# 检测平台
case "$(uname -s)" in
    Linux*)  OS="linux" ;;
    Darwin*) OS="macos" ;;
    *)       OS="unknown" ;;
esac

if [[ "$OS" == "linux" ]]; then
    HASH_CMD="sha256sum"
    HASH_CHECK="sha256sum -c"
else
    HASH_CMD="shasum -a 256"
    HASH_CHECK="shasum -a 256 -c"
fi

mkdir -p "$REPORT_DIR"

# ──────────────────── 报告输出 ────────────────────
PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

report() {
    echo "$1" >> "$REPORT_FILE"
}

report_pass() {
    report "✅ **PASS** | $1"
    ((PASS_COUNT++))
}

report_warn() {
    report "⚠️ **WARN** | $1"
    ((WARN_COUNT++))
}

report_fail() {
    report "🚨 **FAIL** | $1"
    ((FAIL_COUNT++))
}

# ──────────────────── 报告头 ────────────────────
report "# OpenClaw 安全审计报告"
report ""
report "- **时间**: $(date '+%Y-%m-%d %H:%M:%S %Z')"
report "- **主机**: $(hostname)"
report "- **系统**: $(uname -srm)"
report "- **用户**: $(whoami)"
report ""
report "---"
report ""

# ══════════════════════════════════════════════════
# 指标 1: OpenClaw 安全审计
# ══════════════════════════════════════════════════
report "## 指标 1: OpenClaw 内置安全审计"
report ""

if command -v openclaw &>/dev/null; then
    AUDIT_OUTPUT=$(openclaw security audit --deep 2>&1 || true)
    if echo "$AUDIT_OUTPUT" | grep -qi "critical\|severe\|error"; then
        report_fail "openclaw security audit 发现问题"
    else
        report_pass "openclaw security audit 通过"
    fi
    report '```'
    report "$AUDIT_OUTPUT"
    report '```'
else
    report_warn "openclaw CLI 未在 PATH 中找到"
fi
report ""

# ══════════════════════════════════════════════════
# 指标 2: 进程与网络
# ══════════════════════════════════════════════════
report "## 指标 2: 进程与网络检查"
report ""

# 监听端口
report "### 监听端口"
report '```'
if [[ "$OS" == "linux" ]]; then
    ss -tlnp 2>/dev/null >> "$REPORT_FILE" || netstat -tlnp 2>/dev/null >> "$REPORT_FILE"
else
    lsof -i -P -n | grep LISTEN >> "$REPORT_FILE" 2>/dev/null || true
fi
report '```'

# 检查 OpenClaw 是否监听非回环地址
if [[ "$OS" == "linux" ]]; then
    NON_LOOPBACK=$(ss -tlnp 2>/dev/null | grep -E "18789|openclaw" | grep -v "127.0.0.1\|::1\|\[::1\]" || true)
else
    NON_LOOPBACK=$(lsof -i -P -n 2>/dev/null | grep -E "18789|openclaw" | grep LISTEN | grep -v "127.0.0.1\|::1" || true)
fi

if [[ -n "$NON_LOOPBACK" ]]; then
    report_fail "OpenClaw 监听了非回环地址: $NON_LOOPBACK"
else
    report_pass "OpenClaw 仅在回环地址监听 (或未运行)"
fi

# 异常外连检查
report ""
report "### 异常外连 (非标准端口)"
report '```'
if [[ "$OS" == "linux" ]]; then
    ss -tnp state established 2>/dev/null | grep -vE ":443|:80|:22|:53" >> "$REPORT_FILE" || true
else
    lsof -i -P -n 2>/dev/null | grep ESTABLISHED | grep -vE ":443|:80|:22|:53" >> "$REPORT_FILE" || true
fi
report '```'
report ""

# ══════════════════════════════════════════════════
# 指标 3: 敏感目录变更
# ══════════════════════════════════════════════════
report "## 指标 3: 敏感目录变更 (24h)"
report ""
report '```'

CHANGED_FILES=$(find "$OC" -type f -mmin -1440 \
    -not -path "*/logs/*" \
    -not -path "*/media/*" \
    -not -path "*/completions/*" \
    -not -path "*/canvas/*" \
    -not -path "*/.git/*" \
    -not -path "*/.backups/*" \
    -not -path "*/security-reports/*" \
    -not -name "*.tmp" \
    2>/dev/null || true)

if [[ -n "$CHANGED_FILES" ]]; then
    echo "$CHANGED_FILES" >> "$REPORT_FILE"
    report_warn "24h 内有 $(echo "$CHANGED_FILES" | wc -l | tr -d ' ') 个文件变更"
else
    report_pass "24h 内无敏感文件变更"
fi
report '```'
report ""

# ══════════════════════════════════════════════════
# 指标 4: 系统定时任务
# ══════════════════════════════════════════════════
report "## 指标 4: 系统定时任务"
report ""
report '```'
if [[ "$OS" == "linux" ]]; then
    crontab -l 2>/dev/null >> "$REPORT_FILE" || echo "(无 crontab)" >> "$REPORT_FILE"
    echo "--- /etc/cron.d/ ---" >> "$REPORT_FILE"
    ls -la /etc/cron.d/ 2>/dev/null >> "$REPORT_FILE" || true
    echo "--- systemd timers ---" >> "$REPORT_FILE"
    systemctl list-timers --no-pager 2>/dev/null >> "$REPORT_FILE" || true
else
    crontab -l 2>/dev/null >> "$REPORT_FILE" || echo "(无 crontab)" >> "$REPORT_FILE"
    echo "--- launchd agents ---" >> "$REPORT_FILE"
    ls ~/Library/LaunchAgents/ 2>/dev/null >> "$REPORT_FILE" || true
fi
report '```'
report_pass "定时任务已列出（请人工审查异常条目）"
report ""

# ══════════════════════════════════════════════════
# 指标 5: OpenClaw Cron
# ══════════════════════════════════════════════════
report "## 指标 5: OpenClaw Cron 任务"
report ""
if command -v openclaw &>/dev/null; then
    report '```'
    openclaw cron list 2>&1 >> "$REPORT_FILE" || echo "(获取失败)" >> "$REPORT_FILE"
    report '```'
    report_pass "OpenClaw Cron 列表已获取"
else
    report_warn "openclaw CLI 不可用"
fi
report ""

# ══════════════════════════════════════════════════
# 指标 6: 登录与 SSH
# ══════════════════════════════════════════════════
report "## 指标 6: 登录与 SSH"
report ""

report "### 最近登录"
report '```'
last -10 2>/dev/null >> "$REPORT_FILE" || echo "(last 命令不可用)" >> "$REPORT_FILE"
report '```'

report ""
report "### SSH 暴力破解检测"
report '```'
if [[ "$OS" == "linux" ]]; then
    if [[ -f /var/log/auth.log ]]; then
        FAILED_SSH=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo "0")
        echo "过去 auth.log 中 Failed password 次数: $FAILED_SSH" >> "$REPORT_FILE"
        if [[ "$FAILED_SSH" -gt 50 ]]; then
            report_warn "SSH 暴力破解尝试 > 50 次"
        else
            report_pass "SSH 暴力破解尝试在正常范围 ($FAILED_SSH 次)"
        fi
    elif [[ -f /var/log/secure ]]; then
        FAILED_SSH=$(grep -c "Failed password" /var/log/secure 2>/dev/null || echo "0")
        echo "过去 secure 日志中 Failed password 次数: $FAILED_SSH" >> "$REPORT_FILE"
    fi
elif [[ "$OS" == "macos" ]]; then
    FAILED_SSH=$(log show --last 24h --predicate 'process == "sshd" && eventMessage CONTAINS "Failed"' 2>/dev/null | wc -l | tr -d ' ')
    echo "过去 24h SSH 失败次数: $FAILED_SSH" >> "$REPORT_FILE"
    if [[ "$FAILED_SSH" -gt 50 ]]; then
        report_warn "SSH 暴力破解尝试 > 50 次"
    else
        report_pass "SSH 暴力破解尝试在正常范围 ($FAILED_SSH 次)"
    fi
fi
report '```'
report ""

# ══════════════════════════════════════════════════
# 指标 7: 配置完整性
# ══════════════════════════════════════════════════
report "## 指标 7: 配置完整性"
report ""

BASELINE_FILE="${OC}/.config-baseline.sha256"
if [[ -f "$BASELINE_FILE" ]]; then
    INTEGRITY_CHECK=$($HASH_CHECK "$BASELINE_FILE" 2>&1 || true)
    if echo "$INTEGRITY_CHECK" | grep -q "FAILED\|FAILED"; then
        report_fail "配置文件哈希校验失败！可能被篡改"
        report '```'
        echo "$INTEGRITY_CHECK" >> "$REPORT_FILE"
        report '```'
    else
        report_pass "配置文件哈希校验通过"
    fi
else
    report_warn "未找到哈希基线文件（请先运行 deploy-hardening.sh）"
fi

# 权限检查
report ""
report "### 文件权限检查"
PERM_OK=true
for f in "${OC}/openclaw.json" "${OC}/devices/paired.json"; do
    if [[ -f "$f" ]]; then
        PERM=$(stat -f "%Lp" "$f" 2>/dev/null || stat -c "%a" "$f" 2>/dev/null)
        if [[ "$PERM" != "600" ]]; then
            report_fail "$(basename $f) 权限异常: $PERM (应为 600)"
            PERM_OK=false
        fi
    fi
done
if $PERM_OK; then
    report_pass "核心文件权限正确 (600)"
fi
report ""

# ══════════════════════════════════════════════════
# 指标 8: 黄线交叉验证
# ══════════════════════════════════════════════════
report "## 指标 8: 黄线交叉验证"
report ""

report "### sudo 操作记录 (24h)"
report '```'
if [[ "$OS" == "linux" ]]; then
    if [[ -f /var/log/auth.log ]]; then
        grep "sudo:" /var/log/auth.log 2>/dev/null | tail -20 >> "$REPORT_FILE" || true
    fi
elif [[ "$OS" == "macos" ]]; then
    log show --last 24h --predicate 'process == "sudo"' 2>/dev/null | tail -20 >> "$REPORT_FILE" || true
fi
report '```'

report ""
report "### OpenClaw memory/ 黄线日志"
report '```'
TODAY=$(date +%Y-%m-%d)
MEMORY_FILE="${OC}/workspace/memory/${TODAY}.md"
if [[ -f "$MEMORY_FILE" ]]; then
    grep -i "sudo\|install\|docker\|iptables\|ufw\|chattr\|systemctl" "$MEMORY_FILE" >> "$REPORT_FILE" 2>/dev/null || echo "(无黄线记录)" >> "$REPORT_FILE"
else
    echo "(今日无 memory 文件)" >> "$REPORT_FILE"
fi
report '```'
report_pass "交叉验证日志已列出（请人工比对）"
report ""

# ══════════════════════════════════════════════════
# 指标 9: 磁盘使用
# ══════════════════════════════════════════════════
report "## 指标 9: 磁盘使用"
report ""
report '```'
df -h / >> "$REPORT_FILE" 2>/dev/null
report '```'

USAGE=$(df / 2>/dev/null | awk 'NR==2 {gsub(/%/,""); print $5}')
if [[ -n "$USAGE" && "$USAGE" -gt 85 ]]; then
    report_fail "磁盘使用率 ${USAGE}% > 85%"
else
    report_pass "磁盘使用率正常 (${USAGE:-N/A}%)"
fi

# 大文件检查
report ""
report "### 24h 新增大文件 (>100MB)"
report '```'
LARGE_FILES=$(find "$OC" -type f -mmin -1440 -size +100M -not -path "*/.git/*" 2>/dev/null || true)
if [[ -n "$LARGE_FILES" ]]; then
    echo "$LARGE_FILES" >> "$REPORT_FILE"
    report_warn "发现 24h 内新增的大文件"
else
    echo "(无)" >> "$REPORT_FILE"
    report_pass "无异常大文件"
fi
report '```'
report ""

# ══════════════════════════════════════════════════
# 指标 10: 环境变量审查
# ══════════════════════════════════════════════════
report "## 指标 10: 环境变量审查"
report ""

# 找到 openclaw/gateway 进程
GATEWAY_PID=$(pgrep -f "openclaw" 2>/dev/null | head -1 || true)
if [[ -n "$GATEWAY_PID" ]]; then
    report '```'
    if [[ "$OS" == "linux" ]]; then
        cat /proc/$GATEWAY_PID/environ 2>/dev/null | tr '\0' '\n' | grep -iE "KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL" >> "$REPORT_FILE" || echo "(无法读取或无匹配)" >> "$REPORT_FILE"
    else
        ps eww -p "$GATEWAY_PID" 2>/dev/null | tr ' ' '\n' | grep -iE "KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL" >> "$REPORT_FILE" || echo "(macOS 限制，建议使用 Activity Monitor)" >> "$REPORT_FILE"
    fi
    report '```'
    report_warn "请人工检查敏感环境变量是否应存在"
else
    report_pass "OpenClaw 进程未运行，无需检查环境变量"
fi
report ""

# ══════════════════════════════════════════════════
# 指标 11: 敏感凭据扫描 (DLP)
# ══════════════════════════════════════════════════
report "## 指标 11: 敏感凭据扫描 (DLP)"
report ""

WORKSPACE="${OC}/workspace"
if [[ -d "$WORKSPACE" ]]; then
    # 扫描明文私钥 / 助记词 / 高熵 token
    DLP_FINDINGS=$(grep -rlE \
        "PRIVATE KEY|BEGIN RSA|BEGIN EC|BEGIN OPENSSH|mnemonic|seed phrase|sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|glpat-[a-zA-Z0-9-]{20}" \
        "$WORKSPACE" \
        --include="*.md" --include="*.txt" --include="*.json" --include="*.yaml" --include="*.yml" --include="*.env" \
        2>/dev/null || true)

    if [[ -n "$DLP_FINDINGS" ]]; then
        report_fail "workspace 中发现疑似明文凭据！"
        report '```'
        echo "$DLP_FINDINGS" | head -20 >> "$REPORT_FILE"
        report '```'
    else
        report_pass "workspace 中未发现明文凭据"
    fi
else
    report_warn "workspace 目录不存在"
fi
report ""

# ══════════════════════════════════════════════════
# 指标 12: Skill/MCP 完整性
# ══════════════════════════════════════════════════
report "## 指标 12: Skill/MCP 完整性"
report ""

SKILLS_BASELINE="${OC}/.skills-baseline.sha256"
if [[ -f "$SKILLS_BASELINE" ]]; then
    SKILL_CHECK=$($HASH_CHECK "$SKILLS_BASELINE" 2>&1 || true)
    SKILL_FAILED=$(echo "$SKILL_CHECK" | grep -c "FAILED" || true)
    if [[ "$SKILL_FAILED" -gt 0 ]]; then
        report_fail "Skill 完整性校验失败: $SKILL_FAILED 个文件被修改"
        report '```'
        echo "$SKILL_CHECK" | grep "FAILED" >> "$REPORT_FILE"
        report '```'
    else
        report_pass "Skill 完整性校验通过"
    fi
else
    report_warn "未找到 Skill 基线文件"
fi
report ""

# ══════════════════════════════════════════════════
# 指标 13: 灾备同步
# ══════════════════════════════════════════════════
report "## 指标 13: Git 灾备同步"
report ""

if [[ -d "${OC}/.git" ]]; then
    cd "$OC"

    # 增量 commit
    git add -A 2>/dev/null
    COMMIT_MSG="Nightly audit snapshot - $(date +%Y-%m-%d)"
    git commit -q -m "$COMMIT_MSG" 2>/dev/null || true

    # 尝试 push
    REMOTE=$(git remote 2>/dev/null | head -1)
    if [[ -n "$REMOTE" ]]; then
        if git push "$REMOTE" 2>/dev/null; then
            report_pass "Git 灾备同步成功 (remote: $REMOTE)"
        else
            report_warn "Git push 失败（请检查网络或认证）"
        fi
    else
        report_warn "未配置 Git 远程仓库"
    fi
else
    report_warn "Git 灾备未初始化（请先运行 deploy-hardening.sh）"
fi
report ""

# ──────────────────── 报告摘要 ────────────────────
report "---"
report ""
report "## 审计摘要"
report ""
report "| 结果 | 数量 |"
report "|------|------|"
report "| ✅ PASS | $PASS_COUNT |"
report "| ⚠️ WARN | $WARN_COUNT |"
report "| 🚨 FAIL | $FAIL_COUNT |"
report ""

TOTAL=$((PASS_COUNT + WARN_COUNT + FAIL_COUNT))
if [[ "$FAIL_COUNT" -gt 0 ]]; then
    report "> 🚨 **发现 ${FAIL_COUNT} 项严重问题，请立即处理！**"
elif [[ "$WARN_COUNT" -gt 0 ]]; then
    report "> ⚠️ **发现 ${WARN_COUNT} 项警告，建议关注。**"
else
    report "> ✅ **全部 ${TOTAL} 项检查通过。**"
fi

# ──────────────────── 输出报告 ────────────────────
echo "======================================"
echo "  OpenClaw 安全审计报告"
echo "  时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "======================================"
echo ""
echo "  PASS: $PASS_COUNT"
echo "  WARN: $WARN_COUNT"
echo "  FAIL: $FAIL_COUNT"
echo ""
echo "  报告保存: $REPORT_FILE"
echo "======================================"

# 输出报告内容到 stdout（供 openclaw cron 推送）
cat "$REPORT_FILE"
