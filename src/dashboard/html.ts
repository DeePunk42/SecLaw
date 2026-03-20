/**
 * Embedded SPA dashboard — returns a complete HTML page as a string.
 * No external resources (no CDN, no font loading).
 */

export function getDashboardHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecLaw Dashboard</title>
<style>
:root {
  --bg: #0f1117;
  --bg-card: #1a1d27;
  --bg-input: #252833;
  --border: #2d3040;
  --text: #e2e4ea;
  --text-dim: #8b8fa3;
  --green: #22c55e;
  --yellow: #f59e0b;
  --red: #ef4444;
  --purple: #a855f7;
  --blue: #3b82f6;
  --font-mono: "SF Mono", "Cascadia Code", "Fira Code", Menlo, Consolas, monospace;
  --font-ui: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: var(--font-ui);
  background: var(--bg);
  color: var(--text);
  min-height: 100vh;
}
header {
  display: flex; align-items: center; justify-content: space-between;
  padding: 12px 20px;
  border-bottom: 1px solid var(--border);
  background: var(--bg-card);
}
header h1 { font-size: 16px; font-weight: 600; }
header h1 span { color: var(--blue); }
.status-dot { display: inline-block; width: 8px; height: 8px; border-radius: 50%; background: var(--green); margin-right: 6px; }
nav {
  display: flex; gap: 0;
  border-bottom: 1px solid var(--border);
  background: var(--bg-card);
}
nav button {
  padding: 10px 20px; background: none; border: none; border-bottom: 2px solid transparent;
  color: var(--text-dim); cursor: pointer; font-size: 13px; font-family: var(--font-ui);
  transition: color 0.15s, border-color 0.15s;
}
nav button:hover { color: var(--text); }
nav button.active { color: var(--blue); border-bottom-color: var(--blue); }
.tab-content { display: none; padding: 16px 20px; }
.tab-content.active { display: block; }

/* ─── Tool Call Cards ─── */
.log-toolbar {
  display: flex; gap: 8px; align-items: center; margin-bottom: 12px; flex-wrap: wrap;
}
.log-toolbar select, .log-toolbar input {
  padding: 6px 10px; background: var(--bg-input); border: 1px solid var(--border);
  color: var(--text); border-radius: 4px; font-size: 12px; font-family: var(--font-ui);
}
.log-toolbar button {
  padding: 6px 12px; background: var(--bg-input); border: 1px solid var(--border);
  color: var(--text); border-radius: 4px; cursor: pointer; font-size: 12px; font-family: var(--font-ui);
}
.log-toolbar button:hover { background: var(--border); }
.log-toolbar .count { color: var(--text-dim); font-size: 12px; margin-left: auto; }
.log-list { display: flex; flex-direction: column; gap: 6px; max-height: calc(100vh - 200px); overflow-y: auto; }

.tc-card {
  background: var(--bg-card); border-radius: 6px; padding: 10px 14px;
  border-left: 3px solid var(--border); font-size: 13px; cursor: pointer;
}
.tc-card.tier-GREEN { border-left-color: var(--green); }
.tc-card.tier-YELLOW { border-left-color: var(--yellow); }
.tc-card.tier-RED { border-left-color: var(--red); }
.tc-card.status-blocked { background: rgba(239,68,68,0.08); }
.tc-card.status-overridden { background: rgba(168,85,247,0.08); }
.tc-card.danger { box-shadow: inset 0 0 0 1px rgba(239,68,68,0.4); }

.tc-card-header { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.log-time { color: var(--text-dim); font-size: 11px; font-family: var(--font-mono); }
.badge {
  display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px;
  font-weight: 600; text-transform: uppercase; font-family: var(--font-mono);
}
.badge-green { background: rgba(34,197,94,0.15); color: var(--green); }
.badge-yellow { background: rgba(245,158,11,0.15); color: var(--yellow); }
.badge-red { background: rgba(239,68,68,0.15); color: var(--red); }
.badge-event { background: rgba(59,130,246,0.15); color: var(--blue); }
.badge-danger { background: rgba(239,68,68,0.25); color: var(--red); }
.log-tool { font-family: var(--font-mono); font-size: 12px; color: var(--text); }

.tc-status {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 1px 8px; border-radius: 3px; font-size: 10px;
  font-weight: 600; text-transform: uppercase; font-family: var(--font-mono);
}
.tc-status.allowed { background: rgba(34,197,94,0.15); color: var(--green); }
.tc-status.blocked { background: rgba(239,68,68,0.15); color: var(--red); }
.tc-status.pending { background: rgba(245,158,11,0.15); color: var(--yellow); }
.tc-status.overridden { background: rgba(168,85,247,0.15); color: var(--purple); }

.spinner {
  display: inline-block; width: 10px; height: 10px;
  border: 2px solid rgba(245,158,11,0.3); border-top-color: var(--yellow);
  border-radius: 50%; animation: spin 0.8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }

@keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
.blink { animation: blink 1.5s ease-in-out infinite; }

.tc-detail {
  display: none; margin-top: 8px; padding-top: 8px; border-top: 1px solid var(--border);
  font-size: 12px;
}
.tc-card.expanded .tc-detail { display: block; }

.tc-phase {
  margin-bottom: 8px; padding: 6px 8px; background: var(--bg-input); border-radius: 4px;
}
.tc-phase-title {
  font-size: 10px; font-weight: 600; text-transform: uppercase; color: var(--text-dim);
  margin-bottom: 4px; font-family: var(--font-mono);
}
.tc-phase-body {
  font-family: var(--font-mono); font-size: 11px; color: var(--text);
  white-space: pre-wrap; word-break: break-all;
}

.tc-pin {
  display: inline-block; padding: 2px 8px; background: rgba(239,68,68,0.2);
  border: 1px solid rgba(239,68,68,0.4); border-radius: 3px;
  font-family: var(--font-mono); font-size: 12px; color: var(--red);
  letter-spacing: 2px; font-weight: 600;
}

/* ─── Config Tab ─── */
.config-section { margin-bottom: 20px; }
.config-section h3 {
  font-size: 13px; color: var(--blue); margin-bottom: 10px;
  padding-bottom: 6px; border-bottom: 1px solid var(--border);
}
.config-field { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
.config-field label { width: 180px; font-size: 12px; color: var(--text-dim); }
.config-hint { font-size: 11px; color: var(--text-dim); margin-left: 4px; }
.config-field input, .config-field select {
  flex: 1; max-width: 300px; padding: 6px 10px; background: var(--bg-input);
  border: 1px solid var(--border); color: var(--text); border-radius: 4px;
  font-size: 12px; font-family: var(--font-mono);
}
.config-field input[type="checkbox"] { flex: none; width: 16px; height: 16px; }
.btn-mini {
  padding: 5px 10px; background: var(--bg-input); border: 1px solid var(--border);
  color: var(--text); border-radius: 4px; cursor: pointer; font-size: 11px;
  font-family: var(--font-ui);
}
.btn-mini:hover { border-color: var(--blue); }
.btn-mini:disabled { opacity: 0.6; cursor: default; }
.btn-save {
  padding: 8px 20px; background: var(--blue); border: none; color: #fff;
  border-radius: 4px; cursor: pointer; font-size: 13px; font-family: var(--font-ui);
}
.btn-save:hover { opacity: 0.9; }
.toast {
  position: fixed; top: 16px; right: 16px; padding: 10px 16px; border-radius: 6px;
  font-size: 13px; z-index: 999; opacity: 0; transition: opacity 0.3s;
}
.toast.show { opacity: 1; }
.toast.success { background: rgba(34,197,94,0.9); color: #fff; }
.toast.error { background: rgba(239,68,68,0.9); color: #fff; }

/* ─── Multi-Select Checkbox Dropdown ─── */
.multi-select {
  position: relative; flex: 1; max-width: 300px;
}
.multi-select-toggle {
  display: flex; align-items: center; justify-content: space-between;
  padding: 6px 10px; background: var(--bg-input); border: 1px solid var(--border);
  border-radius: 4px; cursor: pointer; font-size: 12px; font-family: var(--font-mono);
  color: var(--text); min-height: 30px; user-select: none;
}
.multi-select-toggle:hover { border-color: var(--blue); }
.multi-select.open .multi-select-toggle { border-color: var(--blue); border-radius: 4px 4px 0 0; }
.multi-select-summary { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.multi-select-arrow { margin-left: 8px; font-size: 10px; color: var(--text-dim); transition: transform 0.15s; }
.multi-select.open .multi-select-arrow { transform: rotate(180deg); }
.multi-select-dropdown {
  display: none; position: absolute; top: 100%; left: 0; right: 0;
  background: var(--bg-input); border: 1px solid var(--blue); border-top: none;
  border-radius: 0 0 4px 4px; max-height: 200px; overflow-y: auto; z-index: 50;
}
.multi-select.open .multi-select-dropdown { display: block; }
.multi-select-item {
  padding: 0;
}
.multi-select-item label {
  display: flex; align-items: center; gap: 8px;
  padding: 6px 10px; cursor: pointer; font-size: 12px;
  font-family: var(--font-mono); color: var(--text); width: 100%;
}
.multi-select-item label:hover { background: rgba(59,130,246,0.1); }
.multi-select-item input[type="checkbox"] {
  width: 14px; height: 14px; accent-color: var(--blue); flex-shrink: 0; cursor: pointer;
}
.multi-select-empty {
  padding: 10px; text-align: center; font-size: 11px; color: var(--text-dim);
}
.multi-select-actions {
  display: flex; gap: 8px; padding: 6px 10px;
  border-top: 1px solid var(--border); font-size: 11px;
}
.multi-select-actions a {
  color: var(--blue); cursor: pointer; text-decoration: none;
}
.multi-select-actions a:hover { text-decoration: underline; }

/* ─── Health Tab ─── */
.health-header {
  background: var(--bg-card); border-radius: 8px; padding: 16px 20px; margin-bottom: 16px;
}
.health-header-top {
  display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px;
}
.health-header-top h2 { font-size: 16px; font-weight: 600; }
.health-header-top .health-actions { display: flex; gap: 8px; }
.health-btn {
  padding: 6px 14px; background: var(--bg-input); border: 1px solid var(--border);
  color: var(--text); border-radius: 4px; cursor: pointer; font-size: 12px; font-family: var(--font-ui);
}
.health-btn:hover { background: var(--border); }
.health-btn.primary { background: var(--blue); border-color: var(--blue); color: #fff; }
.health-btn.primary:hover { opacity: 0.9; }
.score-bar-container { margin-bottom: 8px; }
.score-bar {
  height: 8px; border-radius: 4px; background: var(--bg-input); overflow: hidden;
}
.score-bar-fill {
  height: 100%; border-radius: 4px; transition: width 0.5s ease;
}
.score-label { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 4px; }
.score-label .score-value { font-size: 28px; font-weight: 700; font-family: var(--font-mono); }
.score-label .score-max { font-size: 14px; color: var(--text-dim); }

/* Scan progress bar */
.scan-progress { margin: 8px 0; }
.scan-progress-text { font-size: 11px; color: var(--blue); margin-bottom: 4px; }
.scan-progress-bar {
  height: 4px; border-radius: 2px; background: var(--bg-input); overflow: hidden;
}
.scan-progress-fill {
  height: 100%; border-radius: 2px; background: var(--blue);
  width: 0%; transition: width 0.3s ease;
}

.health-meta { font-size: 11px; color: var(--text-dim); margin-bottom: 8px; }
.health-stats { display: flex; gap: 12px; flex-wrap: wrap; }
.health-stat {
  display: inline-flex; align-items: center; gap: 4px;
  font-size: 12px; font-family: var(--font-mono);
}
.health-stat .stat-icon { font-size: 14px; }

/* Scanning state: dim score and stats */
.health-header.scanning .score-value { opacity: 0.3; }
.health-header.scanning .health-stats { opacity: 0.3; }
.health-header.scanning .health-meta { opacity: 0.3; }

.domain-cards { display: flex; flex-direction: column; gap: 8px; margin-bottom: 16px; }
.domain-card {
  background: var(--bg-card); border-radius: 6px; overflow: hidden;
}
.domain-header {
  display: flex; align-items: center; gap: 12px; padding: 10px 14px; cursor: pointer;
  user-select: none;
}
.domain-header:hover { background: rgba(59,130,246,0.05); }
.domain-arrow { font-size: 10px; color: var(--text-dim); transition: transform 0.2s; width: 12px; }
.domain-card.expanded .domain-arrow { transform: rotate(90deg); }
.domain-name { font-size: 13px; font-weight: 600; flex: 1; }
.domain-score { font-size: 11px; font-family: var(--font-mono); color: var(--text-dim); }
.domain-bar { width: 80px; height: 4px; border-radius: 2px; background: var(--bg-input); overflow: hidden; }
.domain-bar-fill { height: 100%; border-radius: 2px; }
.domain-checks { display: none; padding: 0 14px 10px 38px; }
.domain-card.expanded .domain-checks { display: block; }

/* Skeleton domain cards */
.domain-card.skeleton .domain-score { color: var(--border); }
.domain-card.skeleton .domain-bar-fill { width: 0% !important; }

.check-item {
  display: flex; align-items: flex-start; gap: 8px; padding: 4px 0;
  font-size: 12px; border-bottom: 1px solid var(--border);
}
.check-item:last-child { border-bottom: none; }
.check-icon { width: 16px; text-align: center; flex-shrink: 0; }
.check-body { flex: 1; }
.check-name { font-weight: 500; }
.check-msg { color: var(--text-dim); font-size: 11px; }
.check-fix {
  font-size: 11px; color: var(--blue); font-family: var(--font-mono);
  margin-top: 2px;
}

.harden-panel {
  background: var(--bg-card); border-radius: 8px; padding: 16px 20px; margin-bottom: 16px;
}
.harden-panel h3 { font-size: 14px; font-weight: 600; margin-bottom: 12px; }
.harden-section { margin-bottom: 12px; }
.harden-section-title { font-size: 11px; color: var(--text-dim); margin-bottom: 6px; text-transform: uppercase; }
.harden-btns { display: flex; gap: 6px; flex-wrap: wrap; }
.harden-btn {
  padding: 5px 12px; background: var(--bg-input); border: 1px solid var(--border);
  color: var(--text); border-radius: 4px; cursor: pointer; font-size: 11px; font-family: var(--font-ui);
}
.harden-btn:hover { background: var(--border); }
.harden-btn.high-risk { border-color: rgba(239,68,68,0.4); color: var(--red); }
.harden-btn.high-risk:hover { background: rgba(239,68,68,0.1); }
.harden-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.harden-divider { border: none; border-top: 1px solid var(--border); margin: 12px 0; }

.harden-results {
  background: var(--bg-card); border-radius: 8px; padding: 16px 20px; margin-bottom: 16px;
}
.harden-results h3 { font-size: 14px; font-weight: 600; margin-bottom: 8px; }
.harden-result-item {
  padding: 6px 0; font-size: 12px; border-bottom: 1px solid var(--border);
  font-family: var(--font-mono);
}
.harden-result-item:last-child { border-bottom: none; }
.harden-result-item .rollback { font-size: 10px; color: var(--text-dim); display: block; margin-top: 2px; }

/* ─── Rules Tab ─── */
.rules-panel {
  background: var(--bg-card); border-radius: 8px; padding: 16px 20px;
}
.rules-toolbar {
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 10px;
}
.rules-toolbar select, .rules-toolbar button {
  padding: 6px 10px; background: var(--bg-input); border: 1px solid var(--border);
  color: var(--text); border-radius: 4px; font-size: 12px; font-family: var(--font-ui);
}
.rules-toolbar button { cursor: pointer; }
.rules-toolbar button:hover { background: var(--border); }
.rules-toolbar button.primary { background: var(--blue); border-color: var(--blue); color: #fff; }
.rules-toolbar button.primary:hover { opacity: 0.9; }
.rules-meta { font-size: 11px; color: var(--text-dim); margin-bottom: 10px; }
.rules-list { display: flex; flex-direction: column; gap: 10px; }
.rule-item {
  border: 1px solid var(--border); border-radius: 6px; padding: 10px; background: var(--bg-input);
}
.rule-item-header {
  display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 8px;
}
.rule-item-title { font-size: 12px; font-weight: 600; color: var(--blue); }
.rule-item-remove {
  padding: 4px 8px; font-size: 11px; border: 1px solid rgba(239,68,68,0.5);
  color: var(--red); background: rgba(239,68,68,0.08); border-radius: 4px; cursor: pointer;
}
.rule-item-remove:hover { background: rgba(239,68,68,0.15); }
.rule-grid {
  display: grid; grid-template-columns: 1fr 1fr; gap: 8px;
}
.rule-field { display: flex; flex-direction: column; gap: 4px; }
.rule-field label { font-size: 11px; color: var(--text-dim); }
.rule-field input, .rule-field select, .rule-field textarea {
  width: 100%; padding: 6px 8px; background: var(--bg); border: 1px solid var(--border);
  color: var(--text); border-radius: 4px; font-size: 12px; font-family: var(--font-mono);
}
.rule-field.full { grid-column: 1 / -1; }

/* ─── Placeholder pages ─── */
.placeholder {
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  min-height: 300px; color: var(--text-dim);
}
.placeholder h2 { font-size: 20px; margin-bottom: 8px; color: var(--text); }
.placeholder p { font-size: 14px; }
</style>
</head>
<body>
<header>
  <h1><span class="status-dot"></span>Sec<span>Law</span> Dashboard</h1>
  <span style="font-size:12px;color:var(--text-dim)">127.0.0.1</span>
</header>
<nav>
  <button class="active" data-tab="logs">Audit Log</button>
  <button data-tab="config">Config</button>
  <button data-tab="health">Health</button>
  <button data-tab="rules">Rules</button>
</nav>

<!-- Tab 1: Audit Log (Tool Call Cards) -->
<div id="tab-logs" class="tab-content active">
  <div class="log-toolbar">
    <select id="filter-tier"><option value="">All Tiers</option><option value="GREEN">GREEN</option><option value="YELLOW">YELLOW</option><option value="RED">RED</option></select>
    <select id="filter-status"><option value="">All Status</option><option value="allowed">Allowed</option><option value="blocked">Blocked</option><option value="overridden">Overridden</option><option value="pending">Pending</option></select>
    <input id="filter-tool" type="text" placeholder="Tool name..." style="width:120px">
    <button id="btn-pause">Pause</button>
    <button id="btn-clear">Clear</button>
    <span class="count" id="log-count">0 calls</span>
  </div>
  <div class="log-list" id="log-list"></div>
</div>

<!-- Tab 2: Config Editor -->
<div id="tab-config" class="tab-content">
  <div class="config-section">
    <h3>LLM</h3>
    <div class="config-field"><label>Model</label><input id="cfg-llm-model" list="cfg-llm-model-list" placeholder="provider/model" autocomplete="off"><datalist id="cfg-llm-model-list"></datalist><button id="btn-test-llm-model" class="btn-mini" type="button">Test</button><span class="config-hint">provider/model</span></div>
    <div class="config-field"><label>Enabled</label><input id="cfg-llm-enabled" type="checkbox"><span class="config-hint">Enable LLM auditing</span></div>
    <div class="config-field"><label>Max Concurrent</label><input id="cfg-llm-maxConcurrent" type="number" min="1" max="10"><span class="config-hint">Parallel audit limit</span></div>
    <div class="config-field"><label>Recent Calls in Prompt</label><input id="cfg-llm-promptRecentCalls" type="number" min="0" max="20"><span class="config-hint">Tool calls included in audit context</span></div>
    <div class="config-field"><label>Trusted Senders</label><div class="multi-select" id="cfg-llm-trustedSenderLabels"><div class="multi-select-toggle"><span class="multi-select-summary">0 selected</span><span class="multi-select-arrow">&#x25BE;</span></div><div class="multi-select-dropdown"></div></div><button id="btn-refresh-labels" type="button" style="padding:6px 10px;background:var(--bg-input);border:1px solid var(--border);color:var(--text);border-radius:4px;cursor:pointer;font-size:12px;margin-left:4px" title="Refresh labels from logs">&#x21bb;</button></div>
  </div>
  <div class="config-section">
    <h3>LLM Retry</h3>
    <div class="config-field"><label>Max Retries</label><input id="cfg-llm-retry-maxRetries" type="number" min="0" max="10"></div>
    <div class="config-field"><label>Initial Backoff</label><input id="cfg-llm-retry-initialBackoffMs" type="number" min="100" max="30000"><span class="config-hint">ms</span></div>
    <div class="config-field"><label>Cooldown</label><input id="cfg-llm-retry-cooldownMs" type="number" min="1000" max="300000"><span class="config-hint">ms, after threshold</span></div>
    <div class="config-field"><label>Cooldown After</label><input id="cfg-llm-retry-cooldownThreshold" type="number" min="1" max="20"><span class="config-hint">consecutive errors</span></div>
  </div>
  <div class="config-section">
    <h3>Timeouts</h3>
    <div class="config-field"><label>Audit Timeout</label><input id="cfg-timeouts-auditTimeoutMs" type="number" min="1000" max="120000"><span class="config-hint">ms (sync &amp; async)</span></div>
    <div class="config-field"><label>Timeout Policy</label><select id="cfg-timeouts-syncTimeoutPolicy"><option value="fail_closed">fail_closed</option><option value="fail_open">fail_open</option></select><span class="config-hint">fail_closed = block, fail_open = allow</span></div>
  </div>
  <div class="config-section">
    <h3>Logging</h3>
    <div class="config-field"><label>Log Level</label><select id="cfg-logging-level"><option value="debug">debug</option><option value="info">info</option><option value="warn">warn</option><option value="error">error</option></select></div>
    <div class="config-field"><label>JSONL Audit Log</label><input id="cfg-logging-auditJsonl" type="checkbox"><span class="config-hint">Write structured logs to disk</span></div>
  </div>
  <div class="config-section">
    <h3>Dashboard</h3>
    <div class="config-field"><label>Enabled</label><input id="cfg-dashboard-enabled" type="checkbox" disabled title="Requires restart"><span class="config-hint">Requires restart</span></div>
    <div class="config-field"><label>Port</label><input id="cfg-dashboard-port" type="number" disabled title="Requires restart"><span class="config-hint">Requires restart</span></div>
    <div class="config-field"><label>Bind Address</label><input id="cfg-dashboard-host" type="text" disabled title="Requires restart"><span class="config-hint">Requires restart</span></div>
  </div>
  <button class="btn-save" id="btn-save-config">Save Configuration</button>
</div>

<!-- Tab 3: Health -->
<div id="tab-health" class="tab-content">
  <div id="health-content">
    <!-- Score Header -->
    <div class="health-header">
      <div class="health-header-top">
        <h2>Security Posture</h2>
        <div class="health-actions">
          <button class="health-btn primary" id="btn-health-scan">Scan</button>
          <button class="health-btn" id="btn-health-report">Report</button>
        </div>
      </div>
      <div class="score-bar-container">
        <div class="score-label">
          <span><span class="score-value" id="health-score">—</span><span class="score-max">/100</span></span>
        </div>
        <div class="score-bar"><div class="score-bar-fill" id="health-score-bar" style="width:0%;background:var(--green)"></div></div>
      </div>
      <div class="scan-progress" id="scan-progress" style="display:none">
        <div class="scan-progress-text" id="scan-progress-text">Scanning...</div>
        <div class="scan-progress-bar"><div class="scan-progress-fill" id="scan-progress-fill"></div></div>
      </div>
      <div class="health-meta" id="health-meta"></div>
      <div class="health-stats" id="health-stats">
        <span class="health-stat"><span class="stat-icon" style="color:var(--green)">&#x2705;</span> — pass</span>
        <span class="health-stat"><span class="stat-icon" style="color:var(--yellow)">&#x26A0;&#xFE0F;</span> — warn</span>
        <span class="health-stat"><span class="stat-icon" style="color:var(--red)">&#x274C;</span> — fail</span>
        <span class="health-stat"><span class="stat-icon" style="color:var(--text-dim)">&#x23ED;&#xFE0F;</span> — skip</span>
      </div>
    </div>

    <!-- Domain Cards -->
    <div class="domain-cards" id="health-domains">
      <div class="domain-card skeleton">
        <div class="domain-header">
          <span class="domain-arrow">&#x25B8;</span>
          <span class="domain-name">网络隔离</span>
          <span class="domain-score">—/—</span>
          <div class="domain-bar"><div class="domain-bar-fill"></div></div>
        </div>
      </div>
      <div class="domain-card skeleton">
        <div class="domain-header">
          <span class="domain-arrow">&#x25B8;</span>
          <span class="domain-name">认证</span>
          <span class="domain-score">—/—</span>
          <div class="domain-bar"><div class="domain-bar-fill"></div></div>
        </div>
      </div>
      <div class="domain-card skeleton">
        <div class="domain-header">
          <span class="domain-arrow">&#x25B8;</span>
          <span class="domain-name">Exec 安全</span>
          <span class="domain-score">—/—</span>
          <div class="domain-bar"><div class="domain-bar-fill"></div></div>
        </div>
      </div>
      <div class="domain-card skeleton">
        <div class="domain-header">
          <span class="domain-arrow">&#x25B8;</span>
          <span class="domain-name">文件系统</span>
          <span class="domain-score">—/—</span>
          <div class="domain-bar"><div class="domain-bar-fill"></div></div>
        </div>
      </div>
      <div class="domain-card skeleton">
        <div class="domain-header">
          <span class="domain-arrow">&#x25B8;</span>
          <span class="domain-name">供应链</span>
          <span class="domain-score">—/—</span>
          <div class="domain-bar"><div class="domain-bar-fill"></div></div>
        </div>
      </div>
      <div class="domain-card skeleton">
        <div class="domain-header">
          <span class="domain-arrow">&#x25B8;</span>
          <span class="domain-name">Channel/PI</span>
          <span class="domain-score">—/—</span>
          <div class="domain-bar"><div class="domain-bar-fill"></div></div>
        </div>
      </div>
      <div class="domain-card skeleton">
        <div class="domain-header">
          <span class="domain-arrow">&#x25B8;</span>
          <span class="domain-name">Agent</span>
          <span class="domain-score">—/—</span>
          <div class="domain-bar"><div class="domain-bar-fill"></div></div>
        </div>
      </div>
      <div class="domain-card skeleton">
        <div class="domain-header">
          <span class="domain-arrow">&#x25B8;</span>
          <span class="domain-name">监控</span>
          <span class="domain-score">—/—</span>
          <div class="domain-bar"><div class="domain-bar-fill"></div></div>
        </div>
      </div>
    </div>

    <!-- Hardening Actions -->
    <div class="harden-panel">
      <h3>Hardening Actions</h3>
      <div class="harden-section">
        <div class="harden-section-title">Configuration Safety</div>
        <div class="harden-btns">
          <button class="harden-btn" onclick="runHardenAction('backup')">Backup</button>
          <button class="harden-btn high-risk" onclick="runHardenAction('deploy-config','balanced')">Deploy Balanced</button>
          <button class="harden-btn high-risk" onclick="runHardenAction('deploy-config','paranoid')">Deploy Paranoid</button>
          <button class="harden-btn" onclick="runHardenAction('validate')">Validate</button>
        </div>
      </div>
      <div class="harden-section">
        <div class="harden-section-title">File System</div>
        <div class="harden-btns">
          <button class="harden-btn high-risk" onclick="runHardenAction('permissions')">Permissions</button>
          <button class="harden-btn" onclick="runHardenAction('baseline')">Baseline</button>
          <button class="harden-btn high-risk" onclick="runHardenAction('immutable-protect')">Immutable</button>
        </div>
      </div>
      <div class="harden-section">
        <div class="harden-section-title">Supply Chain</div>
        <div class="harden-btns">
          <button class="harden-btn" onclick="runHardenAction('npmrc')">npmrc</button>
        </div>
      </div>
      <div class="harden-section">
        <div class="harden-section-title">Agent &amp; Monitoring</div>
        <div class="harden-btns">
          <button class="harden-btn" onclick="runHardenAction('deploy-agents')">Deploy AGENTS.md</button>
          <button class="harden-btn" onclick="runHardenAction('deploy-audit')">Deploy Audit Script</button>
          <button class="harden-btn" onclick="runHardenAction('git-backup')">Git Backup</button>
          <button class="harden-btn" onclick="runHardenAction('audit')">Run Audit</button>
        </div>
      </div>
      <div class="harden-section">
        <div class="harden-section-title">Network &amp; System</div>
        <div class="harden-btns">
          <button class="harden-btn high-risk" onclick="runHardenAction('firewall')">Firewall</button>
          <button class="harden-btn" onclick="runHardenAction('disk-encryption')">Disk Encryption</button>
          <button class="harden-btn" onclick="runHardenAction('channel-hint')">Channel Hints</button>
          <button class="harden-btn" onclick="runHardenAction('verify-hint')">Verify Hints</button>
        </div>
      </div>
    </div>

    <!-- Action Results -->
    <div class="harden-results" id="harden-results" style="display:none">
      <h3>Action Results</h3>
      <div id="harden-results-list"></div>
    </div>
  </div>
</div>

<!-- Tab 4: Rules -->
<div id="tab-rules" class="tab-content">
  <div class="rules-panel">
    <div class="rules-toolbar">
      <select id="rules-file-select"></select>
      <button id="btn-rules-add">Add Rule</button>
      <button id="btn-rules-upload">Upload YAML</button>
      <button id="btn-rules-download">Download YAML</button>
      <button id="btn-rules-save" class="primary">Save</button>
      <input id="rules-upload-input" type="file" accept=".yaml,.yml" style="display:none">
    </div>
    <div class="rules-meta" id="rules-meta">Loading rules...</div>
    <div class="rules-list" id="rules-list"></div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
(function() {
  // ─── Tab switching ───
  const navBtns = document.querySelectorAll('nav button');
  const tabs = document.querySelectorAll('.tab-content');
  navBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      navBtns.forEach(b => b.classList.remove('active'));
      tabs.forEach(t => t.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('tab-' + btn.dataset.tab).classList.add('active');
    });
  });

  // ─── Toast ───
  function showToast(msg, type) {
    const t = document.getElementById('toast');
    t.textContent = msg;
    t.className = 'toast show ' + type;
    setTimeout(() => { t.className = 'toast'; }, 3000);
  }

  // ─── Tool Call Cards ───
  const logList = document.getElementById('log-list');
  const logCount = document.getElementById('log-count');
  const filterTier = document.getElementById('filter-tier');
  const filterStatus = document.getElementById('filter-status');
  const filterTool = document.getElementById('filter-tool');
  const btnPause = document.getElementById('btn-pause');
  const btnClear = document.getElementById('btn-clear');

  var records = new Map();
  var recordOrder = [];
  let paused = false;
  let eventSource = null;

  function relativeTime(ts) {
    const d = new Date(ts);
    const diff = (Date.now() - d.getTime()) / 1000;
    if (diff < 60) return Math.floor(diff) + 's ago';
    if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
    if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
    return d.toLocaleTimeString();
  }

  function tierBadgeClass(tier) {
    if (tier === 'GREEN') return 'badge-green';
    if (tier === 'YELLOW') return 'badge-yellow';
    if (tier === 'RED') return 'badge-red';
    return '';
  }

  function escapeHtml(s) {
    return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  function matchesFilter(rec) {
    if (filterTier.value && rec.tier !== filterTier.value) return false;
    if (filterStatus.value && rec.finalStatus !== filterStatus.value) return false;
    if (filterTool.value && !rec.toolName.includes(filterTool.value)) return false;
    return true;
  }

  function statusHtml(rec) {
    if (rec.finalStatus === 'overridden') {
      return '<span class="tc-status overridden">OVERRIDDEN</span>';
    }
    if (rec.finalStatus === 'blocked' && rec.overridePin) {
      return '<span class="tc-status blocked">BLOCKED</span> <span class="tc-pin">' + escapeHtml(rec.overridePin) + '</span> <span class="blink" style="font-size:10px;color:var(--yellow)">awaiting approval</span>';
    }
    if (rec.finalStatus === 'blocked') {
      return '<span class="tc-status blocked">BLOCKED</span>';
    }
    if (rec.finalStatus === 'pending') {
      var label = rec.asyncAuditStatus === 'enqueued' ? 'auditing...' : 'pending';
      return '<span class="tc-status pending"><span class="spinner"></span> ' + label + '</span>';
    }
    return '<span class="tc-status allowed">allowed</span>';
  }

  function phaseHtml(title, body) {
    if (!body) return '';
    return '<div class="tc-phase"><div class="tc-phase-title">' + escapeHtml(title) + '</div><div class="tc-phase-body">' + body + '</div></div>';
  }

  function detailHtml(rec) {
    var parts = [];

    // Rule Match
    if (rec.ruleId) {
      var ruleBody = 'Rule: ' + escapeHtml(rec.ruleId);
      if (rec.ruleReason) ruleBody += '\\nReason: ' + escapeHtml(rec.ruleReason);
      parts.push(phaseHtml('Rule Match', ruleBody));
    }

    // Block Reason
    if (rec.blockReason) {
      var blockBody = escapeHtml(rec.blockReason);
      if (rec.blockSource) blockBody = 'Source: ' + rec.blockSource + '\\n' + blockBody;
      parts.push(phaseHtml('Block Reason', blockBody));
    }

    // Intent Context
    if (rec.intentContext) {
      parts.push(phaseHtml('Intent Context', escapeHtml(JSON.stringify(rec.intentContext, null, 2))));
    }

    // Sync LLM Audit — only RED calls go through sync audit
    if (rec.tier === 'RED' && rec.syncAudit) {
      var syncBody = 'Decision: ' + escapeHtml(rec.syncAudit.decision);
      if (rec.syncAudit.reason) syncBody += '\\nReason: ' + escapeHtml(rec.syncAudit.reason);
      if (rec.syncAudit.durationMs !== undefined) syncBody += '\\nDuration: ' + rec.syncAudit.durationMs + 'ms';
      parts.push(phaseHtml('Sync LLM Audit', syncBody));
    }

    // Service Error
    if (rec.serviceError) {
      var seBody = 'Category: ' + escapeHtml(rec.serviceError.category);
      if (rec.serviceError.statusCode) seBody += '\\nStatus: ' + rec.serviceError.statusCode;
      if (rec.serviceError.message) seBody += '\\nMessage: ' + escapeHtml(rec.serviceError.message);
      parts.push(phaseHtml('Service Error', seBody));
    }

    // Async Audit — only for non-RED (RED already has Sync Audit)
    if (rec.tier !== 'RED') {
      if (rec.asyncAuditStatus === 'enqueued' && !rec.asyncAudit) {
        parts.push(phaseHtml('Async Audit', '<span class="spinner"></span> <span style="color:var(--yellow)">waiting...</span>'));
      } else if (rec.asyncAudit) {
        var asyncBody = 'Decision: ' + escapeHtml(rec.asyncAudit.decision);
        if (rec.asyncAudit.reason) asyncBody += '\\nReason: ' + escapeHtml(rec.asyncAudit.reason);
        if (rec.asyncAudit.durationMs !== undefined) asyncBody += '\\nDuration: ' + rec.asyncAudit.durationMs + 'ms';
        parts.push(phaseHtml('Async Audit', asyncBody));
      }
    }

    // Override — shown inline in status badge; awaiting-approval still needs its own phase
    if (rec.finalStatus === 'blocked' && rec.overridePin) {
      parts.push(phaseHtml('Override', 'PIN: <span class="tc-pin">' + escapeHtml(rec.overridePin) + '</span> <span class="blink" style="color:var(--yellow)">awaiting approval</span>'));
    }

    // Params
    if (rec.params) {
      parts.push(phaseHtml('Params', escapeHtml(JSON.stringify(rec.params, null, 2))));
    }

    return parts.join('');
  }

  function renderCard(rec) {
    var div = document.createElement('div');
    var cls = 'tc-card';
    if (rec.tier) cls += ' tier-' + rec.tier;
    if (rec.finalStatus === 'blocked' || rec.finalStatus === 'overridden') cls += ' status-' + rec.finalStatus;
    if (rec.dangerDetected) cls += ' danger';
    div.className = cls;
    div.dataset.tcid = rec.toolCallId;

    div.innerHTML =
      '<div class="tc-card-header">' +
        '<span class="log-time">' + relativeTime(rec.startedAt) + '</span>' +
        '<span class="log-tool">' + escapeHtml(rec.toolName) + '</span>' +
        (rec.tier ? '<span class="badge ' + tierBadgeClass(rec.tier) + '">' + rec.tier + '</span>' : '') +
        statusHtml(rec) +
        (rec.dangerDetected ? ' <span class="badge badge-danger">DANGER</span>' : '') +
      '</div>' +
      '<div class="tc-detail">' + detailHtml(rec) + '</div>';

    div.addEventListener('click', function() { div.classList.toggle('expanded'); });
    return div;
  }

  function renderAll() {
    logList.innerHTML = '';
    var filtered = recordOrder.filter(function(id) { var r = records.get(id); return r && matchesFilter(r); });
    for (var i = filtered.length - 1; i >= 0; i--) {
      logList.appendChild(renderCard(records.get(filtered[i])));
    }
    logCount.textContent = filtered.length + ' calls';
  }

  function updateToolCallCard(rec) {
    records.set(rec.toolCallId, rec);
    if (recordOrder.indexOf(rec.toolCallId) === -1) {
      recordOrder.push(rec.toolCallId);
    }
    if (recordOrder.length > 2000) {
      var removed = recordOrder.splice(0, recordOrder.length - 1500);
      removed.forEach(function(id) { records.delete(id); });
    }

    if (paused) return;

    if (!matchesFilter(rec)) {
      // Remove from DOM if it exists but no longer matches
      var existing = logList.querySelector('[data-tcid="' + rec.toolCallId + '"]');
      if (existing) existing.remove();
      logCount.textContent = recordOrder.filter(function(id) { var r = records.get(id); return r && matchesFilter(r); }).length + ' calls';
      return;
    }

    var existingEl = logList.querySelector('[data-tcid="' + rec.toolCallId + '"]');
    if (existingEl) {
      var wasExpanded = existingEl.classList.contains('expanded');
      var newEl = renderCard(rec);
      if (wasExpanded) newEl.classList.add('expanded');
      existingEl.replaceWith(newEl);
    } else {
      logList.insertBefore(renderCard(rec), logList.firstChild);
    }
    logCount.textContent = recordOrder.filter(function(id) { var r = records.get(id); return r && matchesFilter(r); }).length + ' calls';
  }

  filterTier.addEventListener('change', renderAll);
  filterStatus.addEventListener('change', renderAll);
  filterTool.addEventListener('input', renderAll);

  btnPause.addEventListener('click', function() {
    paused = !paused;
    btnPause.textContent = paused ? 'Resume' : 'Pause';
    if (!paused) renderAll();
  });

  btnClear.addEventListener('click', function() {
    records = new Map();
    recordOrder = [];
    renderAll();
  });

  // Load initial tool calls
  fetch('/api/tool-calls?limit=200')
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (Array.isArray(data)) {
        data.forEach(function(rec) {
          records.set(rec.toolCallId, rec);
          recordOrder.push(rec.toolCallId);
        });
      }
      renderAll();
      connectSSE();
    })
    .catch(function() { connectSSE(); });

  let sseRetryTimer = null;

  function connectSSE() {
    if (eventSource) {
      eventSource.close();
      eventSource = null;
    }
    if (sseRetryTimer) {
      clearTimeout(sseRetryTimer);
      sseRetryTimer = null;
    }

    // Re-fetch current state to catch up on any updates missed during disconnect
    fetch('/api/tool-calls?limit=200')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (Array.isArray(data)) {
          data.forEach(function(rec) {
            records.set(rec.toolCallId, rec);
            if (recordOrder.indexOf(rec.toolCallId) === -1) {
              recordOrder.push(rec.toolCallId);
            }
          });
          if (!paused) renderAll();
        }
      })
      .catch(function() { /* best-effort */ });

    eventSource = new EventSource('/api/tool-calls/stream');

    eventSource.onopen = function() {
      if (sseRetryTimer) {
        clearTimeout(sseRetryTimer);
        sseRetryTimer = null;
      }
    };

    eventSource.onmessage = function(e) {
      if (!e.data || e.data === '{}') return;
      try { updateToolCallCard(JSON.parse(e.data)); } catch(err) { console.warn('SSE parse error', err); }
    };

    eventSource.onerror = function() {
      if (eventSource && eventSource.readyState === 2) {
        eventSource.close();
        eventSource = null;
        if (!sseRetryTimer) {
          sseRetryTimer = setTimeout(connectSSE, 3000);
        }
      }
    };
  }

  // ─── Sender Labels (Multi-Select Checkbox) ───
  var msContainer = document.getElementById('cfg-llm-trustedSenderLabels');
  var msToggle = msContainer.querySelector('.multi-select-toggle');
  var msDropdown = msContainer.querySelector('.multi-select-dropdown');

  msToggle.addEventListener('click', function(e) {
    e.stopPropagation();
    msContainer.classList.toggle('open');
  });
  document.addEventListener('click', function(e) {
    if (!msContainer.contains(e.target)) msContainer.classList.remove('open');
  });

  function getSelectedLabels() {
    return Array.from(msDropdown.querySelectorAll('input[type="checkbox"]:checked')).map(function(cb) { return cb.value; });
  }

  function updateSummary() {
    var sel = getSelectedLabels();
    var summary = msContainer.querySelector('.multi-select-summary');
    if (sel.length === 0) summary.textContent = 'None selected';
    else if (sel.length <= 2) summary.textContent = sel.join(', ');
    else summary.textContent = sel.length + ' selected';
  }

  function renderLabelCheckboxes(allLabels, selectedLabels) {
    msDropdown.innerHTML = '';
    if (allLabels.length === 0) {
      msDropdown.innerHTML = '<div class="multi-select-empty">No labels found. Click \\u21bb to scan.</div>';
      updateSummary();
      return;
    }
    // Select all / none actions
    var actions = document.createElement('div');
    actions.className = 'multi-select-actions';
    var selAll = document.createElement('a');
    selAll.textContent = 'Select all';
    selAll.addEventListener('click', function(e) {
      e.preventDefault();
      msDropdown.querySelectorAll('input[type="checkbox"]').forEach(function(cb) { cb.checked = true; });
      updateSummary();
    });
    var selNone = document.createElement('a');
    selNone.textContent = 'Clear';
    selNone.addEventListener('click', function(e) {
      e.preventDefault();
      msDropdown.querySelectorAll('input[type="checkbox"]').forEach(function(cb) { cb.checked = false; });
      updateSummary();
    });
    actions.appendChild(selAll);
    actions.appendChild(selNone);
    msDropdown.appendChild(actions);

    allLabels.forEach(function(label) {
      var item = document.createElement('div');
      item.className = 'multi-select-item';
      var lbl = document.createElement('label');
      var cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.value = label;
      if (selectedLabels.indexOf(label) !== -1) cb.checked = true;
      cb.addEventListener('change', updateSummary);
      lbl.appendChild(cb);
      lbl.appendChild(document.createTextNode(label));
      item.appendChild(lbl);
      msDropdown.appendChild(item);
    });
    updateSummary();
  }

  function loadSenderLabels(selectedLabels) {
    fetch('/api/sender-labels')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var allLabels = data.labels || [];
        selectedLabels.forEach(function(l) {
          if (l && allLabels.indexOf(l) === -1) allLabels.push(l);
        });
        allLabels.sort();
        renderLabelCheckboxes(allLabels, selectedLabels);
      })
      .catch(function() {
        renderLabelCheckboxes(selectedLabels, selectedLabels);
      });
  }

  document.getElementById('btn-refresh-labels').addEventListener('click', function() {
    var currentSelected = getSelectedLabels();
    fetch('/api/sender-labels/refresh', { method: 'POST' })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var allLabels = data.labels || [];
        currentSelected.forEach(function(l) {
          if (l && allLabels.indexOf(l) === -1) allLabels.push(l);
        });
        allLabels.sort();
        renderLabelCheckboxes(allLabels, currentSelected);
        showToast('Sender labels refreshed (' + allLabels.length + ' found)', 'success');
      })
      .catch(function() { showToast('Failed to refresh sender labels', 'error'); });
  });

  // ─── Config Editor ───
  function loadConfig() {
    Promise.all([
      fetch('/api/config').then(function(r) { return r.json(); }),
      fetch('/api/models').then(function(r) { return r.json(); }).catch(function() { return []; }),
    ]).then(function(results) {
        var cfg = results[0];
        var models = results[1];
        // Populate model datalist
        var input = document.getElementById('cfg-llm-model');
        var list = document.getElementById('cfg-llm-model-list');
        var currentVal = cfg.llm?.model || '';
        list.innerHTML = '';
        if (Array.isArray(models)) {
          models.forEach(function(m) {
            var opt = document.createElement('option');
            opt.value = m.value;
            opt.label = m.label;
            list.appendChild(opt);
          });
        }
        input.value = currentVal;
        // LLM
        document.getElementById('cfg-llm-enabled').checked = cfg.llm?.enabled ?? true;
        document.getElementById('cfg-llm-maxConcurrent').value = cfg.llm?.maxConcurrent || 2;
        document.getElementById('cfg-llm-promptRecentCalls').value = cfg.llm?.promptRecentCalls ?? 3;
        loadSenderLabels(cfg.llm?.trustedSenderLabels || []);
        // LLM Retry
        var retry = cfg.llm?.retry || {};
        document.getElementById('cfg-llm-retry-maxRetries').value = retry.maxRetries ?? 2;
        document.getElementById('cfg-llm-retry-initialBackoffMs').value = retry.initialBackoffMs ?? 1000;
        document.getElementById('cfg-llm-retry-cooldownMs').value = retry.cooldownMs ?? 30000;
        document.getElementById('cfg-llm-retry-cooldownThreshold').value = retry.cooldownThreshold ?? 3;
        // Timeouts
        document.getElementById('cfg-timeouts-auditTimeoutMs').value = cfg.timeouts?.auditTimeoutMs || 60000;
        document.getElementById('cfg-timeouts-syncTimeoutPolicy').value = cfg.timeouts?.syncTimeoutPolicy || 'fail_closed';
        // Logging
        document.getElementById('cfg-logging-level').value = cfg.logging?.level || 'info';
        document.getElementById('cfg-logging-auditJsonl').checked = cfg.logging?.auditJsonl ?? true;
        // Dashboard (read-only)
        document.getElementById('cfg-dashboard-enabled').checked = cfg.dashboard?.enabled ?? true;
        document.getElementById('cfg-dashboard-port').value = cfg.dashboard?.port ?? 19198;
        document.getElementById('cfg-dashboard-host').value = cfg.dashboard?.host || '127.0.0.1';
      })
      .catch(function() { showToast('Failed to load config', 'error'); });
  }

  document.getElementById('btn-test-llm-model').addEventListener('click', function() {
    var btn = document.getElementById('btn-test-llm-model');
    var model = (document.getElementById('cfg-llm-model').value || '').trim();
    if (!model) {
      showToast('Please select a model first', 'error');
      return;
    }
    btn.disabled = true;
    var prevText = btn.textContent;
    btn.textContent = 'Testing...';
    fetch('/api/models/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: model }),
    })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.ok) {
          var latency = typeof data.latencyMs === 'number' ? data.latencyMs + 'ms' : 'n/a';
          var preview = (data.preview || '').trim();
          var msg = 'Model test passed (' + latency + ')';
          if (preview) msg += ': ' + preview;
          showToast(msg, 'success');
        } else {
          showToast('Model test failed: ' + (data.error || 'unknown error'), 'error');
        }
      })
      .catch(function() { showToast('Model test failed', 'error'); })
      .finally(function() {
        btn.disabled = false;
        btn.textContent = prevText || 'Test';
      });
  });

  document.getElementById('btn-save-config').addEventListener('click', function() {
    var labels = getSelectedLabels();

    var body = {
      llm: {
        model: document.getElementById('cfg-llm-model').value,
        enabled: document.getElementById('cfg-llm-enabled').checked,
        maxConcurrent: parseInt(document.getElementById('cfg-llm-maxConcurrent').value, 10),
        promptRecentCalls: parseInt(document.getElementById('cfg-llm-promptRecentCalls').value, 10),
        trustedSenderLabels: labels,
        retry: {
          maxRetries: parseInt(document.getElementById('cfg-llm-retry-maxRetries').value, 10),
          initialBackoffMs: parseInt(document.getElementById('cfg-llm-retry-initialBackoffMs').value, 10),
          cooldownMs: parseInt(document.getElementById('cfg-llm-retry-cooldownMs').value, 10),
          cooldownThreshold: parseInt(document.getElementById('cfg-llm-retry-cooldownThreshold').value, 10),
        },
      },
      timeouts: {
        auditTimeoutMs: parseInt(document.getElementById('cfg-timeouts-auditTimeoutMs').value, 10),
        syncTimeoutPolicy: document.getElementById('cfg-timeouts-syncTimeoutPolicy').value,
      },
      logging: {
        level: document.getElementById('cfg-logging-level').value,
        auditJsonl: document.getElementById('cfg-logging-auditJsonl').checked,
      },
    };
    fetch('/api/config', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.ok) showToast('Configuration saved', 'success');
        else showToast('Failed: ' + (data.errors || []).join(', '), 'error');
      })
      .catch(function() { showToast('Failed to save config', 'error'); });
  });

  // Load config when switching to config tab
  document.querySelector('[data-tab="config"]').addEventListener('click', loadConfig);
  if (document.querySelector('[data-tab="config"]').classList.contains('active')) loadConfig();

  // ─── Health Tab ───
  var healthLoaded = false;
  var healthProgressTimer = null;

  function stopHealthProgressTimer() {
    if (!healthProgressTimer) return;
    clearInterval(healthProgressTimer);
    healthProgressTimer = null;
  }

  function setHealthInitialState() {
    document.getElementById('health-score').textContent = '—';
    var bar = document.getElementById('health-score-bar');
    bar.style.width = '0%';
    bar.style.background = 'var(--border)';
    document.getElementById('health-meta').textContent = '';
    document.getElementById('health-stats').innerHTML =
      '<span class="health-stat"><span class="stat-icon" style="color:var(--green)">\\u2705</span> — pass</span>' +
      '<span class="health-stat"><span class="stat-icon" style="color:var(--yellow)">\\u26A0\\uFE0F</span> — warn</span>' +
      '<span class="health-stat"><span class="stat-icon" style="color:var(--red)">\\u274C</span> — fail</span>' +
      '<span class="health-stat"><span class="stat-icon" style="color:var(--text-dim)">\\u23ED\\uFE0F</span> — skip</span>';
  }

  function resetHealthScanUi() {
    var progress = document.getElementById('scan-progress');
    var progressText = document.getElementById('scan-progress-text');
    var progressFill = document.getElementById('scan-progress-fill');
    var header = document.querySelector('#tab-health .health-header');
    var scanBtn = document.getElementById('btn-health-scan');
    stopHealthProgressTimer();
    header.classList.remove('scanning');
    scanBtn.disabled = false;
    progress.style.display = 'none';
    progressText.textContent = 'Scanning...';
    progressFill.style.width = '0%';
  }

  function loadHealthScan() {
    var header = document.querySelector('#tab-health .health-header');
    var progress = document.getElementById('scan-progress');
    var progressText = document.getElementById('scan-progress-text');
    var progressFill = document.getElementById('scan-progress-fill');
    var scanBtn = document.getElementById('btn-health-scan');
    var progressPercent = 0;

    stopHealthProgressTimer();
    header.classList.add('scanning');
    scanBtn.disabled = true;
    progress.style.display = 'block';
    progressText.textContent = 'Scanning...';
    progressFill.style.width = '0%';

    healthProgressTimer = setInterval(function() {
      progressPercent = Math.min(90, progressPercent + 2 + Math.random() * 3);
      progressFill.style.width = Math.round(progressPercent) + '%';
      if (progressPercent >= 90) stopHealthProgressTimer();
    }, 100);

    fetch('/api/health/scan')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.error) throw new Error('Scan error: ' + data.error);
        stopHealthProgressTimer();
        progressFill.style.width = '100%';
        progressText.textContent = 'Scan complete';
        setTimeout(function() {
          progress.style.display = 'none';
          progressText.textContent = 'Scanning...';
          progressFill.style.width = '0%';
        }, 500);
        header.classList.remove('scanning');
        scanBtn.disabled = false;
        renderHealthScore(data.summary, data.platform || {});
        renderDomainCards(data.checks || []);
        healthLoaded = true;
      })
      .catch(function(err) {
        resetHealthScanUi();
        showToast(err && err.message ? err.message : 'Failed to run security scan', 'error');
      });
  }

  function scoreColor(score) {
    if (score >= 80) return 'var(--green)';
    if (score >= 50) return 'var(--yellow)';
    return 'var(--red)';
  }

  function renderHealthScore(summary, platform) {
    document.getElementById('health-score').textContent = summary.score;
    var bar = document.getElementById('health-score-bar');
    bar.style.width = summary.score + '%';
    bar.style.background = scoreColor(summary.score);

    var meta = document.getElementById('health-meta');
    var parts = [];
    if (platform.os) parts.push('Platform: ' + platform.os);
    if (platform.arch) parts.push('Arch: ' + platform.arch);
    if (platform.nodeVersion) parts.push('Node: ' + platform.nodeVersion);
    if (platform.openclawVersion) parts.push('OpenClaw: ' + platform.openclawVersion);
    if (platform.isWSL2) parts.push('WSL2');
    meta.textContent = parts.join(' | ');

    var stats = document.getElementById('health-stats');
    stats.innerHTML =
      '<span class="health-stat"><span class="stat-icon" style="color:var(--green)">\\u2705</span> ' + summary.pass + ' pass</span>' +
      '<span class="health-stat"><span class="stat-icon" style="color:var(--yellow)">\\u26A0\\uFE0F</span> ' + summary.warn + ' warn</span>' +
      '<span class="health-stat"><span class="stat-icon" style="color:var(--red)">\\u274C</span> ' + summary.fail + ' fail</span>' +
      '<span class="health-stat"><span class="stat-icon" style="color:var(--text-dim)">\\u23ED\\uFE0F</span> ' + summary.skip + ' skip</span>';
  }

  function renderDomainCards(checks) {
    var domains = {};
    checks.forEach(function(c) {
      if (!domains[c.domain]) domains[c.domain] = [];
      domains[c.domain].push(c);
    });

    var container = document.getElementById('health-domains');
    container.innerHTML = '';

    Object.keys(domains).forEach(function(domain) {
      var items = domains[domain];
      var pass = items.filter(function(c) { return c.status === 'pass'; }).length;
      var total = items.length;
      var pct = total > 0 ? Math.round((pass / total) * 100) : 0;

      var card = document.createElement('div');
      card.className = 'domain-card';
      card.innerHTML =
        '<div class="domain-header">' +
          '<span class="domain-arrow">\\u25B8</span>' +
          '<span class="domain-name">' + escapeHtml(domain) + '</span>' +
          '<span class="domain-score">' + pass + '/' + total + '</span>' +
          '<div class="domain-bar"><div class="domain-bar-fill" style="width:' + pct + '%;background:' + scoreColor(pct) + '"></div></div>' +
        '</div>' +
        '<div class="domain-checks">' + items.map(function(c) {
          var icon = c.status === 'pass' ? '\\u2705' : c.status === 'fail' ? '\\u274C' : c.status === 'warn' ? '\\u26A0\\uFE0F' : '\\u23ED\\uFE0F';
          return '<div class="check-item">' +
            '<span class="check-icon">' + icon + '</span>' +
            '<div class="check-body">' +
              '<span class="check-name">' + escapeHtml(c.name) + '</span>' +
              '<div class="check-msg">' + escapeHtml(c.message) + '</div>' +
              (c.fix ? '<div class="check-fix">fix: ' + escapeHtml(c.fix) + '</div>' : '') +
            '</div>' +
          '</div>';
        }).join('') + '</div>';

      card.querySelector('.domain-header').addEventListener('click', function() {
        card.classList.toggle('expanded');
      });

      container.appendChild(card);
    });
  }

  // Expose globally for inline onclick handlers
  window.runHardenAction = function(action, mode) {
    var body = { action: action };
    if (mode) body.mode = mode;

    fetch('/api/health/harden', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    })
    .then(function(r) { return r.json(); })
    .then(function(result) {
      if (result.error) { showToast('Error: ' + result.error, 'error'); return; }
      appendHardenResult(result);
      showToast((result.success ? '\\u2705 ' : '\\u274C ') + result.name + ': ' + (result.success ? 'Success' : 'Failed'), result.success ? 'success' : 'error');
    })
    .catch(function() { showToast('Harden action failed', 'error'); });
  };

  function appendHardenResult(result) {
    var panel = document.getElementById('harden-results');
    var list = document.getElementById('harden-results-list');
    panel.style.display = 'block';

    var icon = result.success ? '\\u2705' : '\\u274C';
    var div = document.createElement('div');
    div.className = 'harden-result-item';
    div.innerHTML = icon + ' <strong>' + escapeHtml(result.name || result.id) + '</strong>: ' + escapeHtml(result.message) +
      (result.rollback ? '<span class="rollback">rollback: ' + escapeHtml(result.rollback) + '</span>' : '');
    list.insertBefore(div, list.firstChild);
  }

  function downloadReport() {
    fetch('/api/health/report')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.error) { showToast('Report error: ' + data.error, 'error'); return; }
        var blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        var url = URL.createObjectURL(blob);
        var a = document.createElement('a');
        a.href = url;
        a.download = 'security-report-' + new Date().toISOString().slice(0,19).replace(/[:.]/g,'-') + '.json';
        a.click();
        URL.revokeObjectURL(url);
        showToast('Report downloaded', 'success');
      })
      .catch(function() { showToast('Failed to generate report', 'error'); });
  }

  document.getElementById('btn-health-scan').addEventListener('click', loadHealthScan);
  document.getElementById('btn-health-report').addEventListener('click', downloadReport);
  setHealthInitialState();
  resetHealthScanUi();

  // Load scan on first tab switch
  document.querySelector('[data-tab="health"]').addEventListener('click', function() {
    if (!healthLoaded) loadHealthScan();
  });

  // ─── Rules Tab ───
  var rulesLoaded = false;
  var rulesState = {
    files: [],
    activeFile: '',
    currentFile: '',
    originalRules: [],
    draftRules: [],
    dirty: false,
  };

  var rulesFileSelect = document.getElementById('rules-file-select');
  var rulesMeta = document.getElementById('rules-meta');
  var rulesList = document.getElementById('rules-list');
  var btnRulesAdd = document.getElementById('btn-rules-add');
  var btnRulesUpload = document.getElementById('btn-rules-upload');
  var btnRulesDownload = document.getElementById('btn-rules-download');
  var btnRulesSave = document.getElementById('btn-rules-save');
  var rulesUploadInput = document.getElementById('rules-upload-input');

  function cloneJson(v) {
    return JSON.parse(JSON.stringify(v));
  }

  function normalizeRule(rule, idx) {
    return {
      id: rule && rule.id ? String(rule.id) : ('RULE-' + (idx + 1)),
      name: rule && rule.name ? String(rule.name) : 'New Rule',
      toolMatch: Array.isArray(rule && rule.toolMatch) ? rule.toolMatch.map(function(t) { return String(t); }) : ['*'],
      conditions: Array.isArray(rule && rule.conditions) ? rule.conditions : [],
      tier: (rule && (rule.tier === 'GREEN' || rule.tier === 'YELLOW' || rule.tier === 'RED')) ? rule.tier : 'YELLOW',
      reason: rule && rule.reason ? String(rule.reason) : '',
      priority: Number.isFinite(rule && rule.priority) ? Number(rule.priority) : 1000,
    };
  }

  function setRulesDirty(dirty) {
    rulesState.dirty = dirty;
    btnRulesSave.disabled = !dirty || !rulesState.currentFile;
    updateRulesMeta();
  }

  function updateRulesMeta() {
    var text = '';
    if (!rulesState.currentFile) {
      text = 'No rule file available. Put YAML files under ~/.openclaw/seclaw/rules.';
    } else {
      text = 'Editing: ' + rulesState.currentFile + ' | Active: ' + (rulesState.activeFile || '(none)');
      if (rulesState.dirty) text += ' | Unsaved changes';
    }
    rulesMeta.textContent = text;
    btnRulesAdd.disabled = !rulesState.currentFile;
    btnRulesUpload.disabled = !rulesState.currentFile;
    btnRulesDownload.disabled = !rulesState.currentFile;
  }

  function renderRules() {
    rulesList.innerHTML = '';
    if (!rulesState.currentFile) {
      updateRulesMeta();
      return;
    }
    if (rulesState.draftRules.length === 0) {
      var empty = document.createElement('div');
      empty.className = 'rule-item';
      empty.textContent = 'No rules in this file. Click Add Rule to create one.';
      rulesList.appendChild(empty);
      updateRulesMeta();
      return;
    }

    rulesState.draftRules.forEach(function(rule, idx) {
      var item = document.createElement('div');
      item.className = 'rule-item';

      var header = document.createElement('div');
      header.className = 'rule-item-header';
      var title = document.createElement('div');
      title.className = 'rule-item-title';
      title.textContent = (idx + 1) + '. ' + rule.id;
      var removeBtn = document.createElement('button');
      removeBtn.className = 'rule-item-remove';
      removeBtn.textContent = 'Remove';
      removeBtn.addEventListener('click', function() {
        rulesState.draftRules.splice(idx, 1);
        setRulesDirty(true);
        renderRules();
      });
      header.appendChild(title);
      header.appendChild(removeBtn);
      item.appendChild(header);

      var grid = document.createElement('div');
      grid.className = 'rule-grid';

      function field(label, value, inputType, onChange, full) {
        var container = document.createElement('div');
        container.className = 'rule-field' + (full ? ' full' : '');
        var lbl = document.createElement('label');
        lbl.textContent = label;
        var input = document.createElement(inputType === 'textarea' ? 'textarea' : 'input');
        if (inputType !== 'textarea' && inputType !== 'text') input.type = inputType;
        if (inputType === 'textarea') input.rows = 4;
        input.value = value;
        input.addEventListener('input', function() {
          onChange(input.value, input);
        });
        container.appendChild(lbl);
        container.appendChild(input);
        return container;
      }

      grid.appendChild(field('id', rule.id, 'text', function(v) {
        rule.id = v.trim();
        setRulesDirty(true);
      }));
      grid.appendChild(field('name', rule.name, 'text', function(v) {
        rule.name = v.trim();
        setRulesDirty(true);
      }));
      grid.appendChild(field('toolMatch (comma-separated)', (rule.toolMatch || []).join(', '), 'text', function(v) {
        rule.toolMatch = v.split(',').map(function(x) { return x.trim(); }).filter(Boolean);
        if (rule.toolMatch.length === 0) rule.toolMatch = ['*'];
        setRulesDirty(true);
      }));
      grid.appendChild(field('priority', String(rule.priority), 'number', function(v) {
        var p = parseInt(v, 10);
        if (!Number.isFinite(p)) p = 1000;
        rule.priority = p;
        setRulesDirty(true);
      }));

      var tierField = document.createElement('div');
      tierField.className = 'rule-field';
      var tierLabel = document.createElement('label');
      tierLabel.textContent = 'tier';
      var tierSelect = document.createElement('select');
      ['GREEN', 'YELLOW', 'RED'].forEach(function(t) {
        var opt = document.createElement('option');
        opt.value = t;
        opt.textContent = t;
        tierSelect.appendChild(opt);
      });
      tierSelect.value = rule.tier || 'YELLOW';
      tierSelect.addEventListener('change', function() {
        rule.tier = tierSelect.value;
        setRulesDirty(true);
      });
      tierField.appendChild(tierLabel);
      tierField.appendChild(tierSelect);
      grid.appendChild(tierField);

      grid.appendChild(field('reason', rule.reason || '', 'text', function(v) {
        rule.reason = v;
        setRulesDirty(true);
      }));

      grid.appendChild(field('conditions (JSON array)', JSON.stringify(rule.conditions || [], null, 2), 'textarea', function(v, input) {
        try {
          var parsed = JSON.parse(v || '[]');
          if (!Array.isArray(parsed)) throw new Error('not array');
          rule.conditions = parsed;
          input.style.borderColor = 'var(--border)';
          setRulesDirty(true);
        } catch(e) {
          input.style.borderColor = 'var(--red)';
        }
      }, true));

      item.appendChild(grid);
      rulesList.appendChild(item);
    });

    updateRulesMeta();
  }

  function loadRuleFile(fileName, skipDirtyPrompt) {
    if (!fileName) return;
    if (!skipDirtyPrompt && rulesState.dirty) {
      var ok = window.confirm('You have unsaved rule changes. Discard them and switch file?');
      if (!ok) {
        rulesFileSelect.value = rulesState.currentFile;
        return;
      }
    }
    fetch('/api/rules/file?name=' + encodeURIComponent(fileName))
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.error) { showToast(data.error, 'error'); return; }
        rulesState.currentFile = fileName;
        rulesState.originalRules = (data.rules || []).map(normalizeRule);
        rulesState.draftRules = cloneJson(rulesState.originalRules);
        setRulesDirty(false);
        renderRules();
      })
      .catch(function() { showToast('Failed to load rule file', 'error'); });
  }

  function loadRuleFiles() {
    fetch('/api/rules/files')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        rulesState.files = Array.isArray(data.files) ? data.files : [];
        rulesState.activeFile = data.activeRuleFile || '';
        rulesFileSelect.innerHTML = '';
        rulesState.files.forEach(function(fileName) {
          var opt = document.createElement('option');
          opt.value = fileName;
          opt.textContent = fileName + (fileName === rulesState.activeFile ? ' (active)' : '');
          rulesFileSelect.appendChild(opt);
        });

        var target = '';
        if (rulesState.currentFile && rulesState.files.indexOf(rulesState.currentFile) >= 0) target = rulesState.currentFile;
        else if (rulesState.activeFile && rulesState.files.indexOf(rulesState.activeFile) >= 0) target = rulesState.activeFile;
        else if (rulesState.files.length > 0) target = rulesState.files[0];

        if (!target) {
          rulesState.currentFile = '';
          rulesState.originalRules = [];
          rulesState.draftRules = [];
          setRulesDirty(false);
          renderRules();
          return;
        }

        rulesFileSelect.value = target;
        loadRuleFile(target, true);
      })
      .catch(function() { showToast('Failed to load rule files', 'error'); });
  }

  function saveRules() {
    if (!rulesState.currentFile) return;
    fetch('/api/rules/file?name=' + encodeURIComponent(rulesState.currentFile), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rules: rulesState.draftRules }),
    })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.error || data.ok === false) {
          showToast((data.error || (data.errors || []).join(', ') || 'Failed to save rules'), 'error');
          return;
        }
        return fetch('/api/rules/active', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: rulesState.currentFile }),
        })
          .then(function(r) { return r.json(); })
          .then(function(activeData) {
            if (activeData.error || activeData.ok === false) {
              showToast((activeData.error || (activeData.errors || []).join(', ') || 'Failed to set active rule file'), 'error');
              return;
            }
            rulesState.activeFile = rulesState.currentFile;
            rulesState.originalRules = cloneJson(rulesState.draftRules);
            setRulesDirty(false);
            showToast('Rules saved', 'success');
            loadRuleFiles();
          });
      })
      .catch(function() { showToast('Failed to save rules', 'error'); });
  }

  rulesFileSelect.addEventListener('change', function() {
    loadRuleFile(rulesFileSelect.value, false);
  });

  btnRulesAdd.addEventListener('click', function() {
    if (!rulesState.currentFile) return;
    rulesState.draftRules.push(normalizeRule({
      id: 'RULE-' + Date.now(),
      name: 'New Rule',
      toolMatch: ['*'],
      conditions: [],
      tier: 'YELLOW',
      priority: 1000,
      reason: '',
    }, rulesState.draftRules.length));
    setRulesDirty(true);
    renderRules();
  });

  btnRulesSave.addEventListener('click', saveRules);

  btnRulesDownload.addEventListener('click', function() {
    if (!rulesState.currentFile) return;
    window.location.href = '/api/rules/file/download?name=' + encodeURIComponent(rulesState.currentFile);
  });

  btnRulesUpload.addEventListener('click', function() {
    if (!rulesState.currentFile) return;
    rulesUploadInput.value = '';
    rulesUploadInput.click();
  });

  rulesUploadInput.addEventListener('change', function() {
    var file = rulesUploadInput.files && rulesUploadInput.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function() {
      var content = String(reader.result || '');
      fetch('/api/rules/file/parse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: content }),
      })
        .then(function(r) { return r.json(); })
        .then(function(data) {
          if (data.error) { showToast(data.error, 'error'); return; }
          rulesState.draftRules = (data.rules || []).map(normalizeRule);
          setRulesDirty(true);
          renderRules();
          showToast('YAML loaded (not saved yet)', 'success');
        })
        .catch(function() { showToast('Failed to parse uploaded YAML', 'error'); });
    };
    reader.readAsText(file);
  });

  document.querySelector('[data-tab="rules"]').addEventListener('click', function() {
    if (!rulesLoaded) {
      rulesLoaded = true;
      loadRuleFiles();
    }
  });
})();
</script>
</body>
</html>`;
}
