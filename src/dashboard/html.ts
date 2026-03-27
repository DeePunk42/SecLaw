/**
 * Embedded SPA dashboard — returns a complete HTML page as a string.
 * No external resources (no CDN, no font loading).
 */

export function getDashboardHtml(basePath: string = ""): string {
  let html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecLaw Dashboard</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=DM+Sans:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap');
:root {
  --bg: #07111f;
  --bg-card: #0a1628;
  --bg-input: #0e1c32;
  --border: #15283e;
  --hover: #1e3448;
  --b1: rgba(54,214,255,.08);
  --b2: rgba(54,214,255,.18);
  --text: #c8d8e8;
  --text-dim: #6b8a9e;
  --text-weak: #3d5a6e;
  --green: #3fd9a1;
  --yellow: #d7b14a;
  --red: #ff5d6c;
  --purple: #a855f7;
  --blue: #36d6ff;
  --font-mono: "DM Mono", "JetBrains Mono", "SF Mono", Menlo, Consolas, monospace;
  --font-ui: "DM Sans", "Noto Sans SC", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  --font-heading: "Space Grotesk", var(--font-ui);
  --user-scale: 1;
  --sw: 76px;
  --r: 10px;
}
*, *::before, *::after { margin: 0; padding: 0; box-sizing: border-box; }
body {
  font-family: var(--font-ui);
  background: var(--bg);
  color: var(--text);
  font-size: calc(14px * var(--user-scale));
  line-height: 1.6;
  min-height: 100vh;
  display: flex;
  -webkit-font-smoothing: antialiased;
}
body::before {
  content: ''; position: fixed; inset: 0; z-index: -1; pointer-events: none;
  background:
    radial-gradient(ellipse 70% 50% at 50% 30%, rgba(54,214,255,.04) 0%, transparent 60%),
    radial-gradient(ellipse 50% 40% at 30% 70%, rgba(11,39,66,.6) 0%, transparent 50%),
    radial-gradient(ellipse 100% 100% at 50% 100%, rgba(8,26,47,.7) 0%, transparent 60%);
}
::-webkit-scrollbar { width: 4px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
::-webkit-scrollbar-thumb:hover { background: var(--hover); }
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .01ms !important; transition-duration: .01ms !important; }
}

/* ─── Sidebar ─── */
.sidebar {
  position: fixed; top: 0; left: 0; bottom: 0; width: var(--sw);
  background: var(--bg-card); border-right: 1px solid var(--border);
  display: flex; flex-direction: column; z-index: 100;
}
.sb-logo {
  padding: 16px 0; text-align: center; border-bottom: 1px solid var(--border);
  font-family: var(--font-heading); font-size: 11px; font-weight: 600;
  color: var(--blue); letter-spacing: 1px; text-transform: uppercase;
}
.sb-logo .dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; background: var(--green); margin-right: 4px; vertical-align: middle; }
.sb-nav { flex: 1; display: flex; flex-direction: column; padding: 8px 0; }
.sb-btn {
  position: relative; display: flex; flex-direction: column; align-items: center; justify-content: center;
  gap: 4px; padding: 14px 0; border: none; background: none; cursor: pointer;
  color: var(--text-dim); font-size: 10px; font-family: var(--font-ui); transition: color .15s;
}
.sb-btn:hover { color: var(--text); background: rgba(54,214,255,.04); }
.sb-btn.active { color: var(--blue); }
.sb-btn.active::before {
  content: ''; position: absolute; left: 0; top: 8px; bottom: 8px; width: 3px;
  background: var(--blue); border-radius: 0 2px 2px 0;
  box-shadow: 0 0 8px rgba(54,214,255,.4);
}
.sb-btn svg { width: 20px; height: 20px; fill: none; stroke: currentColor; stroke-width: 1.5; stroke-linecap: round; stroke-linejoin: round; }
/* ─── Main Area ─── */
.main { margin-left: var(--sw); flex: 1; min-height: 100vh; }
.tab-content { display: none; padding: 20px 24px; }
.tab-content.active { display: block; }
.tab-title {
  font-family: var(--font-heading); font-size: 18px; font-weight: 600;
  margin-bottom: 16px; color: var(--text);
}

/* ─── Tool Call Cards ─── */
.log-toolbar {
  display: flex; gap: 8px; align-items: center; margin-bottom: 12px; flex-wrap: wrap;
}
.log-toolbar button {
  padding: 6px 12px; background: var(--bg-input); border: 1px solid var(--border);
  color: var(--text); border-radius: 6px; cursor: pointer; font-size: 12px; font-family: var(--font-ui);
  transition: all .15s;
}
.log-toolbar button:hover { background: var(--hover); border-color: var(--b2); }
.log-toolbar .count { color: var(--text-dim); font-size: 12px; margin-left: auto; font-family: var(--font-mono); }
.pill-group { display:flex; gap:2px; background:var(--bg-input); border-radius:6px; border:1px solid var(--border); padding:2px; }
.pill-btn { padding:4px 10px; border:none; background:transparent; color:var(--text-dim); border-radius:4px; cursor:pointer; font-size:11px; font-family:var(--font-mono); font-weight:600; text-transform:uppercase; transition: all .12s; }
.pill-btn:hover { color:var(--text); }
.pill-btn.active { background:var(--hover); color:var(--text); }
.pill-btn.active[data-value="GREEN"] { background:rgba(63,217,161,0.15); color:var(--green); }
.pill-btn.active[data-value="YELLOW"] { background:rgba(215,177,74,0.15); color:var(--yellow); }
.pill-btn.active[data-value="RED"] { background:rgba(255,93,108,0.15); color:var(--red); }
.pill-btn.active[data-value="blocked"] { background:rgba(255,93,108,0.15); color:var(--red); }
.pill-btn.active[data-value="danger"] { background:rgba(255,93,108,0.2); color:var(--red); }
.log-container { display:flex; gap:0; height:calc(100vh - 160px); }
.log-list { flex:0 0 60%; overflow-y:auto; padding-right:12px; border-right:1px solid var(--border); display:flex; flex-direction:column; gap:6px; }
.detail-panel { flex:0 0 40%; overflow-y:auto; padding-left:16px; position:sticky; top:0; align-self:flex-start; max-height:calc(100vh - 160px); }
.detail-placeholder { display:flex; align-items:center; justify-content:center; height:100%; color:var(--text-dim); font-size:13px; }
.detail-header { margin-bottom:12px; }
.detail-header .log-tool { font-size:14px; font-weight:600; font-family: var(--font-heading); }
.tc-card.selected { outline:1px solid var(--blue); outline-offset:-1px; }

.tc-card {
  background: var(--bg-card); border-radius: var(--r); padding: 10px 14px;
  border-left: 3px solid var(--border); font-size: 13px; cursor: pointer;
  border: 1px solid var(--b1); border-left: 3px solid var(--border);
  transition: transform .12s, border-color .15s, background .15s;
}
.tc-card:hover { transform: translateY(-1px); border-color: var(--b2); background: rgba(54,214,255,.02); }
.tc-card.tier-GREEN { border-left-color: var(--green); }
.tc-card.tier-YELLOW { border-left-color: var(--yellow); }
.tc-card.tier-RED { border-left-color: var(--red); }
.tc-card.status-blocked { background: rgba(255,93,108,0.06); }
.tc-card.status-overridden { background: rgba(168,85,247,0.06); }
.tc-card.danger { box-shadow: inset 0 0 0 1px rgba(255,93,108,0.4); }

.tc-card-header { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.log-time { color: var(--text-dim); font-size: 11px; font-family: var(--font-mono); }
.badge {
  display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px;
  font-weight: 600; text-transform: uppercase; font-family: var(--font-mono);
}
.badge-green { background: rgba(63,217,161,0.12); color: var(--green); }
.badge-yellow { background: rgba(215,177,74,0.12); color: var(--yellow); }
.badge-red { background: rgba(255,93,108,0.12); color: var(--red); }
.badge-event { background: rgba(54,214,255,0.12); color: var(--blue); }
.badge-danger { background: rgba(255,93,108,0.2); color: var(--red); }
.log-tool { font-family: var(--font-mono); font-size: 12px; color: var(--text); }

.tc-status {
  display: inline-flex; align-items: center; gap: 4px;
  padding: 1px 8px; border-radius: 3px; font-size: 10px;
  font-weight: 600; text-transform: uppercase; font-family: var(--font-mono);
}
.tc-status.allowed { background: rgba(63,217,161,0.12); color: var(--green); }
.tc-status.blocked { background: rgba(255,93,108,0.12); color: var(--red); }
.tc-status.pending { background: rgba(215,177,74,0.12); color: var(--yellow); }
.tc-status.overridden { background: rgba(168,85,247,0.12); color: var(--purple); }

.spinner {
  display: inline-block; width: 10px; height: 10px;
  border: 2px solid rgba(54,214,255,0.2); border-top-color: var(--blue);
  border-radius: 50%; animation: spin 0.8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }

@keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
.blink { animation: blink 1.5s ease-in-out infinite; }

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
  display: inline-block; padding: 2px 8px; background: rgba(255,93,108,0.15);
  border: 1px solid rgba(255,93,108,0.3); border-radius: 4px;
  font-family: var(--font-mono); font-size: 12px; color: var(--red);
  letter-spacing: 2px; font-weight: 600;
}

/* ─── Config Tab ─── */
.config-section { margin-bottom: 20px; }
.config-section h3 {
  font-size: 13px; font-family: var(--font-heading); color: var(--blue); margin-bottom: 10px;
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
  color: var(--text); border-radius: 6px; cursor: pointer; font-size: 11px;
  font-family: var(--font-ui); transition: all .15s;
}
.btn-mini:hover { border-color: var(--blue); background: var(--hover); }
.btn-mini:disabled { opacity: 0.5; cursor: default; }
.btn-save {
  padding: 8px 20px; background: var(--blue); border: none; color: var(--bg);
  border-radius: 6px; cursor: pointer; font-size: 13px; font-family: var(--font-ui);
  font-weight: 600; transition: opacity .15s;
}
.btn-save:hover { opacity: 0.9; }
.toast {
  position: fixed; top: 16px; right: 16px; padding: 10px 16px; border-radius: var(--r);
  font-size: 13px; z-index: 999; opacity: 0; transition: opacity 0.3s;
  backdrop-filter: blur(8px);
}
.toast.show { opacity: 1; }
.toast.success { background: rgba(63,217,161,0.9); color: var(--bg); }
.toast.error { background: rgba(255,93,108,0.9); color: #fff; }

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
.multi-select-item label:hover { background: rgba(54,214,255,.08); }
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
  background: var(--bg-card); border-radius: var(--r); padding: 20px 24px; margin-bottom: 16px;
  border: 1px solid var(--b1);
}
.health-header-top {
  display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px;
}
.health-header-top h2 { font-size: 18px; font-weight: 600; font-family: var(--font-heading); }
.health-header-top .health-actions { display: flex; gap: 8px; }
.health-btn {
  padding: 6px 14px; background: var(--bg-input); border: 1px solid var(--border);
  color: var(--text); border-radius: 6px; cursor: pointer; font-size: 12px; font-family: var(--font-ui);
  transition: all .15s;
}
.health-btn:hover { background: var(--hover); border-color: var(--b2); }
.health-btn.primary { background: var(--blue); border-color: var(--blue); color: var(--bg); font-weight: 600; }
.health-btn.primary:hover { opacity: 0.9; }

/* Hero score display */
.score-hero { display: flex; align-items: baseline; gap: 12px; margin-bottom: 8px; }
.score-hero .score-value { font-size: 48px; font-weight: 300; font-family: var(--font-heading); letter-spacing: -2px; }
.score-hero .score-max { font-size: 16px; color: var(--text-dim); font-family: var(--font-mono); }
.score-hero .score-grade {
  font-size: 28px; font-weight: 700; font-family: var(--font-heading);
  margin-left: auto; padding: 4px 12px; border-radius: 8px;
}
.score-hero .score-grade-label { font-size: 12px; font-family: var(--font-ui); font-weight: 500; }

.score-bar-container { margin-bottom: 12px; }
.score-bar {
  height: 6px; border-radius: 3px; background: var(--bg-input); overflow: hidden;
}
.score-bar-fill {
  height: 100%; border-radius: 3px; transition: width 0.5s ease;
}

/* Scan progress bar */
.scan-progress { margin: 8px 0; }
.scan-progress-text { font-size: 11px; color: var(--blue); margin-bottom: 4px; font-family: var(--font-mono); }
.scan-progress-bar {
  height: 4px; border-radius: 2px; background: var(--bg-input); overflow: hidden;
}
.scan-progress-fill {
  height: 100%; border-radius: 2px; background: var(--blue);
  width: 0%; transition: width 0.3s ease;
}

.health-meta { font-size: 11px; color: var(--text-dim); margin-bottom: 8px; font-family: var(--font-mono); }
.health-stats { display: flex; gap: 16px; flex-wrap: wrap; }
.health-stat {
  display: inline-flex; align-items: center; gap: 4px;
  font-size: 12px; font-family: var(--font-mono);
}
.health-stat .stat-icon { font-size: 14px; }

/* Scanning state: dim score and stats */
.health-header.scanning .score-hero { opacity: 0.3; }
.health-header.scanning .health-stats { opacity: 0.3; }
.health-header.scanning .health-meta { opacity: 0.3; }

.domain-cards { display: flex; flex-direction: column; gap: 8px; margin-bottom: 16px; }
.domain-card {
  background: var(--bg-card); border-radius: var(--r); overflow: hidden;
  border: 1px solid var(--b1); transition: border-color .15s;
}
.domain-card:hover { border-color: var(--b2); }
.domain-header {
  display: flex; align-items: center; gap: 12px; padding: 10px 14px; cursor: pointer;
  user-select: none;
}
.domain-header:hover { background: rgba(54,214,255,.04); }
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
  background: var(--bg-card); border-radius: var(--r); padding: 16px 20px; margin-bottom: 16px;
  border: 1px solid var(--b1);
}
.harden-panel h3 { font-size: 14px; font-weight: 600; margin-bottom: 12px; font-family: var(--font-heading); }
.harden-section { margin-bottom: 12px; }
.harden-section-title { font-size: 11px; color: var(--text-dim); margin-bottom: 6px; text-transform: uppercase; }
.harden-btns { display: flex; gap: 6px; flex-wrap: wrap; }
.harden-btn {
  padding: 5px 12px; background: var(--bg-input); border: 1px solid var(--border);
  color: var(--text); border-radius: 6px; cursor: pointer; font-size: 11px; font-family: var(--font-ui);
  transition: all .15s;
}
.harden-btn:hover { background: var(--hover); border-color: var(--b2); }
.harden-btn.high-risk { border-color: rgba(255,93,108,0.3); color: var(--red); }
.harden-btn.high-risk:hover { background: rgba(255,93,108,0.08); }
.harden-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.harden-divider { border: none; border-top: 1px solid var(--border); margin: 12px 0; }

.harden-results {
  background: var(--bg-card); border-radius: var(--r); padding: 16px 20px; margin-bottom: 16px;
  border: 1px solid var(--b1);
}
.harden-results h3 { font-size: 14px; font-weight: 600; margin-bottom: 8px; }
.harden-result-item {
  padding: 6px 0; font-size: 12px; border-bottom: 1px solid var(--border);
  font-family: var(--font-mono);
}
.harden-result-item:last-child { border-bottom: none; }
.harden-result-item .rollback { font-size: 10px; color: var(--text-dim); display: block; margin-top: 2px; }

/* ─── Domain Score Grid ─── */
.domain-grid {
  display: grid; grid-template-columns: repeat(4,1fr); gap: 14px;
  margin-bottom: 16px;
}
.dg-card {
  background: var(--bg-card); border: 1px solid var(--b1); border-radius: 14px;
  padding: 16px 18px; transition: border-color .2s, transform .2s;
  box-shadow: 0 1px 4px rgba(0,0,0,.15);
}
.dg-card:hover { border-color: var(--b2); transform: translateY(-2px); box-shadow: 0 4px 16px rgba(0,0,0,.2); }
.dg-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
.dg-name { font-family: var(--font-heading); font-size: 14px; font-weight: 700; color: var(--text); }
.dg-pct { font-family: var(--font-mono); font-size: 14px; font-weight: 600; color: var(--text-dim); }
.dg-track { height: 8px; border-radius: 4px; background: rgba(255,255,255,.04); overflow: hidden; }
.dg-fill { height: 100%; border-radius: 4px; transition: width 1s cubic-bezier(.22,1,.36,1); }
.dg-fill.green { background: linear-gradient(90deg, rgba(63,217,161,.3), var(--green)); }
.dg-fill.yellow { background: linear-gradient(90deg, rgba(215,177,74,.3), var(--yellow)); }
.dg-fill.red { background: linear-gradient(90deg, rgba(255,93,108,.3), var(--red)); }
.dg-fill.gray { background: linear-gradient(90deg, rgba(100,100,120,.15), var(--text-weak)); }

/* ─── Action Card Grid ─── */
.action-grid {
  display: grid; grid-template-columns: repeat(4,1fr); gap: 16px;
  margin-bottom: 16px;
}
.action-card {
  display: flex; flex-direction: column; gap: 8px; padding: 16px 18px;
  min-height: 110px; background: var(--bg-card); border: 1px solid var(--b1);
  border-radius: 14px; cursor: pointer; transition: all .15s;
  box-shadow: 0 2px 8px rgba(0,0,0,.15); position: relative; overflow: hidden;
}
.action-card::after {
  content: ''; position: absolute; bottom: 16px; left: 18px; right: 18px;
  height: 4px; border-radius: 2px;
  background: linear-gradient(90deg, transparent 0%, rgba(54,214,255,.6) 80%, #fff 100%);
  box-shadow: 0 0 12px rgba(54,214,255,.4); opacity: 0; transition: opacity .3s;
  pointer-events: none;
}
.action-card:hover { border-color: var(--b2); background: var(--bg-input); transform: translateY(-2px); }
.action-card:hover::after { opacity: 0.2; }
.action-card.selected { border-color: rgba(54,214,255,.25); background: rgba(54,214,255,.03); }
.action-card.selected::after { opacity: 0.8; }
.action-card.high-risk { border-left: 3px solid var(--red); }
.action-checkbox {
  width: 20px; height: 20px; accent-color: var(--blue); cursor: pointer;
  position: relative; z-index: 1; flex-shrink: 0;
}
.action-info { flex: 1; min-width: 0; position: relative; z-index: 1; }
.action-name {
  font-size: 13px; font-weight: 700; font-family: var(--font-heading);
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap;
}
.action-desc { font-size: 11px; color: var(--text-dim); margin-top: 4px; line-height: 1.5; }
.action-domain {
  display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 9px;
  font-family: var(--font-mono); background: rgba(54,214,255,.08); color: var(--blue);
  margin-top: 4px;
}
.risk-badge {
  font-family: var(--font-mono); font-size: 10px; font-weight: 600;
  padding: 2px 6px; border-radius: 3px;
}
.risk-badge.low { background: rgba(63,217,161,.1); color: var(--green); }
.risk-badge.medium { background: rgba(215,177,74,.1); color: var(--yellow); }
.risk-badge.high { background: rgba(255,93,108,.1); color: var(--red); }

/* ─── Harden Header ─── */
.harden-header {
  display: flex; align-items: center; gap: 12px; margin-bottom: 16px; flex-wrap: wrap;
}
.harden-header h3 { font-size: 16px; font-weight: 600; font-family: var(--font-heading); margin: 0; }
.mode-toggle { display: flex; }

/* ─── Before/After Split ─── */
.harden-results-split {
  display: grid; grid-template-columns: 1fr 1fr; gap: 20px;
  margin-bottom: 16px;
}
.harden-results-left, .harden-results-right {
  background: var(--bg-card); border: 1px solid var(--b1); border-radius: 14px;
  padding: 20px; box-shadow: 0 1px 4px rgba(0,0,0,.12);
  display: flex; flex-direction: column; min-height: 0;
}
.harden-results-left h3, .harden-results-right h3 {
  font-size: 13px; font-family: var(--font-heading); font-weight: 600;
  margin-bottom: 12px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px;
}
.harden-results-scroll {
  flex: 1; overflow-y: auto; display: flex; flex-direction: column; gap: 6px;
  max-height: 300px;
}
.predicted-score-box {
  flex: 1; display: flex; flex-direction: column; align-items: center;
  justify-content: center; gap: 16px;
}
.predicted-score-row { display: flex; align-items: center; gap: 24px; }
.predicted-before, .predicted-after {
  display: flex; flex-direction: column; align-items: center; gap: 4px;
}
.predicted-label { font-size: 11px; color: var(--text-weak); font-weight: 600; letter-spacing: 1px; text-transform: uppercase; }
.predicted-num {
  font-family: var(--font-heading); font-size: 48px; font-weight: 700;
  line-height: 1; color: var(--text-dim);
}
.predicted-num.predicted-highlight {
  background: linear-gradient(180deg, #fff 20%, var(--green) 100%);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text;
}
.predicted-arrow { font-size: 28px; color: var(--blue); font-weight: 300; }
.predicted-grade-row { display: flex; align-items: center; gap: 16px; }
.predicted-grade-badge {
  font-family: var(--font-heading); font-size: 20px; font-weight: 700;
  padding: 4px 14px; border-radius: 16px;
  background: rgba(255,255,255,.04); color: var(--text-weak);
  border: 1px solid rgba(255,255,255,.06);
}
.predicted-grade-badge.predicted-grade-up {
  background: rgba(63,217,161,.08); color: var(--green);
  border-color: rgba(63,217,161,.12);
}
.predicted-arrow-small { font-size: 18px; color: var(--blue); }

/* ─── Report Area ─── */
.report-area {
  font-size: 12px; line-height: 1.8; min-height: 100px; max-height: 500px; overflow-y: auto;
}
.report-area h1 { font-family: var(--font-heading); font-size: 16px; font-weight: 700; margin-bottom: 10px; color: var(--blue); }
.report-area h2 { font-family: var(--font-heading); font-size: 13px; font-weight: 700; margin: 16px 0 6px; border-bottom: 1px solid var(--b1); padding-bottom: 4px; }
.report-area h3 { font-size: 11px; font-weight: 700; margin: 12px 0 4px; color: var(--text-dim); }
.report-area table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: 11px; }
.report-area th { text-align: left; padding: 5px 8px; background: var(--bg-input); border-bottom: 1px solid var(--b1); color: var(--text-dim); font-family: var(--font-mono); font-size: 10px; text-transform: uppercase; letter-spacing: .5px; }
.report-area td { padding: 5px 8px; border-bottom: 1px solid rgba(255,255,255,.02); }
.report-area code { background: rgba(54,214,255,.06); padding: 1px 4px; border-radius: 3px; font-size: 10px; color: var(--blue); font-family: var(--font-mono); }
.report-area blockquote { border-left: 2px solid var(--blue); padding-left: 10px; margin: 6px 0; color: var(--text-dim); }
.report-area ul, .report-area ol { padding-left: 20px; margin: 4px 0; }
.report-area li { margin: 2px 0; }

/* ─── Responsive ─── */
@media(max-width:1200px) { .domain-grid, .action-grid { grid-template-columns: repeat(2,1fr); } .harden-results-split { grid-template-columns: 1fr; } }
@media(max-width:600px) { .domain-grid, .action-grid { grid-template-columns: 1fr; } }

/* ─── Rules Tab ─── */
.rules-mode-toggle { margin-bottom: 12px; }
.rules-mode-section { }
.rules-file-tabs {
  display: flex; gap: 0; margin-bottom: 12px; border-bottom: 1px solid var(--border);
}
.rules-file-tab {
  padding: 8px 16px; font-size: 12px; font-family: var(--font-mono); cursor: pointer;
  border-bottom: 2px solid transparent; color: var(--text-dim); background: none; border-top: none;
  border-left: none; border-right: none; white-space: nowrap;
}
.rules-file-tab:hover { color: var(--text); background: rgba(54,214,255,.04); }
.rules-file-tab.active { color: var(--blue); border-bottom-color: var(--blue); }
.rules-file-tab.dimmed { opacity: 0.4; font-style: italic; }
.rules-file-tab.dimmed:hover { opacity: 0.6; }
.rules-file-tab.dimmed.active { opacity: 0.7; }
.badge-source {
  display: inline-block; padding: 1px 5px; border-radius: 3px; font-size: 9px;
  font-weight: 600; font-family: var(--font-mono); cursor: pointer;
  background: rgba(54,214,255,0.1); color: var(--blue);
}
.badge-source:hover { background: rgba(54,214,255,0.2); }
.rules-inactive-note {
  padding: 8px 14px; margin-bottom: 12px; border-radius: 6px; font-size: 12px;
  background: rgba(215,177,74,0.06); color: var(--yellow); border: 1px solid rgba(215,177,74,0.15);
}
.rules-toolbar {
  display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 12px;
}
.rules-toolbar select, .rules-toolbar button {
  padding: 6px 10px; background: var(--bg-input); border: 1px solid var(--border);
  color: var(--text); border-radius: 4px; font-size: 12px; font-family: var(--font-ui);
}
.rules-toolbar select { font-family: var(--font-mono); max-width: 180px; }
.rules-toolbar button { cursor: pointer; }
.rules-toolbar button:hover { background: var(--border); }
.rules-toolbar button.primary { background: var(--blue); border-color: var(--blue); color: #fff; }
.rules-toolbar button.primary:hover { opacity: 0.9; }
.rules-toolbar button:disabled { opacity: 0.5; cursor: default; }
.rules-toolbar .count { color: var(--text-dim); font-size: 12px; }
.rules-container { display: flex; gap: 0; height: calc(100vh - 280px); }
.rules-list-panel {
  flex: 0 0 60%; overflow-y: auto; padding-right: 12px; border-right: 1px solid var(--border);
  display: flex; flex-direction: column; gap: 6px;
}
.rules-detail-panel {
  flex: 0 0 40%; overflow-y: auto; padding-left: 16px;
  position: sticky; top: 0; align-self: flex-start; max-height: calc(100vh - 320px);
}
.rule-card {
  background: var(--bg-card); border-radius: var(--r); padding: 10px 14px;
  border-left: 3px solid var(--border); cursor: pointer; font-size: 13px;
  border: 1px solid var(--b1); border-left: 3px solid var(--border);
  transition: transform .12s, border-color .15s, background .15s;
}
.rule-card:hover { transform: translateY(-1px); border-color: var(--b2); background: rgba(54,214,255,.02); }
.rule-card.selected { outline: 1px solid var(--blue); outline-offset: -1px; }
.rule-card.tier-GREEN { border-left-color: var(--green); }
.rule-card.tier-YELLOW { border-left-color: var(--yellow); }
.rule-card.tier-RED { border-left-color: var(--red); }
.rule-card-id { font-family: var(--font-mono); font-size: 12px; font-weight: 600; }
.rule-card-name { color: var(--text-dim); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.rule-card-meta {
  display: flex; align-items: center; gap: 8px; margin-top: 4px; font-size: 11px; color: var(--text-dim);
}
.rule-card-meta .mono { font-family: var(--font-mono); }
.badge-platform {
  display: inline-block; padding: 1px 5px; border-radius: 3px; font-size: 9px;
  font-weight: 600; text-transform: uppercase; font-family: var(--font-mono);
  background: rgba(168,85,247,0.15); color: var(--purple);
}
.rule-tag {
  display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px;
  font-family: var(--font-mono); background: rgba(54,214,255,0.1); color: var(--blue);
}
.rule-detail-section { margin-bottom: 12px; }
.rule-detail-label {
  font-size: 10px; font-weight: 600; text-transform: uppercase; color: var(--text-dim);
  margin-bottom: 4px; font-family: var(--font-mono); letter-spacing: 0.5px;
}
.rule-detail-value {
  font-family: var(--font-mono); font-size: 12px; color: var(--text);
  background: var(--bg-input); border-radius: 4px; padding: 6px 8px; white-space: pre-wrap; word-break: break-all;
}
.rule-edit-field { margin-bottom: 10px; }
.rule-edit-field label {
  display: block; font-size: 10px; font-weight: 600; text-transform: uppercase;
  color: var(--text-dim); margin-bottom: 3px; font-family: var(--font-mono); letter-spacing: 0.5px;
}
.rule-edit-field input, .rule-edit-field select {
  width: 100%; padding: 5px 8px; background: var(--bg-input); border: 1px solid var(--border);
  color: var(--text); border-radius: 4px; font-size: 12px; font-family: var(--font-mono); box-sizing: border-box;
}
.rule-edit-field textarea {
  width: 100%; padding: 5px 8px; background: var(--bg-input); border: 1px solid var(--border);
  color: var(--text); border-radius: 4px; font-size: 12px; font-family: var(--font-mono);
  resize: vertical; min-height: 80px; box-sizing: border-box;
}
.rule-edit-actions {
  display: flex; gap: 6px; margin-top: 12px;
}
.rule-edit-actions button {
  padding: 5px 12px; border-radius: 4px; font-size: 12px; cursor: pointer; border: 1px solid var(--border);
  background: var(--bg-input); color: var(--text); font-family: var(--font-ui);
}
.rule-edit-actions button.primary { background: var(--blue); border-color: var(--blue); color: #fff; }
.rule-edit-actions button.danger { background: var(--red); border-color: var(--red); color: #fff; }
.rule-edit-actions button:hover { opacity: 0.9; }
.test-panel {
  background: var(--bg-card); border-radius: var(--r); margin-bottom: 12px; overflow: hidden;
  border: 1px solid var(--b1);
}
.test-panel-header {
  padding: 10px 14px; cursor: pointer; font-size: 13px; font-weight: 600;
  user-select: none; color: var(--text-dim);
}
.test-panel-header:hover { color: var(--text); }
.test-panel-body { padding: 0 14px 14px; }
.test-panel-body.collapsed { display: none; }
.test-panel-body input, .test-panel-body select {
  width: 100%; padding: 6px 10px; background: var(--bg-input); border: 1px solid var(--border);
  color: var(--text); border-radius: 4px; font-size: 12px; font-family: var(--font-mono);
}
.test-panel-body button {
  padding: 6px 14px; background: var(--blue); border: 1px solid var(--blue);
  color: #fff; border-radius: 4px; cursor: pointer; font-size: 12px; font-family: var(--font-ui);
}
.test-panel-body button:hover { opacity: 0.9; }
.test-input-hint {
  margin-top: 6px; font-size: 11px; color: var(--text-dim); font-family: var(--font-mono);
}
.test-result {
  margin-top: 8px; padding: 8px 10px; border-radius: 4px; font-size: 12px;
  font-family: var(--font-mono); border-left: 3px solid var(--border); background: var(--bg-input);
}
.test-result.tier-GREEN { border-left-color: var(--green); }
.test-result.tier-YELLOW { border-left-color: var(--yellow); }
.test-result.tier-RED { border-left-color: var(--red); }
.test-result.error { border-left-color: var(--red); color: var(--red); }

/* ─── Placeholder pages ─── */
.placeholder {
  display: flex; flex-direction: column; align-items: center; justify-content: center;
  min-height: 300px; color: var(--text-dim);
}
.placeholder h2 { font-size: 20px; margin-bottom: 8px; color: var(--text); }
.placeholder p { font-size: 14px; }

/* ─── Login Overlay ─── */
.login-overlay { position:fixed; inset:0; z-index:1000; background:rgba(4,8,18,0.9); backdrop-filter:blur(8px); display:flex; align-items:center; justify-content:center; }
.login-overlay.hidden { display:none; }
.login-card { background:var(--bg-card); border:1px solid var(--b2); border-radius:var(--r); padding:32px; width:340px; text-align:center; }
.login-card h2 { font-size:18px; margin-bottom:4px; }
.login-sub { font-size:13px; color:var(--text-dim); margin-bottom:16px; }
.login-card input { width:100%; padding:10px 12px; background:var(--bg-input); border:1px solid var(--border); border-radius:4px; color:var(--text); font-size:14px; font-family:var(--font-mono); margin-bottom:8px; }
.login-card input:focus { outline:none; border-color:var(--blue); }
.login-error { color:var(--red); font-size:12px; min-height:18px; margin-bottom:8px; }
.login-card button { width:100%; padding:10px; background:var(--blue); border:none; border-radius:4px; color:#fff; font-size:14px; cursor:pointer; }
.login-card button:hover { opacity:0.9; }
</style>
</head>
<body>
<div id="login-overlay" class="login-overlay hidden">
  <div class="login-card">
    <h2>SecLaw Dashboard</h2>
    <div class="login-sub">Enter your API token to continue</div>
    <input id="login-token" type="password" placeholder="Bearer token" autocomplete="off" />
    <div id="login-error" class="login-error"></div>
    <button id="login-submit">Authenticate</button>
  </div>
</div>
<div class="sidebar">
  <div class="sb-logo"><span class="dot"></span>SecLaw</div>
  <div class="sb-nav">
    <button class="sb-btn active" data-tab="logs">
      <svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/></svg>
      <span>Audit</span>
    </button>
    <button class="sb-btn" data-tab="config">
      <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
      <span>Config</span>
    </button>
    <button class="sb-btn" data-tab="health">
      <svg viewBox="0 0 24 24"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
      <span>Health</span>
    </button>
    <button class="sb-btn" data-tab="rules">
      <svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      <span>Rules</span>
    </button>
  </div>
</div>
<div class="main">

<!-- Tab 1: Audit Log (Tool Call Cards) -->
<div id="tab-logs" class="tab-content active">
  <div class="log-toolbar">
    <div class="pill-group" id="pill-tier">
      <button class="pill-btn active" data-value="">ALL</button>
      <button class="pill-btn" data-value="GREEN">GREEN</button>
      <button class="pill-btn" data-value="YELLOW">YELLOW</button>
      <button class="pill-btn" data-value="RED">RED</button>
    </div>
    <div class="pill-group" id="pill-status">
      <button class="pill-btn active" data-value="">ALL</button>
      <button class="pill-btn" data-value="blocked">Blocked</button>
      <button class="pill-btn" data-value="danger">Danger</button>
    </div>
    <button id="btn-pause">Pause</button>
    <span class="count" id="log-count">0 calls</span>
  </div>
  <div class="log-container">
    <div class="log-list" id="log-list"></div>
    <div class="detail-panel" id="detail-panel">
      <div class="detail-placeholder">Select a log entry to view details</div>
    </div>
  </div>
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
    <h3>Dashboard</h3>
    <div class="config-field"><label>Enabled</label><input id="cfg-dashboard-enabled" type="checkbox" disabled title="Requires restart"><span class="config-hint">Requires restart</span></div>
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
        <div class="score-hero">
          <span class="score-value" id="health-score">—</span><span class="score-max">/100</span>
          <span class="score-grade" id="health-grade" style="display:none">
            <span id="health-grade-letter"></span>
            <span class="score-grade-label" id="health-grade-label"></span>
          </span>
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

    <!-- Domain Score Grid -->
    <div class="domain-grid" id="domain-grid"></div>

    <!-- Detailed Domain Cards (collapsible) -->
    <div class="domain-cards" id="health-domains"></div>

    <!-- Hardening Actions -->
    <div class="harden-panel">
      <div class="harden-header">
        <h3>安全加固</h3>
        <div class="pill-group mode-toggle" id="mode-toggle">
          <button class="pill-btn active" data-mode="balanced">Balanced</button>
          <button class="pill-btn" data-mode="paranoid">Paranoid</button>
        </div>
        <span style="flex:1"></span>
        <button class="health-btn" id="btn-select-all">全选</button>
        <button class="health-btn primary" id="btn-run-selected" disabled>执行选中项 (0)</button>
      </div>
      <div class="action-grid" id="action-grid"></div>
    </div>

    <!-- Results + Before/After -->
    <div class="harden-results-split" id="harden-results-split" style="display:none">
      <div class="harden-results-left">
        <h3>执行结果</h3>
        <div class="harden-results-scroll" id="harden-results-list"></div>
      </div>
      <div class="harden-results-right">
        <h3>加固后评分</h3>
        <div class="predicted-score-box">
          <div class="predicted-score-row">
            <div class="predicted-before">
              <span class="predicted-label">加固前</span>
              <span class="predicted-num" id="predicted-before-score">—</span>
            </div>
            <div class="predicted-arrow">&#x2192;</div>
            <div class="predicted-after">
              <span class="predicted-label">加固后</span>
              <span class="predicted-num predicted-highlight" id="predicted-after-score">—</span>
            </div>
          </div>
          <div class="predicted-grade-row">
            <span class="predicted-grade-badge" id="predicted-before-grade">—</span>
            <span class="predicted-arrow-small">&#x2192;</span>
            <span class="predicted-grade-badge predicted-grade-up" id="predicted-after-grade">—</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Report Panel -->
    <div class="harden-panel" id="report-panel" style="display:none">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h3 style="font-family:var(--font-heading);font-size:14px;font-weight:600;margin:0">安全报告</h3>
        <button class="health-btn" id="btn-export-report">导出 Markdown</button>
      </div>
      <div class="report-area" id="report-content"></div>
    </div>
  </div>
</div>

<!-- Tab 4: Rules -->
<div id="tab-rules" class="tab-content">
  <!-- Mode Toggle -->
  <div class="rules-mode-toggle">
    <div class="pill-group" id="pill-rules-mode">
      <button class="pill-btn active" data-value="files">Rule Files</button>
      <button class="pill-btn" data-value="effective">Effective Rules</button>
    </div>
  </div>

  <!-- ── Rule Files Mode ── -->
  <div id="rules-mode-files" class="rules-mode-section">
    <div class="rules-file-tabs" id="rules-file-tabs"></div>
    <div id="rules-inactive-note" class="rules-inactive-note" style="display:none"></div>
    <div class="rules-toolbar">
      <div class="pill-group" id="pill-rules-tier-files">
        <button class="pill-btn active" data-value="">ALL</button>
        <button class="pill-btn" data-value="GREEN">GREEN</button>
        <button class="pill-btn" data-value="YELLOW">YELLOW</button>
        <button class="pill-btn" data-value="RED">RED</button>
      </div>
      <span class="count" id="rules-count-files">0 rules</span>
      <span style="margin-left:auto"></span>
      <button id="btn-rules-add">+ Add</button>
      <button id="btn-rules-upload">Upload</button>
      <button id="btn-rules-download">Download</button>
      <button id="btn-rules-save" class="primary" disabled>Save</button>
      <input id="rules-upload-input" type="file" accept=".yaml,.yml" style="display:none">
    </div>
    <div class="rules-container">
      <div class="rules-list-panel" id="rules-list-files"></div>
      <div class="rules-detail-panel" id="rules-detail-files">
        <div class="detail-placeholder">Select a rule to view details</div>
      </div>
    </div>
  </div>

  <!-- ── Effective Rules Mode ── -->
  <div id="rules-mode-effective" class="rules-mode-section" style="display:none">
    <div class="test-panel">
      <div class="test-panel-header" id="test-panel-toggle">&#x25B6; Rule Tester</div>
      <div class="test-panel-body collapsed" id="test-panel-body">
        <div style="display:flex;gap:8px;margin-bottom:8px;align-items:center">
          <select id="test-tool-name" style="flex:0 0 220px"></select>
          <button id="btn-test-rule">Test</button>
        </div>
        <input id="test-input-value" placeholder="Enter command/path/url/query content">
        <div id="test-input-hint" class="test-input-hint"></div>
        <div id="test-result" class="test-result" style="display:none"></div>
      </div>
    </div>
    <div class="rules-toolbar">
      <div class="pill-group" id="pill-rules-tier-effective">
        <button class="pill-btn active" data-value="">ALL</button>
        <button class="pill-btn" data-value="GREEN">GREEN</button>
        <button class="pill-btn" data-value="YELLOW">YELLOW</button>
        <button class="pill-btn" data-value="RED">RED</button>
      </div>
      <span class="count" id="rules-count-effective">0 rules</span>
    </div>
    <div class="rules-container">
      <div class="rules-list-panel" id="rules-list-effective"></div>
      <div class="rules-detail-panel" id="rules-detail-effective">
        <div class="detail-placeholder">Select a rule to view details</div>
      </div>
    </div>
  </div>
</div>

</div><!-- /.main -->
<div class="toast" id="toast"></div>

<script>
(function() {
  // ─── Auth Layer ───
  function findGatewayToken() {
    try {
      for (var i = 0; i < sessionStorage.length; i++) {
        var key = sessionStorage.key(i);
        if (key && key.indexOf('openclaw.control.token.v1:') === 0) {
          var val = sessionStorage.getItem(key);
          if (val && val.trim()) return val.trim();
        }
      }
    } catch(e) {}
    return '';
  }
  var _origFetch = window.fetch;
  var _dashToken = sessionStorage.getItem('seclaw_token') || findGatewayToken();

  window.fetch = function(url, opts) {
    opts = opts || {};
    if (_dashToken && typeof url === 'string' && url.indexOf('/api/') !== -1) {
      opts.headers = Object.assign({}, opts.headers || {}, {
        'Authorization': 'Bearer ' + _dashToken
      });
    }
    return _origFetch.call(window, url, opts).then(function(resp) {
      if (resp.status === 401) { showLoginOverlay(); throw new Error('Unauthorized'); }
      return resp;
    });
  };

  function showLoginOverlay() {
    var overlay = document.getElementById('login-overlay');
    overlay.classList.remove('hidden');
    var inp = document.getElementById('login-token');
    setTimeout(function() { inp.focus(); }, 50);
  }

  function attemptLogin() {
    var inp = document.getElementById('login-token');
    var errEl = document.getElementById('login-error');
    var token = inp.value.trim();
    if (!token) { errEl.textContent = 'Token is required'; return; }
    errEl.textContent = '';
    _origFetch('/api/health', { headers: { 'Authorization': 'Bearer ' + token } })
      .then(function(r) {
        if (r.status === 401) { errEl.textContent = 'Invalid token'; return; }
        _dashToken = token;
        sessionStorage.setItem('seclaw_token', token);
        location.reload();
      })
      .catch(function() { errEl.textContent = 'Connection failed'; });
  }

  document.getElementById('login-submit').addEventListener('click', attemptLogin);
  document.getElementById('login-token').addEventListener('keydown', function(e) {
    if (e.key === 'Enter') attemptLogin();
  });

  // Startup probe: check if auth is required
  if (!_dashToken) {
    _origFetch('/api/health').then(function(r) {
      if (r.status === 401) showLoginOverlay();
    }).catch(function() {});
  }

  // ─── Tab switching (sidebar) ───
  const navBtns = document.querySelectorAll('.sb-btn');
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
  const detailPanel = document.getElementById('detail-panel');
  const btnPause = document.getElementById('btn-pause');

  var records = new Map();
  var recordOrder = [];
  var activeTier = '';
  var activeStatus = '';
  var selectedToolCallId = null;
  let paused = false;
  let eventSource = null;

  // ─── Pill group event delegation ───
  document.getElementById('pill-tier').addEventListener('click', function(e) {
    var btn = e.target.closest('.pill-btn');
    if (!btn) return;
    this.querySelectorAll('.pill-btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    activeTier = btn.dataset.value || '';
    renderAll();
  });
  document.getElementById('pill-status').addEventListener('click', function(e) {
    var btn = e.target.closest('.pill-btn');
    if (!btn) return;
    this.querySelectorAll('.pill-btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    activeStatus = btn.dataset.value || '';
    renderAll();
  });

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
    if (activeTier && rec.tier !== activeTier) return false;
    if (activeStatus === 'blocked' && rec.finalStatus !== 'blocked') return false;
    if (activeStatus === 'danger' && !rec.dangerDetected) return false;
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

  function showDetail(toolCallId) {
    selectedToolCallId = toolCallId;
    var rec = records.get(toolCallId);
    if (!rec) {
      detailPanel.innerHTML = '<div class="detail-placeholder">Select a log entry to view details</div>';
      return;
    }
    var html = '<div class="detail-header">' +
      '<div class="tc-card-header" style="margin-bottom:8px">' +
        '<span class="log-time">' + relativeTime(rec.startedAt) + '</span>' +
        '<span class="log-tool">' + escapeHtml(rec.toolName) + '</span>' +
        (rec.tier ? '<span class="badge ' + tierBadgeClass(rec.tier) + '">' + rec.tier + '</span>' : '') +
        statusHtml(rec) +
        (rec.dangerDetected ? ' <span class="badge badge-danger">DANGER</span>' : '') +
      '</div></div>' +
      detailHtml(rec);
    detailPanel.innerHTML = html;
  }

  function renderCard(rec) {
    var div = document.createElement('div');
    var cls = 'tc-card';
    if (rec.tier) cls += ' tier-' + rec.tier;
    if (rec.finalStatus === 'blocked' || rec.finalStatus === 'overridden') cls += ' status-' + rec.finalStatus;
    if (rec.dangerDetected) cls += ' danger';
    if (selectedToolCallId === rec.toolCallId) cls += ' selected';
    div.className = cls;
    div.dataset.tcid = rec.toolCallId;

    div.innerHTML =
      '<div class="tc-card-header">' +
        '<span class="log-time">' + relativeTime(rec.startedAt) + '</span>' +
        '<span class="log-tool">' + escapeHtml(rec.toolName) + '</span>' +
        (rec.tier ? '<span class="badge ' + tierBadgeClass(rec.tier) + '">' + rec.tier + '</span>' : '') +
        statusHtml(rec) +
        (rec.dangerDetected ? ' <span class="badge badge-danger">DANGER</span>' : '') +
      '</div>';

    div.addEventListener('click', function() {
      var prev = logList.querySelector('.tc-card.selected');
      if (prev) prev.classList.remove('selected');
      div.classList.add('selected');
      showDetail(rec.toolCallId);
    });
    return div;
  }

  function renderAll() {
    logList.innerHTML = '';
    var filtered = recordOrder.filter(function(id) { var r = records.get(id); return r && matchesFilter(r); });
    for (var i = filtered.length - 1; i >= 0; i--) {
      logList.appendChild(renderCard(records.get(filtered[i])));
    }
    logCount.textContent = filtered.length + ' calls';
    // Restore selected card or show placeholder
    if (selectedToolCallId) {
      var selRec = records.get(selectedToolCallId);
      if (selRec && matchesFilter(selRec)) {
        var selEl = logList.querySelector('[data-tcid="' + selectedToolCallId + '"]');
        if (selEl) selEl.classList.add('selected');
        showDetail(selectedToolCallId);
      } else {
        detailPanel.innerHTML = '<div class="detail-placeholder">Select a log entry to view details</div>';
      }
    }
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
      var wasSelected = existingEl.classList.contains('selected');
      var newEl = renderCard(rec);
      if (wasSelected) newEl.classList.add('selected');
      existingEl.replaceWith(newEl);
    } else {
      logList.insertBefore(renderCard(rec), logList.firstChild);
    }
    logCount.textContent = recordOrder.filter(function(id) { var r = records.get(id); return r && matchesFilter(r); }).length + ' calls';

    // Refresh sidebar if the selected card was updated
    if (selectedToolCallId === rec.toolCallId) {
      showDetail(rec.toolCallId);
    }
  }

  btnPause.addEventListener('click', function() {
    paused = !paused;
    btnPause.textContent = paused ? 'Resume' : 'Pause';
    if (!paused) renderAll();
  });

  // Load initial tool calls
  fetch('/api/tool-calls?limit=500')
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
    fetch('/api/tool-calls?limit=500')
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

    var sseUrl = '/api/tool-calls/stream';
    if (_dashToken) sseUrl += '?token=' + encodeURIComponent(_dashToken);
    eventSource = new EventSource(sseUrl);

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
        // Dashboard (read-only)
        document.getElementById('cfg-dashboard-enabled').checked = cfg.dashboard?.enabled ?? true;
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
  // ─── Health Tab ───
  var healthLoaded = false;
  var healthProgressTimer = null;
  var lastScanData = null;
  var selectedActions = new Set();
  var hardenMode = 'balanced';
  var reportMarkdown = '';

  var SCAN_STAGES = [
    { label: '\\u68C0\\u6D4B: \\u7F51\\u7EDC\\u9694\\u79BB\\u7B56\\u7565', pct: 8 },
    { label: '\\u68C0\\u6D4B: \\u8BA4\\u8BC1\\u4E0E\\u5BC6\\u94A5\\u914D\\u7F6E', pct: 18 },
    { label: '\\u68C0\\u6D4B: \\u6267\\u884C\\u5B89\\u5168\\u7B56\\u7565', pct: 28 },
    { label: '\\u68C0\\u6D4B: \\u6587\\u4EF6\\u7CFB\\u7EDF\\u6743\\u9650', pct: 40 },
    { label: '\\u68C0\\u6D4B: \\u4F9B\\u5E94\\u94FE\\u5B89\\u5168', pct: 50 },
    { label: '\\u68C0\\u6D4B: Channel/PI \\u9632\\u5FA1', pct: 60 },
    { label: '\\u68C0\\u6D4B: Agent \\u884C\\u4E3A\\u4E0E\\u6C99\\u7BB1', pct: 72 },
    { label: '\\u68C0\\u6D4B: \\u76D1\\u63A7\\u5BA1\\u8BA1\\u914D\\u7F6E', pct: 82 },
    { label: '\\u751F\\u6210\\u5B89\\u5168\\u8BC4\\u4F30\\u62A5\\u544A...', pct: 92 },
  ];

  var HARDEN_ACTIONS = [
    { id: 'backup', name: '\\u5907\\u4EFD\\u914D\\u7F6E', desc: '\\u5907\\u4EFD\\u5F53\\u524D openclaw.json', risk: 'low', domain: '\\u914D\\u7F6E' },
    { id: 'deploy-config', name: '\\u90E8\\u7F72\\u5B89\\u5168\\u914D\\u7F6E', desc: '\\u5408\\u5E76\\u6A21\\u677F\\u5230 openclaw.json', risk: 'high', domain: '\\u914D\\u7F6E' },
    { id: 'validate', name: 'Schema \\u6821\\u9A8C', desc: '\\u8FD0\\u884C openclaw config validate', risk: 'low', domain: '\\u914D\\u7F6E' },
    { id: 'permissions', name: '\\u6743\\u9650\\u52A0\\u56FA', desc: 'chmod 600/700 \\u6216 icacls', risk: 'high', domain: '\\u6587\\u4EF6\\u7CFB\\u7EDF' },
    { id: 'baseline', name: '\\u54C8\\u5E0C\\u57FA\\u7EBF', desc: '\\u751F\\u6210 SHA-256 \\u914D\\u7F6E\\u57FA\\u7EBF', risk: 'low', domain: '\\u6587\\u4EF6\\u7CFB\\u7EDF' },
    { id: 'immutable-protect', name: '\\u4E0D\\u53EF\\u53D8\\u4FDD\\u62A4', desc: 'chattr/chflags \\u5BA1\\u8BA1\\u811A\\u672C', risk: 'high', domain: '\\u6587\\u4EF6\\u7CFB\\u7EDF' },
    { id: 'npmrc', name: '.npmrc \\u52A0\\u56FA', desc: 'ignore-scripts=true', risk: 'medium', domain: '\\u4F9B\\u5E94\\u94FE' },
    { id: 'deploy-agents', name: '\\u90E8\\u7F72 AGENTS.md', desc: '\\u5B89\\u5168\\u884C\\u4E3A\\u89C4\\u5219\\u6A21\\u677F', risk: 'medium', domain: 'Agent' },
    { id: 'deploy-audit', name: '\\u90E8\\u7F72\\u5BA1\\u8BA1\\u811A\\u672C', desc: '\\u590C\\u5236\\u591C\\u95F4\\u5BA1\\u8BA1\\u811A\\u672C', risk: 'medium', domain: '\\u76D1\\u63A7' },
    { id: 'git-backup', name: 'Git \\u707E\\u5907', desc: '\\u521D\\u59CB\\u5316 Git \\u5907\\u4EFD\\u4ED3\\u5E93', risk: 'medium', domain: '\\u76D1\\u63A7' },
    { id: 'audit', name: '\\u5B89\\u5168\\u5BA1\\u8BA1', desc: 'openclaw security audit --deep', risk: 'low', domain: '\\u76D1\\u63A7' },
    { id: 'firewall', name: '\\u9632\\u706B\\u5899\\u89C4\\u5219', desc: '\\u5E73\\u53F0\\u9632\\u706B\\u5899\\u914D\\u7F6E', risk: 'high', domain: '\\u7F51\\u7EDC' },
    { id: 'disk-encryption', name: '\\u78C1\\u76D8\\u52A0\\u5BC6', desc: '\\u68C0\\u6D4B\\u52A0\\u5BC6\\u72B6\\u6001 (\\u53EA\\u8BFB)', risk: 'low', domain: '\\u7F51\\u7EDC' },
    { id: 'channel-hint', name: 'Channel UID', desc: 'UID \\u914D\\u7F6E\\u63D0\\u793A', risk: 'low', domain: 'Channel' },
    { id: 'verify-hint', name: 'Cron \\u9A8C\\u8BC1', desc: '\\u90E8\\u7F72\\u540E\\u9A8C\\u8BC1\\u63D0\\u793A', risk: 'low', domain: '\\u76D1\\u63A7' },
  ];

  function scoreColor(score) {
    if (score >= 80) return 'var(--green)';
    if (score >= 50) return 'var(--yellow)';
    return 'var(--red)';
  }
  function scoreColorCls(score) {
    if (score >= 80) return 'green';
    if (score >= 50) return 'yellow';
    if (score > 0) return 'red';
    return 'gray';
  }

  var gradeColors = { A: 'var(--blue)', B: 'var(--green)', C: 'var(--yellow)', D: 'var(--red)', F: 'var(--red)' };
  var gradeLabels = { A: '\\u5B89\\u5168', B: '\\u9700\\u6539\\u8FDB', C: '\\u8106\\u5F31', D: '\\u5371\\u9669', F: '\\u4E0D\\u53EF\\u63A5\\u53D7' };

  function calcDomainScore(items) {
    var scored = items.filter(function(c) { return c.status !== 'n/a' && c.status !== 'skip'; });
    if (scored.length === 0) return -1;
    var p = scored.filter(function(c) { return c.status === 'pass'; }).length;
    var w = scored.filter(function(c) { return c.status === 'warn'; }).length;
    return Math.round(((p + w * 0.5) / scored.length) * 100);
  }

  function setHealthInitialState() {
    document.getElementById('health-score').textContent = '\\u2014';
    var bar = document.getElementById('health-score-bar');
    bar.style.width = '0%'; bar.style.background = 'var(--border)';
    document.getElementById('health-grade').style.display = 'none';
    document.getElementById('health-meta').textContent = '';
    document.getElementById('health-stats').innerHTML =
      '<span class="health-stat"><span class="stat-icon" style="color:var(--green)">\\u2705</span> \\u2014 pass</span>' +
      '<span class="health-stat"><span class="stat-icon" style="color:var(--yellow)">\\u26A0\\uFE0F</span> \\u2014 warn</span>' +
      '<span class="health-stat"><span class="stat-icon" style="color:var(--red)">\\u274C</span> \\u2014 fail</span>' +
      '<span class="health-stat"><span class="stat-icon" style="color:var(--blue)">\\uD83D\\uDD18</span> \\u2014 n/a</span>' +
      '<span class="health-stat"><span class="stat-icon" style="color:var(--text-dim)">\\u23ED\\uFE0F</span> \\u2014 skip</span>';
    document.getElementById('domain-grid').innerHTML = '';
    document.getElementById('health-domains').innerHTML = '';
  }

  function loadHealthScan() {
    var header = document.querySelector('#tab-health .health-header');
    var progress = document.getElementById('scan-progress');
    var progressText = document.getElementById('scan-progress-text');
    var progressFill = document.getElementById('scan-progress-fill');
    var scanBtn = document.getElementById('btn-health-scan');

    if (healthProgressTimer) { clearInterval(healthProgressTimer); healthProgressTimer = null; }
    header.classList.add('scanning');
    scanBtn.disabled = true;
    progress.style.display = 'block';
    progressFill.style.width = '0%';

    // Staged progress animation
    var stageIdx = 0;
    var dataReady = false;
    function nextStage() {
      if (stageIdx < SCAN_STAGES.length && !dataReady) {
        var s = SCAN_STAGES[stageIdx];
        progressText.textContent = s.label;
        progressFill.style.width = s.pct + '%';
        stageIdx++;
        healthProgressTimer = setTimeout(nextStage, 300 + Math.random() * 300);
      }
    }
    nextStage();

    fetch('/api/health/scan')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.error) throw new Error('Scan error: ' + data.error);
        dataReady = true;
        if (healthProgressTimer) { clearTimeout(healthProgressTimer); healthProgressTimer = null; }
        progressFill.style.width = '100%';
        progressText.textContent = '\\u626B\\u63CF\\u5B8C\\u6210';
        setTimeout(function() { progress.style.display = 'none'; progressFill.style.width = '0%'; }, 500);
        header.classList.remove('scanning');
        scanBtn.disabled = false;
        lastScanData = data;
        renderHealthScore(data.summary, data.platform || {});
        renderDomainGrid(data.checks || []);
        renderDomainCards(data.checks || []);
        autoGenerateReport(data);
        healthLoaded = true;
      })
      .catch(function(err) {
        dataReady = true;
        if (healthProgressTimer) { clearTimeout(healthProgressTimer); healthProgressTimer = null; }
        header.classList.remove('scanning');
        scanBtn.disabled = false;
        progress.style.display = 'none';
        showToast(err && err.message ? err.message : 'Failed to run scan', 'error');
      });
  }

  function renderHealthScore(summary, platform) {
    document.getElementById('health-score').textContent = summary.score;
    var bar = document.getElementById('health-score-bar');
    bar.style.width = summary.score + '%';
    bar.style.background = scoreColor(summary.score);
    var grade = summary.grade;
    if (grade) {
      var gradeEl = document.getElementById('health-grade');
      gradeEl.style.display = '';
      gradeEl.style.background = (gradeColors[grade] || 'var(--text-dim)').replace('var(', 'rgba(').replace(')', ',0.12)');
      gradeEl.style.color = gradeColors[grade] || 'var(--text-dim)';
      document.getElementById('health-grade-letter').textContent = grade;
      document.getElementById('health-grade-label').textContent = ' ' + (gradeLabels[grade] || '');
    }
    var meta = document.getElementById('health-meta');
    var parts = [];
    if (platform.os) parts.push(platform.os);
    if (platform.arch) parts.push(platform.arch);
    if (platform.nodeVersion) parts.push('Node ' + platform.nodeVersion);
    if (platform.openclawVersion) parts.push('OC ' + platform.openclawVersion);
    if (platform.isWSL2) parts.push('WSL2');
    if (summary.hasCriticalFail) parts.push('\\u26A0 CRITICAL');
    meta.textContent = parts.join(' \\u00B7 ');
    var naCount = summary.na || 0;
    var stats = document.getElementById('health-stats');
    stats.innerHTML =
      '<span class="health-stat"><span class="stat-icon" style="color:var(--green)">\\u2705</span> ' + summary.pass + ' pass</span>' +
      '<span class="health-stat"><span class="stat-icon" style="color:var(--yellow)">\\u26A0\\uFE0F</span> ' + summary.warn + ' warn</span>' +
      '<span class="health-stat"><span class="stat-icon" style="color:var(--red)">\\u274C</span> ' + summary.fail + ' fail</span>' +
      '<span class="health-stat"><span class="stat-icon" style="color:var(--blue)">\\uD83D\\uDD18</span> ' + naCount + ' n/a</span>' +
      '<span class="health-stat"><span class="stat-icon" style="color:var(--text-dim)">\\u23ED\\uFE0F</span> ' + summary.skip + ' skip</span>';
  }

  // ── Domain Score Grid (4-column) ──
  function renderDomainGrid(checks) {
    var domains = {};
    checks.forEach(function(c) { if (!domains[c.domain]) domains[c.domain] = []; domains[c.domain].push(c); });
    var grid = document.getElementById('domain-grid');
    grid.innerHTML = Object.keys(domains).map(function(d) {
      var pct = calcDomainScore(domains[d]);
      var display = pct >= 0 ? pct : 0;
      var label = pct >= 0 ? pct + '%' : 'N/A';
      var cls = pct >= 0 ? scoreColorCls(pct) : 'gray';
      return '<div class="dg-card"><div class="dg-head"><span class="dg-name">' + escapeHtml(d) + '</span><span class="dg-pct">' + label + '</span></div><div class="dg-track"><div class="dg-fill ' + cls + '" style="width:' + display + '%"></div></div></div>';
    }).join('');
  }

  // ── Detailed Domain Cards (collapsible) ──
  function renderDomainCards(checks) {
    var domains = {};
    checks.forEach(function(c) { if (!domains[c.domain]) domains[c.domain] = []; domains[c.domain].push(c); });
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
        '<div class="domain-header"><span class="domain-arrow">\\u25B8</span><span class="domain-name">' + escapeHtml(domain) + '</span><span class="domain-score">' + pass + '/' + total + '</span><div class="domain-bar"><div class="domain-bar-fill" style="width:' + pct + '%;background:' + scoreColor(pct) + '"></div></div></div>' +
        '<div class="domain-checks">' + items.map(function(c) {
          var icon = c.status === 'pass' ? '\\u2705' : c.status === 'fail' ? '\\u274C' : c.status === 'warn' ? '\\u26A0\\uFE0F' : c.status === 'n/a' ? '\\uD83D\\uDD18' : '\\u23ED\\uFE0F';
          return '<div class="check-item"><span class="check-icon">' + icon + '</span><div class="check-body"><span class="check-name">' + escapeHtml(c.name) + '</span><div class="check-msg">' + escapeHtml(c.message) + '</div>' + (c.fix && c.status !== 'pass' && c.status !== 'n/a' ? '<div class="check-fix">' + escapeHtml(c.fix) + '</div>' : '') + '</div></div>';
        }).join('') + '</div>';
      card.querySelector('.domain-header').addEventListener('click', function() { card.classList.toggle('expanded'); });
      container.appendChild(card);
    });
  }

  // ── Action Card Grid ──
  function renderActionGrid() {
    var grid = document.getElementById('action-grid');
    grid.innerHTML = '';
    HARDEN_ACTIONS.forEach(function(a) {
      var card = document.createElement('div');
      card.className = 'action-card' + (a.risk === 'high' ? ' high-risk' : '');
      card.innerHTML =
        '<div style="display:flex;gap:10px;align-items:flex-start"><input type="checkbox" class="action-checkbox" value="' + a.id + '">' +
        '<div class="action-info"><div class="action-name">' + a.name + ' <span class="risk-badge ' + a.risk + '">' + (a.risk === 'high' ? '\\u9AD8\\u5371' : a.risk === 'medium' ? '\\u4E2D\\u7B49' : '\\u5B89\\u5168') + '</span></div>' +
        '<div class="action-desc">' + a.desc + '</div>' +
        '<span class="action-domain">' + a.domain + '</span></div></div>';
      card.addEventListener('click', function(e) {
        if (e.target.type === 'checkbox') return;
        var chk = card.querySelector('.action-checkbox');
        chk.checked = !chk.checked;
        chk.dispatchEvent(new Event('change'));
      });
      card.querySelector('.action-checkbox').addEventListener('change', function() {
        if (this.checked) { selectedActions.add(a.id); card.classList.add('selected'); }
        else { selectedActions.delete(a.id); card.classList.remove('selected'); }
        updateRunBtn();
      });
      grid.appendChild(card);
    });
  }

  function updateRunBtn() {
    var btn = document.getElementById('btn-run-selected');
    btn.disabled = selectedActions.size === 0;
    btn.textContent = '\\u6267\\u884C\\u9009\\u4E2D\\u9879 (' + selectedActions.size + ')';
  }

  // ── Batch Execution + Before/After ──
  function runSelectedActions() {
    if (selectedActions.size === 0) return;
    var beforeScore = lastScanData ? lastScanData.summary.score : 0;
    var beforeGrade = lastScanData ? (lastScanData.summary.grade || '\\u2014') : '\\u2014';
    var split = document.getElementById('harden-results-split');
    var list = document.getElementById('harden-results-list');
    split.style.display = 'grid';
    list.innerHTML = '';
    document.getElementById('predicted-before-score').textContent = beforeScore;
    document.getElementById('predicted-before-grade').textContent = beforeGrade;
    document.getElementById('predicted-after-score').textContent = '...';
    document.getElementById('predicted-after-grade').textContent = '...';

    var actions = Array.from(selectedActions);
    var idx = 0;
    function next() {
      if (idx >= actions.length) {
        // Re-scan to get after score
        fetch('/api/health/scan').then(function(r) { return r.json(); }).then(function(data) {
          if (!data.error) {
            lastScanData = data;
            renderHealthScore(data.summary, data.platform || {});
            renderDomainGrid(data.checks || []);
            renderDomainCards(data.checks || []);
            autoGenerateReport(data);
            document.getElementById('predicted-after-score').textContent = data.summary.score;
            var ag = data.summary.grade || '\\u2014';
            var agEl = document.getElementById('predicted-after-grade');
            agEl.textContent = ag;
            if (data.summary.score > beforeScore) {
              agEl.className = 'predicted-grade-badge predicted-grade-up';
            }
          }
        }).catch(function() {});
        return;
      }
      var body = { action: actions[idx], mode: hardenMode };
      fetch('/api/health/harden', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
        .then(function(r) { return r.json(); })
        .then(function(result) {
          if (!result.error) {
            var icon = result.success ? '\\u2705' : '\\u274C';
            var div = document.createElement('div');
            div.className = 'harden-result-item';
            div.innerHTML = icon + ' <strong>' + escapeHtml(result.name || result.id) + '</strong>: ' + escapeHtml(result.message) + (result.rollback ? '<span class="rollback">rollback: ' + escapeHtml(result.rollback) + '</span>' : '');
            list.appendChild(div);
          }
          idx++; next();
        })
        .catch(function() { idx++; next(); });
    }
    next();
  }

  // ── Markdown Report ──
  function autoGenerateReport(data) {
    if (!data || !data.summary) return;
    var s = data.summary;
    var checks = data.checks || [];
    var date = new Date().toLocaleDateString('zh-CN');
    var lines = [
      '# OpenClaw \\u5B89\\u5168\\u8BC4\\u4F30\\u62A5\\u544A', '',
      '> \\u751F\\u6210\\u65F6\\u95F4: ' + date, '',
      '## \\u7EFC\\u5408\\u8BC4\\u5206', '',
      '| \\u6307\\u6807 | \\u503C |', '|------|------|',
      '| **\\u603B\\u5206** | **' + (s.score || 0) + '/100** |',
      '| **\\u7B49\\u7EA7** | ' + (s.grade || '\\u2014') + ' (' + (gradeLabels[s.grade] || '') + ') |',
      '| \\u901A\\u8FC7 | ' + (s.pass || 0) + ' |',
      '| \\u8B66\\u544A | ' + (s.warn || 0) + ' |',
      '| \\u5931\\u8D25 | ' + (s.fail || 0) + ' |',
      '| N/A | ' + ((s.na || 0) + (s.skip || 0)) + ' |', '',
      '## \\u57DF\\u8BE6\\u60C5', ''
    ];
    var grouped = {};
    checks.forEach(function(c) { var d = c.domain || 'Other'; if (!grouped[d]) grouped[d] = []; grouped[d].push(c); });
    Object.keys(grouped).forEach(function(domain) {
      var items = grouped[domain];
      var passed = items.filter(function(i) { return i.status === 'pass'; }).length;
      lines.push('### ' + domain + ' (' + passed + '/' + items.length + ' \\u901A\\u8FC7)', '');
      lines.push('| \\u72B6\\u6001 | \\u68C0\\u6D4B\\u9879 | \\u8BF4\\u660E |');
      lines.push('|------|--------|------|');
      items.forEach(function(c) {
        var icon = c.status === 'pass' ? '\\u2705' : c.status === 'fail' ? '\\u274C' : c.status === 'warn' ? '\\u26A0\\uFE0F' : '\\u2796';
        lines.push('| ' + icon + ' | ' + c.name + ' | ' + (c.message || '').replace(/\\n/g, ' ').substring(0, 80) + ' |');
      });
      var fixes = items.filter(function(i) { return i.fix && i.status !== 'pass' && i.status !== 'n/a'; });
      if (fixes.length > 0) {
        lines.push('', '**\\u5EFA\\u8BAE\\u4FEE\\u590D:**');
        fixes.forEach(function(f) { lines.push('- ' + f.name + ': \\x60' + f.fix + '\\x60'); });
      }
      lines.push('');
    });
    lines.push('---', '*\\u62A5\\u544A\\u7531 SecLaw \\u81EA\\u52A8\\u751F\\u6210*');
    reportMarkdown = lines.join('\\n');

    // Render to HTML
    var panel = document.getElementById('report-panel');
    panel.style.display = 'block';
    document.getElementById('report-content').innerHTML = renderMarkdownToHtml(reportMarkdown);
  }

  function renderMarkdownToHtml(md) {
    var BT = String.fromCharCode(96);
    var D = String.fromCharCode(36);
    return md
      .replace(/^### (.+)$/gm, '<h3>' + D + '1</h3>')
      .replace(/^## (.+)$/gm, '<h2>' + D + '1</h2>')
      .replace(/^# (.+)$/gm, '<h1>' + D + '1</h1>')
      .replace(/^> (.+)$/gm, '<blockquote>' + D + '1</blockquote>')
      .replace(/^---$/gm, '<hr>')
      .replace(/\\*\\*(.+?)\\*\\*/gm, '<strong>' + D + '1</strong>')
      .replace(/\\*(.+?)\\*/gm, '<em>' + D + '1</em>')
      .replace(new RegExp(BT + '([^' + BT + ']+)' + BT, 'g'), '<code>' + D + '1</code>')
      .replace(/^- (.+)$/gm, '<li>' + D + '1</li>')
      .replace(/^\\|(.+)\\|$/gm, function(match) {
        if (/^\\|[-:| ]+\\|$/.test(match)) return '';
        var cells = match.split('|').filter(function(c) { return c.trim(); });
        return '<tr>' + cells.map(function(c) { return '<td>' + c.trim() + '</td>'; }).join('') + '</tr>';
      })
      .replace(/\\n/g, '<br>');
  }

  function exportReport() {
    if (!reportMarkdown) { showToast('\\u8BF7\\u5148\\u5B8C\\u6210\\u626B\\u63CF', 'error'); return; }
    var blob = new Blob([reportMarkdown], { type: 'text/markdown' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'security-report-' + new Date().toISOString().slice(0, 10) + '.md';
    a.click();
    URL.revokeObjectURL(url);
    showToast('\\u62A5\\u544A\\u5DF2\\u4E0B\\u8F7D', 'success');
  }

  // ── Wire up events ──
  renderActionGrid();
  setHealthInitialState();
  document.getElementById('btn-health-scan').addEventListener('click', loadHealthScan);
  document.getElementById('btn-health-report').addEventListener('click', function() {
    var btn = document.getElementById('btn-health-report');
    btn.disabled = true;
    btn.textContent = '\\u751F\\u6210\\u4E2D...';
    fetch('/api/health/report')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.error) throw new Error(data.error);
        autoGenerateReport(data);
        showToast('\\u62A5\\u544A\\u5DF2\\u751F\\u6210', 'success');
      })
      .catch(function(err) { showToast(err.message || '\\u62A5\\u544A\\u751F\\u6210\\u5931\\u8D25', 'error'); })
      .finally(function() { btn.disabled = false; btn.textContent = 'Report'; });
  });
  document.getElementById('btn-run-selected').addEventListener('click', runSelectedActions);
  document.getElementById('btn-select-all').addEventListener('click', function() {
    var allSelected = selectedActions.size === HARDEN_ACTIONS.length;
    var checkboxes = document.querySelectorAll('.action-checkbox');
    checkboxes.forEach(function(chk) {
      chk.checked = !allSelected;
      chk.dispatchEvent(new Event('change'));
    });
  });
  document.getElementById('btn-export-report').addEventListener('click', exportReport);

  // Mode toggle — pre-select actions based on mode
  function applyModeDefaults(mode) {
    selectedActions.clear();
    document.querySelectorAll('.action-card').forEach(function(c) { c.classList.remove('selected'); });
    HARDEN_ACTIONS.forEach(function(a) {
      var chk = document.querySelector('.action-checkbox[value="' + a.id + '"]');
      if (!chk) return;
      var shouldCheck = mode === 'paranoid' ? true : (a.risk !== 'high');
      chk.checked = shouldCheck;
      if (shouldCheck) {
        selectedActions.add(a.id);
        chk.closest('.action-card').classList.add('selected');
      }
    });
    updateRunBtn();
  }

  document.querySelectorAll('#mode-toggle .pill-btn').forEach(function(btn) {
    btn.addEventListener('click', function() {
      document.querySelectorAll('#mode-toggle .pill-btn').forEach(function(b) { b.classList.remove('active'); });
      btn.classList.add('active');
      hardenMode = btn.dataset.mode;
      applyModeDefaults(hardenMode);
    });
  });

  // Apply balanced defaults on init
  applyModeDefaults('balanced');

  // Load scan on first tab switch
  document.querySelector('[data-tab="health"]').addEventListener('click', function() {
    if (!healthLoaded) loadHealthScan();
  });

  // ─── Rules Tab ───
  var rulesInitialized = false;
  var rs = {
    mode: 'files',
    // Rule Files mode
    filesMeta: [],
    platform: '',
    currentFile: '',
    fileRules: [],
    fileTierFilter: '',
    fileSelectedRuleId: null,
    dirty: false,
    // Effective Rules mode
    effectiveRules: [],
    effectiveTierFilter: '',
    effectiveSelectedRuleId: null,
  };

  // DOM refs
  var filesSection = document.getElementById('rules-mode-files');
  var effectiveSection = document.getElementById('rules-mode-effective');
  var fileTabsEl = document.getElementById('rules-file-tabs');
  var inactiveNoteEl = document.getElementById('rules-inactive-note');
  var filesListEl = document.getElementById('rules-list-files');
  var filesDetailEl = document.getElementById('rules-detail-files');
  var filesCountEl = document.getElementById('rules-count-files');
  var effListEl = document.getElementById('rules-list-effective');
  var effDetailEl = document.getElementById('rules-detail-effective');
  var effCountEl = document.getElementById('rules-count-effective');
  var btnRulesUpload = document.getElementById('btn-rules-upload');
  var btnRulesDownload = document.getElementById('btn-rules-download');
  var btnRulesSave = document.getElementById('btn-rules-save');
  var rulesUploadInput = document.getElementById('rules-upload-input');

  // ─── detectionToYaml (shared) ───
  function detectionToYaml(obj, indent) {
    indent = indent || 0;
    var pad = '  '.repeat(indent);
    var lines = [];
    for (var key in obj) {
      if (!obj.hasOwnProperty(key)) continue;
      var val = obj[key];
      if (val === null || val === undefined) continue;
      if (typeof val === 'object' && !Array.isArray(val)) {
        lines.push(pad + key + ':');
        lines.push(detectionToYaml(val, indent + 1));
      } else if (Array.isArray(val)) {
        lines.push(pad + key + ':');
        val.forEach(function(item) {
          lines.push(pad + '  - ' + JSON.stringify(item));
        });
      } else {
        lines.push(pad + key + ': ' + JSON.stringify(val));
      }
    }
    return lines.join('\\n');
  }

  // ─── Shared: render rule detail into a target element ───
  function renderRuleDetail(rule, targetEl, opts) {
    if (!rule) {
      targetEl.innerHTML = '<div class="detail-placeholder">Rule not found</div>';
      return;
    }
    opts = opts || {};
    var html = '';

    // Header
    html += '<div style="margin-bottom:12px">' +
      '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">' +
        '<span style="font-family:var(--font-mono);font-size:14px;font-weight:600">' + escapeHtml(rule.id) + '</span>' +
        '<span class="badge ' + tierBadgeClass(rule.tier) + '">' + rule.tier + '</span>' +
      '</div>' +
      '<div style="color:var(--text-dim);font-size:13px">' + escapeHtml(rule.name) + '</div>' +
    '</div>';

    // Source file (effective mode only)
    if (opts.showSource && rule.sourceFile) {
      html += '<div class="rule-detail-section">' +
        '<div class="rule-detail-label">Source File</div>' +
        '<div><span class="badge-source" data-file="' + escapeHtml(rule.sourceFile) + '">' + escapeHtml(rule.sourceFile) + '</span></div>' +
      '</div>';
    }

    // Tools
    html += '<div class="rule-detail-section">' +
      '<div class="rule-detail-label">Tools</div>' +
      '<div class="rule-detail-value">' + escapeHtml((rule.tool || []).join(', ')) + '</div>' +
    '</div>';

    // Platform
    if (rule.platform && rule.platform.length > 0) {
      html += '<div class="rule-detail-section">' +
        '<div class="rule-detail-label">Platform</div>' +
        '<div>' + rule.platform.map(function(p) {
          return '<span class="badge-platform">' + escapeHtml(p) + '</span>';
        }).join(' ') + '</div>' +
      '</div>';
    }

    // Priority
    html += '<div class="rule-detail-section">' +
      '<div class="rule-detail-label">Priority</div>' +
      '<div class="rule-detail-value">' + rule.priority + '</div>' +
    '</div>';

    // Reason
    if (rule.reason) {
      html += '<div class="rule-detail-section">' +
        '<div class="rule-detail-label">Reason</div>' +
        '<div class="rule-detail-value">' + escapeHtml(rule.reason) + '</div>' +
      '</div>';
    }

    // Tags
    if (rule.tags && rule.tags.length > 0) {
      html += '<div class="rule-detail-section">' +
        '<div class="rule-detail-label">Tags</div>' +
        '<div>' + rule.tags.map(function(t) {
          return '<span class="rule-tag">' + escapeHtml(t) + '</span>';
        }).join(' ') + '</div>' +
      '</div>';
    }

    // Detection
    if (rule.detection) {
      html += '<div class="rule-detail-section">' +
        '<div class="rule-detail-label">Detection</div>' +
        '<pre class="rule-detail-value">' + escapeHtml(detectionToYaml(rule.detection)) + '</pre>' +
      '</div>';
    }

    targetEl.innerHTML = html;

    // Wire up source badge click -> switch to file mode
    if (opts.showSource) {
      targetEl.querySelectorAll('.badge-source').forEach(function(badge) {
        badge.addEventListener('click', function() {
          switchToFileMode(badge.dataset.file);
        });
      });
    }
  }

  // ─── Shared: render rule card ───
  function createRuleCard(rule, selectedId, opts) {
    opts = opts || {};
    var card = document.createElement('div');
    var cls = 'rule-card tier-' + rule.tier;
    var cardKey = opts.useCompositeKey ? (rule.sourceFile || '') + ':' + rule.id : rule.id;
    if (selectedId === cardKey) cls += ' selected';
    card.className = cls;
    card.dataset.ruleId = rule.id;
    if (rule.sourceFile) card.dataset.sourceFile = rule.sourceFile;

    var toolText = (rule.tool || []).join(', ');
    var extraHtml = '';
    if (rule.platform && rule.platform.length > 0) {
      extraHtml += rule.platform.map(function(p) {
        return ' <span class="badge-platform">' + escapeHtml(p) + '</span>';
      }).join('');
    }
    if (opts.showSource && rule.sourceFile) {
      extraHtml += ' <span class="badge-source" data-file="' + escapeHtml(rule.sourceFile) + '">' + escapeHtml(rule.sourceFile) + '</span>';
    }

    card.innerHTML =
      '<div style="display:flex;align-items:center;gap:6px">' +
        '<span class="rule-card-id">' + escapeHtml(rule.id) + '</span>' +
        '<span class="badge ' + tierBadgeClass(rule.tier) + '">' + rule.tier + '</span>' +
      '</div>' +
      '<div class="rule-card-name">' + escapeHtml(rule.name) + '</div>' +
      '<div class="rule-card-meta">' +
        '<span class="mono">' + escapeHtml(toolText) + '</span>' +
        '<span>P:' + rule.priority + '</span>' +
        extraHtml +
      '</div>';

    return card;
  }

  // ═══════════════════════════════════════════
  // ─── Mode Switching ───
  // ═══════════════════════════════════════════

  document.getElementById('pill-rules-mode').addEventListener('click', function(e) {
    var btn = e.target.closest('.pill-btn');
    if (!btn) return;
    this.querySelectorAll('.pill-btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    var mode = btn.dataset.value || 'files';
    rs.mode = mode;
    if (mode === 'files') {
      filesSection.style.display = '';
      effectiveSection.style.display = 'none';
      if (rs.filesMeta.length === 0) loadFilesMeta();
    } else {
      filesSection.style.display = 'none';
      effectiveSection.style.display = '';
      if (rs.effectiveRules.length === 0) loadEffectiveRules();
    }
  });

  function switchToFileMode(fileName) {
    // Switch pill
    var pills = document.getElementById('pill-rules-mode').querySelectorAll('.pill-btn');
    pills.forEach(function(b) { b.classList.remove('active'); });
    pills[0].classList.add('active');
    rs.mode = 'files';
    filesSection.style.display = '';
    effectiveSection.style.display = 'none';
    // Select file tab
    if (fileName) {
      rs.currentFile = fileName;
      if (rs.filesMeta.length > 0) {
        renderFileTabs();
        loadFileRules(fileName);
      } else {
        loadFilesMeta(function() { loadFileRules(fileName); });
      }
    }
  }

  // ═══════════════════════════════════════════
  // ─── Rule Files Mode ───
  // ═══════════════════════════════════════════

  function loadFilesMeta(cb) {
    fetch('/api/rules/files/meta')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        rs.filesMeta = Array.isArray(data.files) ? data.files : [];
        rs.platform = data.platform || '';
        renderFileTabs();
        // Auto-select first file if none selected
        if (!rs.currentFile && rs.filesMeta.length > 0) {
          var firstActive = rs.filesMeta.find(function(f) { return f.active; });
          rs.currentFile = firstActive ? firstActive.name : rs.filesMeta[0].name;
          renderFileTabs();
          loadFileRules(rs.currentFile);
        } else if (rs.currentFile) {
          loadFileRules(rs.currentFile);
        }
        if (cb) cb();
      })
      .catch(function() { showToast('Failed to load rule files', 'error'); });
  }

  function renderFileTabs() {
    fileTabsEl.innerHTML = '';
    rs.filesMeta.forEach(function(fileMeta) {
      var tab = document.createElement('button');
      tab.className = 'rules-file-tab';
      if (fileMeta.name === rs.currentFile) tab.classList.add('active');
      if (!fileMeta.active) tab.classList.add('dimmed');
      tab.textContent = fileMeta.name;
      if (!fileMeta.active) {
        tab.title = 'Not active on ' + rs.platform;
      }
      tab.addEventListener('click', function() {
        rs.currentFile = fileMeta.name;
        rs.fileSelectedRuleId = null;
        rs.dirty = false;
        btnRulesSave.disabled = true;
        renderFileTabs();
        loadFileRules(fileMeta.name);
      });
      fileTabsEl.appendChild(tab);
    });
  }

  function loadFileRules(fileName) {
    var fileMeta = rs.filesMeta.find(function(f) { return f.name === fileName; });
    if (fileMeta && !fileMeta.active) {
      inactiveNoteEl.textContent = 'This file is not active on the current platform (' + rs.platform + '). Rules shown here do not affect classification.';
      inactiveNoteEl.style.display = '';
    } else {
      inactiveNoteEl.style.display = 'none';
    }
    fetch('/api/rules/file?name=' + encodeURIComponent(fileName))
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.error) {
          rs.fileRules = [];
          showToast(data.error, 'error');
        } else {
          rs.fileRules = data.rules || [];
        }
        renderFileRulesList();
      })
      .catch(function() { showToast('Failed to load rules from ' + fileName, 'error'); });
  }

  // Tier filter for files mode
  document.getElementById('pill-rules-tier-files').addEventListener('click', function(e) {
    var btn = e.target.closest('.pill-btn');
    if (!btn) return;
    this.querySelectorAll('.pill-btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    rs.fileTierFilter = btn.dataset.value || '';
    renderFileRulesList();
  });

  function markDirty() {
    rs.dirty = true;
    btnRulesSave.disabled = false;
  }

  function renderFileRulesList() {
    filesListEl.innerHTML = '';
    var filtered = rs.fileRules.filter(function(r) {
      if (rs.fileTierFilter && r.tier !== rs.fileTierFilter) return false;
      return true;
    });
    filesCountEl.textContent = filtered.length + ' rules';

    if (filtered.length === 0) {
      filesListEl.innerHTML = '<div class="detail-placeholder">No rules in this file</div>';
      return;
    }

    filtered.forEach(function(rule) {
      var card = createRuleCard(rule, rs.fileSelectedRuleId, {});
      card.addEventListener('click', function() {
        var prev = filesListEl.querySelector('.rule-card.selected');
        if (prev) prev.classList.remove('selected');
        card.classList.add('selected');
        rs.fileSelectedRuleId = rule.id;
        renderRuleEditForm(rule);
      });
      filesListEl.appendChild(card);
    });

    if (rs.fileSelectedRuleId) {
      var sel = rs.fileRules.find(function(r) { return r.id === rs.fileSelectedRuleId; });
      if (sel) renderRuleEditForm(sel);
      else filesDetailEl.innerHTML = '<div class="detail-placeholder">Select a rule to view details</div>';
    }
  }

  // ─── Rule Edit Form ───
  function renderRuleEditForm(rule) {
    var toolStr = (rule.tool || []).join(', ');
    var platformStr = (rule.platform || []).join(', ');
    var tagsStr = (rule.tags || []).join(', ');
    var detectionStr = '';
    if (rule.detection) {
      try { detectionStr = detectionToYaml(rule.detection); } catch(e) { detectionStr = JSON.stringify(rule.detection, null, 2); }
    }

    var html =
      '<div class="rule-edit-field">' +
        '<label>ID</label>' +
        '<input id="re-id" value="' + escapeHtml(rule.id || '') + '">' +
      '</div>' +
      '<div class="rule-edit-field">' +
        '<label>Name</label>' +
        '<input id="re-name" value="' + escapeHtml(rule.name || '') + '">' +
      '</div>' +
      '<div style="display:flex;gap:8px">' +
        '<div class="rule-edit-field" style="flex:1">' +
          '<label>Tier</label>' +
          '<select id="re-tier">' +
            '<option value="GREEN"' + (rule.tier === 'GREEN' ? ' selected' : '') + '>GREEN</option>' +
            '<option value="YELLOW"' + (rule.tier === 'YELLOW' ? ' selected' : '') + '>YELLOW</option>' +
            '<option value="RED"' + (rule.tier === 'RED' ? ' selected' : '') + '>RED</option>' +
          '</select>' +
        '</div>' +
        '<div class="rule-edit-field" style="flex:1">' +
          '<label>Priority</label>' +
          '<input id="re-priority" type="number" value="' + (rule.priority || 0) + '">' +
        '</div>' +
      '</div>' +
      '<div class="rule-edit-field">' +
        '<label>Tools (comma-separated)</label>' +
        '<input id="re-tool" value="' + escapeHtml(toolStr) + '">' +
      '</div>' +
      '<div class="rule-edit-field">' +
        '<label>Platform (comma-separated, optional)</label>' +
        '<input id="re-platform" value="' + escapeHtml(platformStr) + '" placeholder="e.g. linux, macos">' +
      '</div>' +
      '<div class="rule-edit-field">' +
        '<label>Reason (optional)</label>' +
        '<input id="re-reason" value="' + escapeHtml(rule.reason || '') + '">' +
      '</div>' +
      '<div class="rule-edit-field">' +
        '<label>Tags (comma-separated, optional)</label>' +
        '<input id="re-tags" value="' + escapeHtml(tagsStr) + '">' +
      '</div>' +
      '<div class="rule-edit-field">' +
        '<label>Detection (YAML)</label>' +
        '<textarea id="re-detection" rows="6">' + escapeHtml(detectionStr) + '</textarea>' +
      '</div>' +
      '<div class="rule-edit-actions">' +
        '<button class="primary" id="re-apply">Apply</button>' +
        '<button class="danger" id="re-delete">Delete</button>' +
      '</div>';

    filesDetailEl.innerHTML = html;

    document.getElementById('re-apply').addEventListener('click', function() {
      applyRuleEdit(rule);
    });
    document.getElementById('re-delete').addEventListener('click', function() {
      deleteRule(rule);
    });
  }

  function parseCommaSep(str) {
    return str.split(',').map(function(s) { return s.trim(); }).filter(function(s) { return s.length > 0; });
  }

  function parseDetectionYaml(str) {
    if (!str.trim()) return { any: {}, condition: 'any' };
    // detectionToYaml uses \\n as line separator in the template literal
    var lines = str.split(/\\\\n|\\n/);
    var result = {};
    var currentKey = null;
    var currentObj = null;
    var currentList = null;

    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var trimmed = line.replace(/^\\s+/, '');
      if (!trimmed) continue;

      // Top-level key (no leading space): "selection:" or "condition: ..."
      if (line === trimmed) {
        var colonIdx = trimmed.indexOf(':');
        if (colonIdx === -1) continue;
        var key = trimmed.substring(0, colonIdx);
        var val = trimmed.substring(colonIdx + 1).trim();
        if (val) {
          try { result[key] = JSON.parse(val); } catch(e) { result[key] = val; }
        } else {
          currentKey = key;
          currentObj = {};
          currentList = null;
          result[key] = currentObj;
        }
      } else if (currentKey) {
        // Nested: "  field|modifier: value" or "  - item"
        var nt = trimmed;
        if (nt.indexOf('- ') === 0) {
          // List item
          var item = nt.substring(2).trim();
          try { item = JSON.parse(item); } catch(e) {}
          if (!currentList) {
            // This list belongs to the last field in currentObj
            var objKeys = Object.keys(currentObj);
            if (objKeys.length > 0) {
              var lastKey = objKeys[objKeys.length - 1];
              if (!Array.isArray(currentObj[lastKey])) currentObj[lastKey] = [];
              currentList = currentObj[lastKey];
            } else {
              currentList = [];
            }
          }
          currentList.push(item);
        } else {
          currentList = null;
          var ci = nt.indexOf(':');
          if (ci === -1) continue;
          var fk = nt.substring(0, ci);
          var fv = nt.substring(ci + 1).trim();
          try { fv = JSON.parse(fv); } catch(e) {}
          currentObj[fk] = fv;
        }
      }
    }
    if (!result.condition) result.condition = 'any';
    return result;
  }

  function applyRuleEdit(originalRule) {
    var newId = (document.getElementById('re-id').value || '').trim();
    if (!newId) { showToast('Rule ID is required', 'error'); return; }

    var toolArr = parseCommaSep(document.getElementById('re-tool').value || '');
    if (toolArr.length === 0) { showToast('At least one tool is required', 'error'); return; }

    var platformArr = parseCommaSep(document.getElementById('re-platform').value || '');
    var tagsArr = parseCommaSep(document.getElementById('re-tags').value || '');
    var detectionText = document.getElementById('re-detection').value || '';
    var detection;
    try {
      detection = parseDetectionYaml(detectionText);
    } catch(e) {
      showToast('Invalid detection YAML', 'error');
      return;
    }

    var idx = rs.fileRules.indexOf(originalRule);
    if (idx === -1) return;

    rs.fileRules[idx] = {
      id: newId,
      name: (document.getElementById('re-name').value || '').trim() || newId,
      tier: document.getElementById('re-tier').value,
      priority: parseInt(document.getElementById('re-priority').value, 10) || 0,
      tool: toolArr,
      platform: platformArr.length > 0 ? platformArr : undefined,
      reason: (document.getElementById('re-reason').value || '').trim() || undefined,
      tags: tagsArr.length > 0 ? tagsArr : undefined,
      detection: detection,
    };

    rs.fileSelectedRuleId = newId;
    markDirty();
    renderFileRulesList();
    showToast('Rule updated (not saved yet)', 'success');
  }

  function deleteRule(rule) {
    var idx = rs.fileRules.indexOf(rule);
    if (idx === -1) return;
    rs.fileRules.splice(idx, 1);
    rs.fileSelectedRuleId = null;
    filesDetailEl.innerHTML = '<div class="detail-placeholder">Select a rule to view details</div>';
    markDirty();
    renderFileRulesList();
    showToast('Rule deleted (not saved yet)', 'success');
  }

  // ─── Add Rule ───
  document.getElementById('btn-rules-add').addEventListener('click', function() {
    if (!rs.currentFile) { showToast('No file selected', 'error'); return; }
    var prefix = 'NEW-';
    var num = 1;
    while (rs.fileRules.some(function(r) { return r.id === prefix + num; })) num++;
    var newRule = {
      id: prefix + num,
      name: 'New rule',
      tool: ['*'],
      tier: 'YELLOW',
      priority: 5000,
      detection: { any: {}, condition: 'any' },
    };
    rs.fileRules.push(newRule);
    rs.fileSelectedRuleId = newRule.id;
    markDirty();
    renderFileRulesList();
    // Scroll to bottom
    filesListEl.scrollTop = filesListEl.scrollHeight;
  });

  // ─── File Operations ───
  btnRulesDownload.addEventListener('click', function() {
    var file = rs.currentFile;
    if (!file) { showToast('No file selected', 'error'); return; }
    window.location.href = '/api/rules/file/download?name=' + encodeURIComponent(file);
  });

  btnRulesUpload.addEventListener('click', function() {
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
          rs.fileRules = data.rules || [];
          markDirty();
          renderFileRulesList();
          showToast('YAML loaded (' + rs.fileRules.length + ' rules, not saved yet)', 'success');
        })
        .catch(function() { showToast('Failed to parse uploaded YAML', 'error'); });
    };
    reader.readAsText(file);
  });

  btnRulesSave.addEventListener('click', function() {
    var targetFile = rs.currentFile;
    if (!targetFile || !rs.dirty) return;
    fetch('/api/rules/file?name=' + encodeURIComponent(targetFile), {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ rules: rs.fileRules }),
    })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        if (data.error || data.ok === false) {
          showToast((data.error || 'Failed to save rules'), 'error');
          return;
        }
        rs.dirty = false;
        btnRulesSave.disabled = true;
        showToast('Rules saved to ' + targetFile, 'success');
        // Reload to get clean state from disk
        loadFileRules(targetFile);
        // Reset effective rules cache so it reloads on next view
        rs.effectiveRules = [];
      })
      .catch(function() { showToast('Failed to save rules', 'error'); });
  });

  // ═══════════════════════════════════════════
  // ─── Effective Rules Mode ───
  // ═══════════════════════════════════════════

  function loadEffectiveRules() {
    fetch('/api/rules')
      .then(function(r) { return r.json(); })
      .then(function(data) {
        rs.effectiveRules = data.rules || [];
        rs.platform = data.platform || '';
        renderEffectiveRulesList();
      })
      .catch(function() { showToast('Failed to load effective rules', 'error'); });
  }

  // Tier filter for effective mode
  document.getElementById('pill-rules-tier-effective').addEventListener('click', function(e) {
    var btn = e.target.closest('.pill-btn');
    if (!btn) return;
    this.querySelectorAll('.pill-btn').forEach(function(b) { b.classList.remove('active'); });
    btn.classList.add('active');
    rs.effectiveTierFilter = btn.dataset.value || '';
    renderEffectiveRulesList();
  });

  function renderEffectiveRulesList() {
    effListEl.innerHTML = '';
    var filtered = rs.effectiveRules.filter(function(r) {
      if (rs.effectiveTierFilter && r.tier !== rs.effectiveTierFilter) return false;
      return true;
    });
    effCountEl.textContent = filtered.length + ' rules';

    if (filtered.length === 0) {
      effListEl.innerHTML = '<div class="detail-placeholder">No rules match the current filter</div>';
      return;
    }

    filtered.forEach(function(rule) {
      var compositeKey = (rule.sourceFile || '') + ':' + rule.id;
      var card = createRuleCard(rule, rs.effectiveSelectedRuleId, { showSource: true, useCompositeKey: true });
      card.addEventListener('click', function() {
        var prev = effListEl.querySelector('.rule-card.selected');
        if (prev) prev.classList.remove('selected');
        card.classList.add('selected');
        rs.effectiveSelectedRuleId = compositeKey;
        renderRuleDetail(rule, effDetailEl, { showSource: true });
      });
      // Source badge click in card -> switch to file mode
      card.querySelectorAll('.badge-source').forEach(function(badge) {
        badge.addEventListener('click', function(e) {
          e.stopPropagation();
          switchToFileMode(badge.dataset.file);
        });
      });
      effListEl.appendChild(card);
    });

    if (rs.effectiveSelectedRuleId) {
      var sel = rs.effectiveRules.find(function(r) {
        return (r.sourceFile || '') + ':' + r.id === rs.effectiveSelectedRuleId;
      });
      if (sel) renderRuleDetail(sel, effDetailEl, { showSource: true });
      else effDetailEl.innerHTML = '<div class="detail-placeholder">Select a rule to view details</div>';
    }
  }

  // ─── Test Panel Toggle ───
  document.getElementById('test-panel-toggle').addEventListener('click', function() {
    var body = document.getElementById('test-panel-body');
    var header = document.getElementById('test-panel-toggle');
    if (body.classList.contains('collapsed')) {
      body.classList.remove('collapsed');
      header.innerHTML = '&#x25BC; Rule Tester';
    } else {
      body.classList.add('collapsed');
      header.innerHTML = '&#x25B6; Rule Tester';
    }
  });

  // ─── Rule Tester ───
  var RULE_TESTER_TOOLS = [
    'exec', 'bash', 'fs_write', 'write', 'edit', 'apply_patch',
    'fs_read', 'read', 'fs_delete', 'fs_move', 'web_fetch', 'web_search',
  ];

  var RULE_TESTER_PATH_TOOLS = new Set([
    'fs_write', 'write', 'edit', 'apply_patch', 'fs_read', 'read', 'fs_delete', 'fs_move',
  ]);

  function getRuleTestValueMeta(toolName) {
    if (toolName === 'exec' || toolName === 'bash') {
      return { field: 'command', label: 'command', placeholder: 'e.g. rm -rf /tmp/build' };
    }
    if (toolName === 'web_fetch') {
      return { field: 'url', label: 'URL', placeholder: 'e.g. https://example.com/api/data' };
    }
    if (toolName === 'web_search') {
      return { field: 'query', label: 'query', placeholder: 'e.g. git rebase interactive' };
    }
    if (RULE_TESTER_PATH_TOOLS.has(toolName)) {
      return { field: 'path', label: 'path', placeholder: 'e.g. /workspace/src/index.ts' };
    }
    return { field: 'path', label: 'path', placeholder: 'e.g. /workspace/file.txt' };
  }

  function initRuleTesterForm() {
    var toolSelect = document.getElementById('test-tool-name');
    var valueInput = document.getElementById('test-input-value');
    var hintEl = document.getElementById('test-input-hint');
    if (!toolSelect || !valueInput || !hintEl) return;

    toolSelect.innerHTML = RULE_TESTER_TOOLS.map(function(tool) {
      return '<option value="' + tool + '">' + tool + '</option>';
    }).join('');
    toolSelect.value = RULE_TESTER_TOOLS[0];

    function refreshInputMeta() {
      var meta = getRuleTestValueMeta(toolSelect.value || '');
      valueInput.placeholder = meta.placeholder;
      hintEl.textContent = 'Mapped to params.' + meta.field;
    }
    toolSelect.addEventListener('change', refreshInputMeta);
    refreshInputMeta();
  }

  initRuleTesterForm();

  document.getElementById('btn-test-rule').addEventListener('click', function() {
    var toolName = document.getElementById('test-tool-name').value.trim();
    var value = document.getElementById('test-input-value').value.trim();
    var resultEl = document.getElementById('test-result');
    var meta = getRuleTestValueMeta(toolName);

    if (!toolName) {
      resultEl.style.display = 'block';
      resultEl.className = 'test-result error';
      resultEl.textContent = 'Please select a tool';
      return;
    }
    if (!value) {
      resultEl.style.display = 'block';
      resultEl.className = 'test-result error';
      resultEl.textContent = 'Please enter ' + meta.label + ' content';
      return;
    }

    var params = {};
    params[meta.field] = value;
    var valueField = meta.field;

    fetch('/api/rules/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ toolName: toolName, value: value, valueField: valueField }),
    })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        resultEl.style.display = 'block';
        if (data.error) {
          resultEl.className = 'test-result error';
          resultEl.textContent = 'Error: ' + data.error;
          return;
        }
        var tier = data.tier || 'YELLOW';
        resultEl.className = 'test-result tier-' + tier;
        var text = 'TIER: ' + tier;
        if (data.ruleId) {
          text += ' | Rule: ' + data.ruleId;
        } else {
          text += ' | No matching rule (default)';
        }
        if (data.reason) {
          text += '\\n' + data.reason;
        }
        resultEl.textContent = text;

        // Scroll to matched rule in effective list
        if (data.ruleId) {
          rs.effectiveTierFilter = '';
          var pillEff = document.getElementById('pill-rules-tier-effective');
          pillEff.querySelectorAll('.pill-btn').forEach(function(b) { b.classList.remove('active'); });
          pillEff.querySelector('[data-value=""]').classList.add('active');
          renderEffectiveRulesList();
          var targetCard = effListEl.querySelector('[data-rule-id="' + data.ruleId + '"]');
          if (targetCard) {
            targetCard.scrollIntoView({ behavior: 'smooth', block: 'center' });
            targetCard.click();
          }
        }
      })
      .catch(function() {
        resultEl.style.display = 'block';
        resultEl.className = 'test-result error';
        resultEl.textContent = 'Request failed';
      });
  });

  // ─── Init Rules Tab ───
  document.querySelector('[data-tab="rules"]').addEventListener('click', function() {
    if (!rulesInitialized) {
      rulesInitialized = true;
      loadFilesMeta();
    }
  });
})();
</script>
</body>
</html>`;
  if (basePath) {
    html = html.replaceAll("'/api/", `'${basePath}/api/`);
    html = html.replaceAll('"/api/', `"${basePath}/api/`);
  }
  return html;
}
