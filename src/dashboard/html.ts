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
<title>SecAgent Dashboard</title>
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

/* ─── Audit Log Tab ─── */
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
.log-entry {
  background: var(--bg-card); border-radius: 6px; padding: 10px 14px;
  border-left: 3px solid var(--border); font-size: 13px; cursor: pointer;
}
.log-entry.tier-GREEN { border-left-color: var(--green); }
.log-entry.tier-YELLOW { border-left-color: var(--yellow); }
.log-entry.tier-RED { border-left-color: var(--red); }
.log-entry.evt-tool_blocked { background: rgba(239,68,68,0.1); }
.log-entry.evt-danger_detected { background: rgba(239,68,68,0.15); }
.log-entry.evt-override_used { background: rgba(168,85,247,0.1); }
.log-entry-header { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.log-time { color: var(--text-dim); font-size: 11px; font-family: var(--font-mono); }
.badge {
  display: inline-block; padding: 1px 6px; border-radius: 3px; font-size: 10px;
  font-weight: 600; text-transform: uppercase; font-family: var(--font-mono);
}
.badge-green { background: rgba(34,197,94,0.15); color: var(--green); }
.badge-yellow { background: rgba(245,158,11,0.15); color: var(--yellow); }
.badge-red { background: rgba(239,68,68,0.15); color: var(--red); }
.badge-event { background: rgba(59,130,246,0.15); color: var(--blue); }
.log-tool { font-family: var(--font-mono); font-size: 12px; color: var(--text); }
.log-detail {
  display: none; margin-top: 8px; padding-top: 8px; border-top: 1px solid var(--border);
  font-family: var(--font-mono); font-size: 11px; color: var(--text-dim);
  white-space: pre-wrap; word-break: break-all;
}
.log-entry.expanded .log-detail { display: block; }

/* ─── Config Tab ─── */
.config-section { margin-bottom: 20px; }
.config-section h3 {
  font-size: 13px; color: var(--blue); margin-bottom: 10px;
  padding-bottom: 6px; border-bottom: 1px solid var(--border);
}
.config-field { display: flex; align-items: center; gap: 12px; margin-bottom: 8px; }
.config-field label { width: 180px; font-size: 12px; color: var(--text-dim); }
.config-field input, .config-field select {
  flex: 1; max-width: 300px; padding: 6px 10px; background: var(--bg-input);
  border: 1px solid var(--border); color: var(--text); border-radius: 4px;
  font-size: 12px; font-family: var(--font-mono);
}
.config-field input[type="checkbox"] { flex: none; width: 16px; height: 16px; }
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
  <h1><span class="status-dot"></span>Sec<span>Agent</span> Dashboard</h1>
  <span style="font-size:12px;color:var(--text-dim)">127.0.0.1</span>
</header>
<nav>
  <button class="active" data-tab="logs">Audit Log</button>
  <button data-tab="config">Config</button>
  <button data-tab="health">Health</button>
  <button data-tab="rules">Rules</button>
</nav>

<!-- Tab 1: Audit Log -->
<div id="tab-logs" class="tab-content active">
  <div class="log-toolbar">
    <select id="filter-tier"><option value="">All Tiers</option><option value="GREEN">GREEN</option><option value="YELLOW">YELLOW</option><option value="RED">RED</option></select>
    <select id="filter-event"><option value="">All Events</option><option value="tool_classified">tool_classified</option><option value="rule_matched">rule_matched</option><option value="llm_audit">llm_audit</option><option value="tool_blocked">tool_blocked</option><option value="tool_allowed">tool_allowed</option><option value="danger_detected">danger_detected</option><option value="danger_cleared">danger_cleared</option><option value="override_used">override_used</option></select>
    <input id="filter-tool" type="text" placeholder="Tool name..." style="width:120px">
    <button id="btn-pause">Pause</button>
    <button id="btn-clear">Clear</button>
    <span class="count" id="log-count">0 entries</span>
  </div>
  <div class="log-list" id="log-list"></div>
</div>

<!-- Tab 2: Config Editor -->
<div id="tab-config" class="tab-content">
  <div class="config-section">
    <h3>LLM</h3>
    <div class="config-field"><label>model</label><input id="cfg-llm-model" type="text"></div>
    <div class="config-field"><label>enabled</label><input id="cfg-llm-enabled" type="checkbox"></div>
    <div class="config-field"><label>maxConcurrent</label><input id="cfg-llm-maxConcurrent" type="number" min="1" max="10"></div>
    <div class="config-field"><label>trustedSenderLabels</label><input id="cfg-llm-trustedSenderLabels" type="text" placeholder="comma-separated"></div>
  </div>
  <div class="config-section">
    <h3>Timeouts</h3>
    <div class="config-field"><label>syncAuditMs</label><input id="cfg-timeouts-syncAuditMs" type="number" min="1000" max="120000"></div>
    <div class="config-field"><label>asyncAuditMs</label><input id="cfg-timeouts-asyncAuditMs" type="number" min="1000" max="120000"></div>
    <div class="config-field"><label>syncTimeoutPolicy</label><select id="cfg-timeouts-syncTimeoutPolicy"><option value="fail_closed">fail_closed</option><option value="fail_open">fail_open</option></select></div>
  </div>
  <div class="config-section">
    <h3>Logging</h3>
    <div class="config-field"><label>level</label><select id="cfg-logging-level"><option value="debug">debug</option><option value="info">info</option><option value="warn">warn</option><option value="error">error</option></select></div>
    <div class="config-field"><label>auditJsonl</label><input id="cfg-logging-auditJsonl" type="checkbox"></div>
  </div>
  <button class="btn-save" id="btn-save-config">Save Configuration</button>
</div>

<!-- Tab 3: Health -->
<div id="tab-health" class="tab-content">
  <div class="placeholder">
    <h2>Health Check</h2>
    <p>Coming Soon — LLM connectivity, rule integrity, recent statistics</p>
  </div>
</div>

<!-- Tab 4: Rules -->
<div id="tab-rules" class="tab-content">
  <div class="placeholder">
    <h2>Rule Editor</h2>
    <p>Coming Soon — Rule CRUD, YAML editor, rule testing</p>
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

  // ─── Audit Log ───
  const logList = document.getElementById('log-list');
  const logCount = document.getElementById('log-count');
  const filterTier = document.getElementById('filter-tier');
  const filterEvent = document.getElementById('filter-event');
  const filterTool = document.getElementById('filter-tool');
  const btnPause = document.getElementById('btn-pause');
  const btnClear = document.getElementById('btn-clear');

  let entries = [];
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

  function matchesFilter(entry) {
    if (filterTier.value && entry.tier !== filterTier.value) return false;
    if (filterEvent.value && entry.eventType !== filterEvent.value) return false;
    if (filterTool.value && entry.toolName && !entry.toolName.includes(filterTool.value)) return false;
    return true;
  }

  function renderEntry(entry) {
    const div = document.createElement('div');
    let cls = 'log-entry';
    if (entry.tier) cls += ' tier-' + entry.tier;
    if (entry.eventType) cls += ' evt-' + entry.eventType;
    div.className = cls;

    const details = {};
    if (entry.params) details.params = entry.params;
    if (entry.reason) details.reason = entry.reason;
    if (entry.ruleId) details.ruleId = entry.ruleId;
    if (entry.durationMs !== undefined) details.durationMs = entry.durationMs;
    if (entry.decision) details.decision = entry.decision;
    if (entry.source) details.source = entry.source;

    div.innerHTML =
      '<div class="log-entry-header">' +
        '<span class="log-time">' + relativeTime(entry.timestamp) + '</span>' +
        '<span class="badge badge-event">' + (entry.eventType || 'unknown') + '</span>' +
        (entry.toolName ? '<span class="log-tool">' + entry.toolName + '</span>' : '') +
        (entry.tier ? '<span class="badge ' + tierBadgeClass(entry.tier) + '">' + entry.tier + '</span>' : '') +
      '</div>' +
      '<div class="log-detail">' + JSON.stringify(details, null, 2) + '</div>';

    div.addEventListener('click', () => div.classList.toggle('expanded'));
    return div;
  }

  function renderAll() {
    logList.innerHTML = '';
    const filtered = entries.filter(matchesFilter);
    for (let i = filtered.length - 1; i >= 0; i--) {
      logList.appendChild(renderEntry(filtered[i]));
    }
    logCount.textContent = filtered.length + ' entries';
  }

  function addEntry(entry) {
    entries.push(entry);
    if (entries.length > 2000) entries = entries.slice(-1500);
    if (paused) return;
    if (!matchesFilter(entry)) {
      logCount.textContent = entries.filter(matchesFilter).length + ' entries';
      return;
    }
    const el = renderEntry(entry);
    logList.insertBefore(el, logList.firstChild);
    logCount.textContent = entries.filter(matchesFilter).length + ' entries';
  }

  filterTier.addEventListener('change', renderAll);
  filterEvent.addEventListener('change', renderAll);
  filterTool.addEventListener('input', renderAll);

  btnPause.addEventListener('click', () => {
    paused = !paused;
    btnPause.textContent = paused ? 'Resume' : 'Pause';
    if (!paused) renderAll();
  });

  btnClear.addEventListener('click', () => {
    entries = [];
    renderAll();
  });

  // Load initial logs
  fetch('/api/logs?limit=200')
    .then(r => r.json())
    .then(data => {
      entries = data;
      renderAll();
      connectSSE();
    })
    .catch(() => connectSSE());

  function connectSSE() {
    if (eventSource) eventSource.close();
    eventSource = new EventSource('/api/logs/stream');
    eventSource.addEventListener('message', (e) => {
      try { addEntry(JSON.parse(e.data)); } catch {}
    });
    eventSource.addEventListener('error', () => {
      setTimeout(connectSSE, 5000);
    });
  }

  // ─── Config Editor ───
  function loadConfig() {
    fetch('/api/config')
      .then(r => r.json())
      .then(cfg => {
        document.getElementById('cfg-llm-model').value = cfg.llm?.model || '';
        document.getElementById('cfg-llm-enabled').checked = cfg.llm?.enabled ?? true;
        document.getElementById('cfg-llm-maxConcurrent').value = cfg.llm?.maxConcurrent || 2;
        document.getElementById('cfg-llm-trustedSenderLabels').value = (cfg.llm?.trustedSenderLabels || []).join(', ');
        document.getElementById('cfg-timeouts-syncAuditMs').value = cfg.timeouts?.syncAuditMs || 30000;
        document.getElementById('cfg-timeouts-asyncAuditMs').value = cfg.timeouts?.asyncAuditMs || 30000;
        document.getElementById('cfg-timeouts-syncTimeoutPolicy').value = cfg.timeouts?.syncTimeoutPolicy || 'fail_closed';
        document.getElementById('cfg-logging-level').value = cfg.logging?.level || 'info';
        document.getElementById('cfg-logging-auditJsonl').checked = cfg.logging?.auditJsonl ?? true;
      })
      .catch(() => showToast('Failed to load config', 'error'));
  }

  document.getElementById('btn-save-config').addEventListener('click', () => {
    const labels = document.getElementById('cfg-llm-trustedSenderLabels').value
      .split(',').map(s => s.trim()).filter(Boolean);
    const body = {
      llm: {
        model: document.getElementById('cfg-llm-model').value,
        enabled: document.getElementById('cfg-llm-enabled').checked,
        maxConcurrent: parseInt(document.getElementById('cfg-llm-maxConcurrent').value, 10),
        trustedSenderLabels: labels,
      },
      timeouts: {
        syncAuditMs: parseInt(document.getElementById('cfg-timeouts-syncAuditMs').value, 10),
        asyncAuditMs: parseInt(document.getElementById('cfg-timeouts-asyncAuditMs').value, 10),
        syncTimeoutPolicy: document.getElementById('cfg-timeouts-syncTimeoutPolicy').value,
      },
      logging: {
        level: document.getElementById('cfg-logging-level').value,
        auditJsonl: document.getElementById('cfg-logging-auditJsonl').checked,
      },
    };
    fetch('/api/config', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      .then(r => r.json())
      .then(data => {
        if (data.ok) showToast('Configuration saved', 'success');
        else showToast('Failed: ' + (data.errors || []).join(', '), 'error');
      })
      .catch(() => showToast('Failed to save config', 'error'));
  });

  // Load config when switching to config tab
  document.querySelector('[data-tab="config"]').addEventListener('click', loadConfig);
  // Also load on initial page load in case someone navigates directly
  if (document.querySelector('[data-tab="config"]').classList.contains('active')) loadConfig();
})();
</script>
</body>
</html>`;
}
