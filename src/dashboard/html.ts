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
    <div class="config-field"><label>model</label><input id="cfg-llm-model" type="text"></div>
    <div class="config-field"><label>enabled</label><input id="cfg-llm-enabled" type="checkbox"></div>
    <div class="config-field"><label>maxConcurrent</label><input id="cfg-llm-maxConcurrent" type="number" min="1" max="10"></div>
    <div class="config-field"><label>endpoint</label><input id="cfg-llm-endpoint" type="text" ></div>
    <div class="config-field"><label>apiKey</label><input id="cfg-llm-apiKey" type="text"></div>
    <div class="config-field"><label>promptRecentCalls</label><input id="cfg-llm-promptRecentCalls" type="number" min="0" max="20"></div>
    <div class="config-field"><label>trustedSenderLabels</label><input id="cfg-llm-trustedSenderLabels" type="text" placeholder="comma-separated"></div>
  </div>
  <div class="config-section">
    <h3>LLM Retry</h3>
    <div class="config-field"><label>maxRetries</label><input id="cfg-llm-retry-maxRetries" type="number" min="0" max="10"></div>
    <div class="config-field"><label>initialBackoffMs</label><input id="cfg-llm-retry-initialBackoffMs" type="number" min="100" max="30000"></div>
    <div class="config-field"><label>cooldownMs</label><input id="cfg-llm-retry-cooldownMs" type="number" min="1000" max="300000"></div>
    <div class="config-field"><label>cooldownThreshold</label><input id="cfg-llm-retry-cooldownThreshold" type="number" min="1" max="20"></div>
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
  <div class="config-section">
    <h3>Dashboard</h3>
    <div class="config-field"><label>enabled</label><input id="cfg-dashboard-enabled" type="checkbox" disabled title="Requires restart"></div>
    <div class="config-field"><label>port</label><input id="cfg-dashboard-port" type="number" disabled title="Requires restart"></div>
    <div class="config-field"><label>host</label><input id="cfg-dashboard-host" type="text" disabled title="Requires restart"></div>
  </div>
  <div class="config-section">
    <h3>Rules</h3>
    <div class="config-field" style="align-items:flex-start"><label>extra</label><textarea id="cfg-rules-extra" rows="6" style="flex:1;max-width:500px;padding:6px 10px;background:var(--bg-input);border:1px solid var(--border);color:var(--text);border-radius:4px;font-size:12px;font-family:var(--font-mono);resize:vertical" placeholder="[]"></textarea></div>
  </div>
  <div class="config-section">
    <h3>Agent Profiles</h3>
    <div class="config-field" style="align-items:flex-start"><label>agentProfiles</label><textarea id="cfg-agentProfiles" rows="6" style="flex:1;max-width:500px;padding:6px 10px;background:var(--bg-input);border:1px solid var(--border);color:var(--text);border-radius:4px;font-size:12px;font-family:var(--font-mono);resize:vertical" placeholder="{}"></textarea></div>
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

    // Sync LLM Audit
    if (rec.syncAudit) {
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

    // Override
    if (rec.overridePin && rec.overrideUsed) {
      parts.push(phaseHtml('Override', 'PIN: <span class="tc-pin">' + escapeHtml(rec.overridePin) + '</span> <span class="tc-status overridden">APPROVED</span>'));
    } else if (rec.finalStatus === 'blocked' && rec.overridePin) {
      parts.push(phaseHtml('Override', 'PIN: <span class="tc-pin">' + escapeHtml(rec.overridePin) + '</span> <span class="blink" style="color:var(--yellow)">awaiting approval</span>'));
    } else if (rec.overrideUsed) {
      parts.push(phaseHtml('Override', '<span class="tc-status overridden">APPROVED</span>'));
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

  // ─── Config Editor ───
  function loadConfig() {
    fetch('/api/config')
      .then(function(r) { return r.json(); })
      .then(function(cfg) {
        // LLM
        document.getElementById('cfg-llm-model').value = cfg.llm?.model || '';
        document.getElementById('cfg-llm-enabled').checked = cfg.llm?.enabled ?? true;
        document.getElementById('cfg-llm-maxConcurrent').value = cfg.llm?.maxConcurrent || 2;
        document.getElementById('cfg-llm-endpoint').value = cfg.llm?.endpoint || '';
        document.getElementById('cfg-llm-apiKey').value = cfg.llm?.apiKey || '';
        document.getElementById('cfg-llm-promptRecentCalls').value = cfg.llm?.promptRecentCalls ?? 3;
        document.getElementById('cfg-llm-trustedSenderLabels').value = (cfg.llm?.trustedSenderLabels || []).join(', ');
        // LLM Retry
        var retry = cfg.llm?.retry || {};
        document.getElementById('cfg-llm-retry-maxRetries').value = retry.maxRetries ?? 2;
        document.getElementById('cfg-llm-retry-initialBackoffMs').value = retry.initialBackoffMs ?? 1000;
        document.getElementById('cfg-llm-retry-cooldownMs').value = retry.cooldownMs ?? 30000;
        document.getElementById('cfg-llm-retry-cooldownThreshold').value = retry.cooldownThreshold ?? 3;
        // Timeouts
        document.getElementById('cfg-timeouts-syncAuditMs').value = cfg.timeouts?.syncAuditMs || 30000;
        document.getElementById('cfg-timeouts-asyncAuditMs').value = cfg.timeouts?.asyncAuditMs || 30000;
        document.getElementById('cfg-timeouts-syncTimeoutPolicy').value = cfg.timeouts?.syncTimeoutPolicy || 'fail_closed';
        // Logging
        document.getElementById('cfg-logging-level').value = cfg.logging?.level || 'info';
        document.getElementById('cfg-logging-auditJsonl').checked = cfg.logging?.auditJsonl ?? true;
        // Dashboard (read-only)
        document.getElementById('cfg-dashboard-enabled').checked = cfg.dashboard?.enabled ?? true;
        document.getElementById('cfg-dashboard-port').value = cfg.dashboard?.port ?? 19198;
        document.getElementById('cfg-dashboard-host').value = cfg.dashboard?.host || '127.0.0.1';
        // Rules extra
        document.getElementById('cfg-rules-extra').value = cfg.rules?.extra ? JSON.stringify(cfg.rules.extra, null, 2) : '[]';
        // Agent Profiles
        document.getElementById('cfg-agentProfiles').value = cfg.agentProfiles ? JSON.stringify(cfg.agentProfiles, null, 2) : '{}';
      })
      .catch(function() { showToast('Failed to load config', 'error'); });
  }

  document.getElementById('btn-save-config').addEventListener('click', function() {
    var labels = document.getElementById('cfg-llm-trustedSenderLabels').value
      .split(',').map(function(s) { return s.trim(); }).filter(Boolean);

    // Parse JSON textareas
    var rulesExtra, agentProfiles;
    try {
      rulesExtra = JSON.parse(document.getElementById('cfg-rules-extra').value || '[]');
    } catch(e) {
      showToast('Invalid JSON in rules.extra', 'error');
      return;
    }
    try {
      agentProfiles = JSON.parse(document.getElementById('cfg-agentProfiles').value || '{}');
    } catch(e) {
      showToast('Invalid JSON in agentProfiles', 'error');
      return;
    }

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
        syncAuditMs: parseInt(document.getElementById('cfg-timeouts-syncAuditMs').value, 10),
        asyncAuditMs: parseInt(document.getElementById('cfg-timeouts-asyncAuditMs').value, 10),
        syncTimeoutPolicy: document.getElementById('cfg-timeouts-syncTimeoutPolicy').value,
      },
      logging: {
        level: document.getElementById('cfg-logging-level').value,
        auditJsonl: document.getElementById('cfg-logging-auditJsonl').checked,
      },
      rules: { extra: rulesExtra },
      agentProfiles: agentProfiles,
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
})();
</script>
</body>
</html>`;
}
