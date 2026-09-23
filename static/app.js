document.addEventListener('DOMContentLoaded', () => {
  refreshDashboard();
  setInterval(refreshDashboard, 5000);
});

function fillCreds(username, password) {
  document.getElementById('username').value = username;
  document.getElementById('password').value = password;
}

async function refreshDashboard() {
  try {
    const [statsRes, logsRes] = await Promise.all([
      fetch('/api/stats'),
      fetch('/api/logs')
    ]);

    if (statsRes.ok) {
      const stats = await statsRes.json();
      updateStatsUI(stats);
    }

    if (logsRes.ok) {
      const logs = await logsRes.json();
      updateLogsUI(logs);
    }
  } catch (err) {
    console.error('Error refreshing dashboard:', err);
  }
}

function updateStatsUI(stats) {
  document.getElementById('stat-total').textContent = stats.total_attempts || 0;
  document.getElementById('stat-suspicious').textContent = stats.suspicious_count || 0;
  document.getElementById('stat-critical').textContent = stats.critical_count || 0;
  document.getElementById('stat-safe').textContent = stats.safe_count || 0;

  const rules = stats.rule_counts || {};
  document.getElementById('count-unusual-hours').textContent = rules.UNUSUAL_HOURS || 0;
  document.getElementById('count-brute-force').textContent = (rules.BRUTE_FORCE || 0) + (rules.SUSPICIOUS_RECOVERY || 0);
  document.getElementById('count-burst').textContent = rules.BURST_VELOCITY || 0;
}

function updateLogsUI(logs) {
  const tbody = document.getElementById('logs-tbody');
  const counterTag = document.getElementById('log-counter-tag');
  counterTag.textContent = `${logs.length} events`;

  if (!logs || logs.length === 0) {
    tbody.innerHTML = `
      <tr class="empty-row">
        <td colspan="7">No authentication events recorded yet. Attempt a login on the right or run a simulation.</td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = logs.map(entry => {
    const authBadge = entry.auth_success
      ? `<span class="badge badge-auth-success">SUCCESS</span>`
      : `<span class="badge badge-auth-failed">FAILED</span>`;

    const threatClass = (entry.classification || 'SAFE').toLowerCase();
    const threatBadge = `<span class="badge badge-threat-${threatClass}">${entry.classification}</span>`;

    const ruleChips = (entry.triggered_rules || []).map(r => {
      let icon = '⚡';
      if (r.code === 'UNUSUAL_HOURS') icon = '🌙';
      if (r.code === 'BRUTE_FORCE' || r.code === 'SUSPICIOUS_RECOVERY') icon = '⚔️';
      return `<span class="rule-flag-chip" title="${escapeHtml(r.description)}">${icon} ${escapeHtml(r.code)}</span>`;
    }).join(' ');

    return `
      <tr>
        <td class="time-cell">${escapeHtml(entry.time_display || entry.timestamp)}</td>
        <td class="user-cell">${escapeHtml(entry.username)}</td>
        <td class="ip-cell">${escapeHtml(entry.ip)}</td>
        <td>${authBadge}</td>
        <td>${threatBadge}</td>
        <td style="font-family: var(--font-mono); font-weight:600;">${entry.risk_score}/100</td>
        <td>${ruleChips || '<span style="color:var(--text-dim);font-size:0.7rem;">None (Clean)</span>'}</td>
      </tr>
    `;
  }).join('');
}

async function handleLogin(e) {
  e.preventDefault();
  const submitBtn = document.getElementById('submit-btn');
  const originalText = submitBtn.innerHTML;
  submitBtn.disabled = true;
  submitBtn.innerHTML = '<span class="btn-text">ANALYZING AUTH...</span>';

  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;
  const ip = document.getElementById('sim-ip').value.trim();
  const timeSelect = document.getElementById('sim-time-select').value;
  const simulatedHour = timeSelect === 'real' ? null : parseInt(timeSelect, 10);

  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        password,
        ip,
        simulated_hour: simulatedHour
      })
    });

    const data = await res.json();
    renderAssessment(data, res.status);
    await refreshDashboard();
  } catch (err) {
    console.error('Login error:', err);
  } finally {
    submitBtn.disabled = false;
    submitBtn.innerHTML = originalText;
  }
}

function renderAssessment(data, httpStatus) {
  const container = document.getElementById('assessment-container');
  const verdictTag = document.getElementById('verdict-tag');
  const verdictScore = document.getElementById('verdict-score');
  const msgEl = document.getElementById('assessment-msg');
  const listEl = document.getElementById('triggered-list');

  const evalData = data.evaluation || {};
  const classification = evalData.classification || (httpStatus === 200 ? 'SAFE' : 'SUSPICIOUS');
  const score = evalData.risk_score || 0;
  const rules = evalData.triggered_rules || [];

  verdictTag.textContent = classification;
  verdictTag.className = `verdict-tag badge-threat-${classification.toLowerCase()}`;
  verdictScore.textContent = `Risk Score: ${score}/100`;
  msgEl.textContent = data.message || (httpStatus === 200 ? 'Authenticated successfully' : 'Login failed');

  if (rules.length > 0) {
    listEl.innerHTML = rules.map(r => `
      <div class="rule-alert-item severity-${r.severity || 'MEDIUM'}">
        <strong>${escapeHtml(r.name)} (${r.severity})</strong>
        <span>${escapeHtml(r.description)}</span>
      </div>
    `).join('');
  } else {
    listEl.innerHTML = `
      <div style="font-size:0.75rem; color:var(--safe-green); margin-top:2px;">
        ✓ No behavioral anomalies detected. Standard baseline login.
      </div>
    `;
  }

  container.className = 'assessment-container visible';
}

async function simulateScenario(scenario) {
  try {
    const res = await fetch('/api/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario })
    });

    if (res.ok) {
      const data = await res.json();
      if (data.last_result) {
        renderAssessment({
          status: data.last_result.auth_success ? 'success' : 'failed',
          message: data.last_result.details,
          evaluation: {
            risk_score: data.last_result.risk_score,
            classification: data.last_result.classification,
            triggered_rules: data.last_result.triggered_rules
          }
        }, data.last_result.auth_success ? 200 : 401);
      }
      await refreshDashboard();
    }
  } catch (err) {
    console.error('Simulation error:', err);
  }
}

async function clearLogs() {
  try {
    await fetch('/api/clear', { method: 'POST' });
    document.getElementById('assessment-container').className = 'assessment-container';
    await refreshDashboard();
  } catch (err) {
    console.error('Error clearing logs:', err);
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}