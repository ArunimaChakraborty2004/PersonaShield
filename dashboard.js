/* ============================================================
   PersonaShield — Dashboard Logic (dashboard.js)
   ============================================================ */

let allLogs = [];
let filteredLogs = [];
let currentPage = 1;
const PAGE_SIZE = 12;
let sortKey = 'timestamp';
let sortAsc = false;
let donutChart, lineChart;

// ─── Init ────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', loadAll);

async function loadAll() {
  await Promise.all([
    loadSummary(),
    loadLogs(),
    loadTimeline(),
    loadAvgScoreChart(),
    loadUrlSummary(),
    loadUrlLogs(),
    loadUrlStats()
  ]);
}

// ─── Summary Cards ───────────────────────────────────────────────
async function loadSummary() {
  try {
    const res  = await fetch('/api/summary');
    const data = await res.json();
    animateCount('ds-total',   data.total);
    animateCount('ds-threats', data.threats);
    animateCount('ds-safe',    data.safe);
    document.getElementById('ds-avg').textContent = data.avg_score ?? '0';
    loadStats(); // load donut after summary
  } catch (e) {
    console.error('Summary error', e);
  }
}

function animateCount(id, target) {
  const el = document.getElementById(id);
  if (!el) return;
  let current = 0;
  const step = Math.ceil(target / 40);
  const timer = setInterval(() => {
    current += step;
    if (current >= target) { current = target; clearInterval(timer); }
    el.textContent = current;
  }, 30);
}

// ─── Donut Chart ─────────────────────────────────────────────────
async function loadStats() {
  try {
    const res  = await fetch('/api/stats');
    const data = await res.json();

    const labels = data.map(d => d._id || 'Unknown');
    const counts = data.map(d => d.count);
    const colors = [
      '#3b82f6','#ef4444','#f59e0b','#10b981',
      '#8b5cf6','#06b6d4','#ec4899','#84cc16'
    ];

    const ctx = document.getElementById('donutChart').getContext('2d');
    if (donutChart) donutChart.destroy();

    donutChart = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{
          data: counts,
          backgroundColor: colors.slice(0, labels.length),
          borderColor: 'rgba(5,13,26,0.8)',
          borderWidth: 3,
          hoverOffset: 8
        }]
      },
      options: {
        responsive: true,
        cutout: '68%',
        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: '#94a3b8',
              font: { size: 11, family: 'Inter' },
              padding: 14,
              boxWidth: 12,
              boxHeight: 12
            }
          },
          tooltip: {
            backgroundColor: 'rgba(10,22,44,0.95)',
            titleColor: '#f0f6ff',
            bodyColor: '#94a3b8',
            borderColor: 'rgba(59,130,246,0.3)',
            borderWidth: 1
          }
        },
        animation: { animateScale: true, duration: 900 }
      }
    });
  } catch(e) { console.error('Stats error', e); }
}

// ─── Timeline Line Chart (Total Scans + Threats) ─────────────────
async function loadTimeline() {
  try {
    const res  = await fetch('/api/timeline?days=7');
    const data = await res.json();

    const labels  = data.map(d => {
      const date = new Date(d._id);
      return date.toLocaleDateString('en', { month: 'short', day: 'numeric' });
    });
    const total   = data.map(d => d.count);
    const threats = data.map(d => d.threats);

    const ctx = document.getElementById('lineChart').getContext('2d');
    if (lineChart) lineChart.destroy();

    lineChart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels.length ? labels : ['No data'],
        datasets: [
          {
            label: 'Total Scans',
            data: total.length ? total : [0],
            borderColor: '#3b82f6',
            backgroundColor: 'rgba(59,130,246,0.08)',
            pointBackgroundColor: '#3b82f6',
            pointRadius: 5,
            pointHoverRadius: 7,
            fill: true,
            tension: 0.4
          },
          {
            label: 'Threats',
            data: threats.length ? threats : [0],
            borderColor: '#ef4444',
            backgroundColor: 'rgba(239,68,68,0.07)',
            pointBackgroundColor: '#ef4444',
            pointRadius: 5,
            pointHoverRadius: 7,
            fill: true,
            tension: 0.4
          }
        ]
      },
      options: {
        responsive: true,
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: {
            labels: {
              color: '#94a3b8',
              font: { size: 11, family: 'Inter' },
              boxWidth: 12, boxHeight: 12
            }
          },
          tooltip: {
            backgroundColor: 'rgba(10,22,44,0.95)',
            titleColor: '#f0f6ff',
            bodyColor: '#94a3b8',
            borderColor: 'rgba(59,130,246,0.3)',
            borderWidth: 1
          }
        },
        scales: {
          x: {
            grid: { color: 'rgba(255,255,255,0.04)' },
            ticks: { color: '#64748b', font: { size: 11 } }
          },
          y: {
            grid: { color: 'rgba(255,255,255,0.04)' },
            ticks: { color: '#64748b', font: { size: 11 }, stepSize: 1 },
            beginAtZero: true
          }
        }
      }
    });
  } catch(e) {
    console.error('Timeline error', e);
    const ctx = document.getElementById('lineChart').getContext('2d');
    if (lineChart) lineChart.destroy();
    lineChart = new Chart(ctx, {
      type: 'line',
      data: { labels: ['No data'], datasets: [{ label: 'Scans', data: [0], borderColor: '#3b82f6' }] },
      options: { responsive: true }
    });
  }
}

// ─── Avg Risk Score Evolution Chart (separate fetch) ──────────────
async function loadAvgScoreChart() {
  const ctx = document.getElementById('avgScoreChart');
  if (!ctx) return;

  try {
    const res  = await fetch('/api/timeline?days=7');
    const data = await res.json();

    const labels = data.map(d => {
      const date = new Date(d._id);
      return date.toLocaleDateString('en', { month: 'short', day: 'numeric' });
    });
    const avgScores = data.map(d => parseFloat((d.avg_score || 0).toFixed(2)));

    if (window.avgScoreChart && typeof window.avgScoreChart.destroy === 'function') {
      window.avgScoreChart.destroy();
    }

    window.avgScoreChart = new Chart(ctx.getContext('2d'), {
      type: 'line',
      data: {
        labels: labels.length ? labels : ['No data'],
        datasets: [{
          label: 'Avg Risk Score',
          data: avgScores.length ? avgScores : [0],
          borderColor: '#8b5cf6',
          backgroundColor: 'rgba(139,92,246,0.12)',
          pointBackgroundColor: '#8b5cf6',
          pointBorderColor: '#fff',
          pointBorderWidth: 2,
          pointRadius: 6,
          pointHoverRadius: 8,
          fill: true,
          tension: 0.4
        }]
      },
      options: {
        responsive: true,
        interaction: { mode: 'index', intersect: false },
        plugins: {
          legend: { labels: { color: '#94a3b8', font: { size: 11, family: 'Inter' }, boxWidth: 12, boxHeight: 12 } },
          tooltip: {
            backgroundColor: 'rgba(10,22,44,0.95)',
            titleColor: '#f0f6ff',
            bodyColor: '#94a3b8',
            borderColor: 'rgba(139,92,246,0.4)',
            borderWidth: 1,
            callbacks: {
              label: ctx => ` Avg Score: ${ctx.parsed.y.toFixed(2)} / 10`
            }
          }
        },
        scales: {
          x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#64748b', font: { size: 11 } } },
          y: {
            grid: { color: 'rgba(255,255,255,0.04)' },
            ticks: { color: '#64748b', font: { size: 11 } },
            min: 0,
            max: 10,
            beginAtZero: true
          }
        }
      }
    });
  } catch(e) {
    console.error('Avg Score chart error', e);
    const fallbackCtx = document.getElementById('avgScoreChart').getContext('2d');
    if (window.avgScoreChart && typeof window.avgScoreChart.destroy === 'function') {
      window.avgScoreChart.destroy();
    }
    window.avgScoreChart = new Chart(fallbackCtx, {
      type: 'line',
      data: { labels: ['No data'], datasets: [{ label: 'Avg Risk Score', data: [0], borderColor: '#8b5cf6' }] },
      options: { responsive: true }
    });
  }
}

// ─── Logs Table ───────────────────────────────────────────────────
async function loadLogs() {
  try {
    const res = await fetch('/api/logs?limit=200');
    allLogs   = await res.json();
    filteredLogs = [...allLogs];
    currentPage  = 1;
    renderTable();
  } catch(e) {
    console.error('Logs error', e);
    document.getElementById('log-entries').innerHTML =
      '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:2rem;">Failed to load logs.</td></tr>';
  }
}

function renderTable() {
  const tbody  = document.getElementById('log-entries');
  const start  = (currentPage - 1) * PAGE_SIZE;
  const page   = filteredLogs.slice(start, start + PAGE_SIZE);

  if (page.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-muted);padding:2rem;">No logs found.</td></tr>';
    updatePagination();
    return;
  }

  tbody.innerHTML = page.map(entry => {
    const score    = entry.score ?? 0;
    const color    = scoreColor(score);
    const barPct   = (score / 10) * 100;
    const severity = entry.severity || scoreToSeverity(score);
    const badgeCls = severityBadge(severity);
    const typeLabel = entry.threat_type || 'Safe';
    const aiTag    = entry.ai_powered
      ? '<span style="font-size:0.7rem;color:var(--accent-purple);font-weight:600;">🤖 AI</span>'
      : '<span style="font-size:0.7rem;color:var(--text-muted);">Rule</span>';
    const ts       = entry.timestamp
      ? new Date(entry.timestamp).toLocaleString('en', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
      : '—';
    const msg = escHtml((entry.text || '').substring(0, 80)) + (entry.text?.length > 80 ? '…' : '');
    const confidence = entry.confidence ? `${entry.confidence}%` : '—';

    // Expandable explanation
    const expl = entry.explanation
      ? `<div style="margin-top:0.5rem;font-size:0.76rem;color:var(--text-muted);font-style:italic;border-top:1px solid var(--border);padding-top:0.4rem;">${escHtml(entry.explanation.substring(0, 120))}…</div>`
      : '';

    return `
      <tr>
        <td class="msg-cell" title="${escHtml(entry.text || '')}">
          ${msg}${expl}
        </td>
        <td>
          <div class="score-bar-wrap">
            <div class="score-bar">
              <div class="score-bar-fill" style="width:${barPct}%;background:${color};"></div>
            </div>
            <span class="score-text" style="color:${color};">${score}/10</span>
          </div>
        </td>
        <td style="font-weight:600;">${confidence}</td>
        <td><span class="threat-badge ${badgeCls}" style="font-size:0.73rem;">${escHtml(typeLabel)}</span></td>
        <td>${aiTag}</td>
        <td style="color:var(--text-muted);font-size:0.8rem;">${ts}</td>
        <td>
          <select class="feedback-select" onchange="submitFeedback('${entry._id}', this.value)">
            <option value="">Rate...</option>
            <option value="correct"   ${entry.feedback === 'correct'   ? 'selected' : ''}>✓ Correct</option>
            <option value="incorrect" ${entry.feedback === 'incorrect' ? 'selected' : ''}>✗ Wrong</option>
            <option value="unsure"    ${entry.feedback === 'unsure'    ? 'selected' : ''}>? Unsure</option>
          </select>
        </td>
        <td>
          <div style="display:flex;flex-direction:column;gap:4px;">
            <button class="toolbar-btn btn-secondary" style="padding:0.3rem 0.5rem;font-size:0.75rem;" onclick="downloadReport('${entry._id}', 'message')">
              <i class="fas fa-file-pdf"></i> Report
            </button>
            <button class="toolbar-btn btn-primary" style="padding:0.3rem 0.5rem;font-size:0.75rem;background:linear-gradient(135deg, var(--accent-purple), var(--accent-blue));border:none;" onclick="explainWithAI('${entry._id}')">
              <i class="fas fa-brain"></i> Explain
            </button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  updatePagination();
}

function updatePagination() {
  const total   = filteredLogs.length;
  const pages   = Math.ceil(total / PAGE_SIZE);
  const label   = document.getElementById('log-count-label');
  const buttons = document.getElementById('pagination-btns');

  label.textContent = `${total} log${total !== 1 ? 's' : ''}`;

  if (pages <= 1) { buttons.innerHTML = ''; return; }

  let html = `
    <button class="page-btn" onclick="goPage(${currentPage - 1})" ${currentPage === 1 ? 'disabled style="opacity:0.4;"' : ''}>
      <i class="fas fa-chevron-left"></i>
    </button>
  `;
  for (let p = 1; p <= Math.min(pages, 7); p++) {
    html += `<button class="page-btn ${p === currentPage ? 'active' : ''}" onclick="goPage(${p})">${p}</button>`;
  }
  if (pages > 7) html += `<span style="color:var(--text-muted);padding:0 0.25rem;">…${pages}</span>`;
  html += `
    <button class="page-btn" onclick="goPage(${currentPage + 1})" ${currentPage === pages ? 'disabled style="opacity:0.4;"' : ''}>
      <i class="fas fa-chevron-right"></i>
    </button>
  `;
  buttons.innerHTML = html;
}

function goPage(p) {
  const pages = Math.ceil(filteredLogs.length / PAGE_SIZE);
  if (p < 1 || p > pages) return;
  currentPage = p;
  renderTable();
}

// ─── Filter & Sort ───────────────────────────────────────────────
function filterTable() {
  const q    = (document.getElementById('log-search').value || '').toLowerCase();
  const type = document.getElementById('filter-type').value;

  filteredLogs = allLogs.filter(entry => {
    const matchText = !q || (entry.text || '').toLowerCase().includes(q);
    const matchType = !type || entry.threat_type === type;
    return matchText && matchType;
  });

  currentPage = 1;
  renderTable();
}

function sortTable(key) {
  if (sortKey === key) sortAsc = !sortAsc;
  else { sortKey = key; sortAsc = false; }

  filteredLogs.sort((a, b) => {
    const va = a[key] ?? '';
    const vb = b[key] ?? '';
    if (va < vb) return sortAsc ? -1 : 1;
    if (va > vb) return sortAsc ?  1 : -1;
    return 0;
  });

  currentPage = 1;
  renderTable();
}

// ─── Search ──────────────────────────────────────────────────────
function searchLogs() {
  filterTable();
}

// ─── Feedback ────────────────────────────────────────────────────
async function submitFeedback(id, value) {
  if (!value) return;
  try {
    await fetch(`/api/feedback/${id}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ feedback: value })
    });
  } catch(e) { console.error('Feedback error', e); }
}

// ─── CSV Export ──────────────────────────────────────────────────
function exportCSV() {
  const header = ['Message', 'Score', 'Threat Type', 'Severity', 'AI Powered', 'Timestamp', 'Feedback'];
  const rows   = allLogs.map(e => [
    `"${(e.text || '').replace(/"/g, '""')}"`,
    e.score ?? 0,
    e.threat_type || '',
    e.severity || '',
    e.ai_powered ? 'Yes' : 'No',
    e.timestamp || '',
    e.feedback || ''
  ]);

  const csv  = [header, ...rows].map(r => r.join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `personashield_logs_${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ─── Helpers ────────────────────────────────────────────────────
function scoreColor(score) {
  if (score === 0) return '#10b981';
  if (score <= 3)  return '#10b981';
  if (score <= 5)  return '#f59e0b';
  if (score <= 7)  return '#ef4444';
  return '#dc2626';
}

function scoreToSeverity(score) {
  if (score === 0) return 'safe';
  if (score <= 3)  return 'safe';
  if (score <= 5)  return 'medium';
  if (score <= 7)  return 'high';
  return 'critical';
}

function severityBadge(severity) {
  const map = { safe: 'badge-safe', low: 'badge-safe', medium: 'badge-medium', high: 'badge-high', critical: 'badge-critical' };
  return map[severity] || 'badge-safe';
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

window.loadAll       = loadAll;
window.filterTable   = filterTable;
window.sortTable     = sortTable;
window.searchLogs    = searchLogs;
window.submitFeedback = submitFeedback;
window.exportCSV     = exportCSV;
window.goPage        = goPage;
window.loadAvgScoreChart = loadAvgScoreChart;

// ─── URL Scanner Dashboard Logic ─────────────────────────────────
async function loadUrlSummary() {
  try {
    const res = await fetch('/api/url_summary');
    const data = await res.json();
    animateCount('url-total', data.total || 0);
    animateCount('url-threats', data.malicious || 0);
    animateCount('url-suspicious', data.suspicious || 0);
    animateCount('url-safe', data.safe || 0);
  } catch(e) { console.error('URL Summary error', e); }
}

async function loadUrlLogs() {
  try {
    const res = await fetch('/api/url_logs?limit=5');
    const data = await res.json();
    const tbody = document.getElementById('url-log-entries');
    if (!data || data.length === 0) {
      tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-muted);padding:2rem;">No URL scans found.</td></tr>';
      return;
    }
    
    tbody.innerHTML = data.map(entry => {
      const ts = entry.timestamp ? new Date(entry.timestamp).toLocaleString() : '—';
      let statusColor = 'var(--safe-color)';
      if (entry.status === 'Malicious') statusColor = 'var(--high-color)';
      else if (entry.status === 'Suspicious') statusColor = '#f59e0b';
      
      const conf = entry.confidence ? `${entry.confidence}%` : '—';
      
      return `
        <tr>
          <td style="word-break:break-all;" title="${escHtml(entry.url)}">${escHtml(entry.url)}</td>
          <td style="color:${statusColor};font-weight:bold;">${entry.risk_score}/10</td>
          <td style="font-weight:bold;">${conf}</td>
          <td><span style="color:${statusColor};">${escHtml(entry.status)}</span></td>
          <td style="color:var(--text-muted);font-size:0.8rem;">${ts}</td>
          <td>
            <div style="display:flex;flex-direction:column;gap:4px;">
              <button class="toolbar-btn btn-secondary" style="padding:0.3rem 0.5rem;font-size:0.75rem;" onclick="downloadReport('${entry._id}', 'url')">
                <i class="fas fa-file-pdf"></i> Report
              </button>
              <button class="toolbar-btn btn-primary" style="padding:0.3rem 0.5rem;font-size:0.75rem;background:linear-gradient(135deg, var(--accent-purple), var(--accent-blue));border:none;" onclick="explainWithAI('${entry._id}')">
                <i class="fas fa-brain"></i> Explain
              </button>
            </div>
          </td>
        </tr>
      `;
    }).join('');
  } catch(e) {
    console.error('URL Logs error', e);
  }
}

let urlDonutChart, urlLineChart;

async function loadUrlStats() {
  try {
    const res = await fetch('/api/url_stats');
    const data = await res.json();
    
    // URL Donut Chart
    const distLabels = data.threat_distribution.map(d => d._id || 'Unknown');
    const distCounts = data.threat_distribution.map(d => d.count);
    const colors = ['#3b82f6','#ef4444','#f59e0b','#10b981','#8b5cf6','#06b6d4'];
    
    const ctxD = document.getElementById('urlDonutChart').getContext('2d');
    if (urlDonutChart) urlDonutChart.destroy();
    urlDonutChart = new Chart(ctxD, {
      type: 'doughnut',
      data: {
        labels: distLabels,
        datasets: [{
          data: distCounts,
          backgroundColor: colors.slice(0, distLabels.length),
          borderColor: 'rgba(5,13,26,0.8)',
          borderWidth: 3
        }]
      },
      options: {
        responsive: true,
        cutout: '68%',
        plugins: {
          legend: { position: 'bottom', labels: { color: '#94a3b8', font: { family: 'Inter' } } }
        }
      }
    });

    // URL Line Chart
    const trendLabels = data.risk_trends.map(d => {
      const date = new Date(d._id);
      return date.toLocaleDateString('en', { month: 'short', day: 'numeric' });
    });
    const avgRisks = data.risk_trends.map(d => d.avg_risk);

    const ctxL = document.getElementById('urlLineChart').getContext('2d');
    if (urlLineChart) urlLineChart.destroy();
    urlLineChart = new Chart(ctxL, {
      type: 'line',
      data: {
        labels: trendLabels,
        datasets: [{
          label: 'Avg Risk Score',
          data: avgRisks,
          borderColor: '#ef4444',
          backgroundColor: 'rgba(239,68,68,0.1)',
          fill: true,
          tension: 0.4
        }]
      },
      options: {
        responsive: true,
        scales: {
          y: { min: 0, max: 10, grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#64748b' } },
          x: { grid: { color: 'rgba(255,255,255,0.04)' }, ticks: { color: '#64748b' } }
        },
        plugins: { legend: { labels: { color: '#94a3b8' } } }
      }
    });

  } catch(e) { console.error('URL Stats error', e); }
}

function downloadReport(id, type) {
  window.open(`/api/report/${id}?type=${type}`, '_blank');
}

function explainWithAI(id) {
  window.location.href = `/security_assistant?scan_id=${id}`;
}

window.downloadReport = downloadReport;
window.explainWithAI = explainWithAI;
