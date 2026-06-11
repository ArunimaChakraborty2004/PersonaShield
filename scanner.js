/* ============================================================
   PersonaShield — Bulk Scanner (scanner.js)
   ============================================================ */

const SAMPLE_TEXT = `Dear valued customer,

Your account has been suspended due to suspicious activity detected on your account. This is an urgent security notice from our Security Team.

Please click here immediately to verify your identity and update your credentials. Failure to respond within 24 hours will result in permanent account closure and loss of your data.

Your OTP is required to proceed. Do not share this with anyone. Keep this confidential.

Reset via this link: http://secure-verify.account-reset.xyz/login

If you did not authorize this activity, call us immediately at our support line.`;

// ─── Init ────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // hide results on load
  document.getElementById('scan-results').classList.remove('visible');
});

// ─── Sample ──────────────────────────────────────────────────────
function loadSample() {
  document.getElementById('scan-input').value = SAMPLE_TEXT;
}

function clearScan() {
  document.getElementById('scan-input').value = '';
  document.getElementById('scan-results').classList.remove('visible');
}

// ─── Run Scan ────────────────────────────────────────────────────
async function runScan() {
  const text = document.getElementById('scan-input').value.trim();
  if (!text) {
    alert('Please paste some text to scan.');
    return;
  }

  const btn = document.getElementById('scan-btn');
  btn.innerHTML = '<span class="loading-spinner"></span> Scanning...';
  btn.disabled = true;

  try {
    const res  = await fetch('/api/bulk_scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text })
    });
    const data = await res.json();
    renderResults(data, text);
  } catch(e) {
    alert('Error connecting to server. Make sure Flask is running.');
    console.error(e);
  } finally {
    btn.innerHTML = '<i class="fas fa-magnifying-glass"></i> Scan for Threats';
    btn.disabled  = false;
  }
}

// ─── Render Results ───────────────────────────────────────────────
function renderResults(data, originalText) {
  const score    = data.overall_score || 0;
  const threats  = data.threat_count  || 0;
  const total    = data.total_sentences || 0;
  const findings = data.findings || [];

  // Summary
  document.getElementById('res-overall').textContent  = `${score}/10`;
  document.getElementById('res-overall').style.color  = scoreColor(score);
  document.getElementById('res-sentences').textContent = total;
  document.getElementById('res-threats').textContent   = threats;

  const verdict = document.getElementById('res-verdict');
  if (score === 0) {
    verdict.textContent  = '✓ All Clear';
    verdict.style.background = 'rgba(16,185,129,0.15)';
    verdict.style.color      = 'var(--safe-color)';
  } else if (score <= 4) {
    verdict.textContent  = '⚠ Mild Risk';
    verdict.style.background = 'rgba(245,158,11,0.15)';
    verdict.style.color      = 'var(--medium-color)';
  } else if (score <= 7) {
    verdict.textContent  = '🔴 High Risk';
    verdict.style.background = 'rgba(239,68,68,0.15)';
    verdict.style.color      = 'var(--high-color)';
  } else {
    verdict.textContent  = '🚨 CRITICAL';
    verdict.style.background = 'rgba(220,38,38,0.2)';
    verdict.style.color      = 'var(--critical-color)';
  }

  // Highlighted Text
  renderHighlighted(originalText, findings);

  // Findings List
  renderFindings(findings);

  // Show results section
  const resultsEl = document.getElementById('scan-results');
  resultsEl.classList.add('visible');
  resultsEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ─── Highlighted Text ─────────────────────────────────────────────
function renderHighlighted(text, findings) {
  const container = document.getElementById('highlighted-text');

  if (findings.length === 0) {
    container.innerHTML = `<span style="color:var(--text-secondary);">${escHtml(text)}</span>`;
    return;
  }

  // Build a map of dangerous sentences
  const threatSentences = new Set(findings.map(f => f.sentence.toLowerCase()));
  const sev = {};
  findings.forEach(f => { sev[f.sentence.toLowerCase()] = f.severity; });

  // Split into sentences for highlighting
  const sentences = text.split(/(?<=[.!?])\s+/);

  container.innerHTML = sentences.map(s => {
    const key = s.toLowerCase();
    if (threatSentences.has(key)) {
      const severity = sev[key] || 'medium';
      const color = severity === 'critical' || severity === 'high'
        ? 'rgba(239,68,68,0.22)' : 'rgba(245,158,11,0.18)';
      const border = severity === 'critical' || severity === 'high'
        ? 'rgba(239,68,68,0.6)' : 'rgba(245,158,11,0.5)';
      return `<mark style="background:${color};border-bottom:2px solid ${border};border-radius:3px;padding:0.1rem 0.2rem;color:var(--text-primary);cursor:pointer;" title="⚠ Threat detected">${escHtml(s)}</mark> `;
    }
    return `<span style="color:var(--text-secondary);">${escHtml(s)}</span> `;
  }).join('');
}

// ─── Findings List ────────────────────────────────────────────────
function renderFindings(findings) {
  const container = document.getElementById('sentence-findings');

  if (findings.length === 0) {
    container.innerHTML = `
      <div style="text-align:center;padding:2rem;color:var(--safe-color);">
        <i class="fas fa-circle-check" style="font-size:2rem;margin-bottom:0.75rem;display:block;"></i>
        <strong>No threats found!</strong> This text appears to be safe.
      </div>
    `;
    return;
  }

  // Sort by score descending
  const sorted = [...findings].sort((a, b) => b.score - a.score);

  container.innerHTML = sorted.map((f, i) => {
    const sev   = f.severity || scoreToSeverity(f.score);
    const color = scoreColor(f.score);
    const icon  = f.score >= 7 ? '🚨' : f.score >= 5 ? '🔴' : '⚠️';
    return `
      <div class="finding-item ${sev}" style="animation:msg-appear 0.35s ${i * 0.07}s both;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.5rem;flex-wrap:wrap;gap:0.4rem;">
          <div style="display:flex;align-items:center;gap:0.5rem;">
            <span style="font-size:0.9rem;">${icon}</span>
            <span class="threat-badge ${severityBadge(sev)}" style="font-size:0.72rem;">${escHtml(f.type || 'Unknown')}</span>
          </div>
          <span style="font-size:0.8rem;font-weight:700;color:${color};">Score: ${f.score}/10</span>
        </div>
        <div class="finding-sentence">"${escHtml(f.sentence.substring(0, 140))}${f.sentence.length > 140 ? '…' : ''}"</div>
        ${f.explanation ? `<div class="finding-detail"><i class="fas fa-robot" style="color:var(--accent-purple);margin-right:0.3rem;font-size:0.7rem;"></i>${escHtml(f.explanation.substring(0, 160))}…</div>` : ''}
      </div>
    `;
  }).join('');
}

// ─── Helpers ─────────────────────────────────────────────────────
function scoreColor(score) {
  if (score <= 3)  return '#10b981';
  if (score <= 5)  return '#f59e0b';
  if (score <= 7)  return '#ef4444';
  return '#dc2626';
}

function scoreToSeverity(score) {
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

window.runScan   = runScan;
window.clearScan = clearScan;
window.loadSample = loadSample;
