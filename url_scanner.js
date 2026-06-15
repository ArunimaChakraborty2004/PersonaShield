/* ============================================================
   PersonaShield — URL Scanner Logic (url_scanner.js)
   ============================================================ */

// ─── Samples ──────────────────────────────────────────────────
const SAMPLES = {
  phishing: 'http://192.168.0.1/secure/verify-account-billing-login.php',
  safe:     'https://www.github.com/features/copilot'
};

// ─── Entry point: scan button / Enter key ─────────────────────
function scanUrl() {
  const raw = document.getElementById('url-input').value.trim();
  if (!raw) {
    shakeInput();
    return;
  }

  // UI: loading state
  setLoading(true);

  fetch('/api/scan_url', {
    method:  'POST',
    headers: { 'Content-Type': 'application/json' },
    body:    JSON.stringify({ url: raw })
  })
  .then(res => {
    if (!res.ok) throw new Error(`Server returned ${res.status}`);
    return res.json();
  })
  .then(data => {
    setLoading(false);
    if (data.error) {
      showError(data.error);
      return;
    }
    displayResults(data);
  })
  .catch(err => {
    setLoading(false);
    showError('Could not reach the server. Make sure the Flask app is running.');
    console.error('[URL Scanner]', err);
  });
}

// ─── Render results ───────────────────────────────────────────
let currentScanId = null;

function displayResults(data) {
  currentScanId = data.scan_id || null;
  const btn = document.getElementById('download-report-btn');
  if(btn) btn.style.display = currentScanId ? 'inline-block' : 'none';
  
  const aiBtn = document.getElementById('explain-ai-btn');
  if(aiBtn) aiBtn.style.display = currentScanId ? 'inline-block' : 'none';

  // Show results section
  document.getElementById('url-results').style.display = 'block';

  // ── URL label ──
  document.getElementById('res-url').textContent = data.url;

  // ── Score ring animation ──
  const score     = data.risk_score ?? 0;
  const circumference = 2 * Math.PI * 50; // r=50
  const offset    = circumference - (score / 10) * circumference;
  const ringColor = scoreToColor(score);

  const arc = document.getElementById('url-ring-arc');
  arc.style.stroke             = ringColor;
  arc.style.strokeDashoffset   = circumference; // start at 0
  // Force reflow then animate
  arc.getBoundingClientRect();
  arc.style.transition = 'stroke-dashoffset 1s cubic-bezier(0.4,0,0.2,1), stroke 0.5s';
  arc.style.strokeDashoffset = offset;

  const numEl = document.getElementById('url-ring-num');
  numEl.textContent = score;
  numEl.style.fill  = ringColor;

  // ── Status badge ──
  const badge = document.getElementById('res-status-badge');
  const statusLower = (data.status || 'safe').toLowerCase();
  badge.className  = `url-status-badge ${statusLower}`;
  badge.innerHTML  = `${statusIcon(statusLower)} ${data.status}`;

  // ── Explanation & Recommendation ──
  document.getElementById('res-explanation').textContent    = data.explanation    || '—';
  document.getElementById('res-recommendation').textContent = data.recommendation || '—';

  // ── Confidence, Threat Type, Domain Age, AI ──
  document.getElementById('res-confidence').textContent = (data.confidence !== undefined) ? `${data.confidence}%` : '—';
  document.getElementById('res-threat-type').textContent = data.threat_type || 'Unknown';
  document.getElementById('res-domain-age').textContent = (data.domain_age !== undefined && data.domain_age !== null) ? data.domain_age : 'Unknown';
  
  const aiBadge = document.getElementById('res-ai-analysis');
  if (data.ai_powered) {
    aiBadge.innerHTML = '<span style="color:var(--accent-purple);font-weight:bold;"><i class="fas fa-check-circle"></i> AI Evaluated</span>';
  } else {
    aiBadge.innerHTML = '<span style="color:var(--text-muted);">Rule-based (No AI)</span>';
  }

  // ── Detection Sources ──
  const ul = document.getElementById('res-sources');
  ul.innerHTML = '';

  if (data.sources && data.sources.length > 0) {
    data.sources.forEach(src => {
      const li = document.createElement('li');
      li.textContent = src;
      ul.appendChild(li);
    });
  } else {
    const li = document.createElement('li');
    li.className   = 'safe';
    li.textContent = 'No threat indicators detected in URL structure.';
    ul.appendChild(li);
  }

  // Scroll into view smoothly
  document.getElementById('url-results').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ─── Helpers ──────────────────────────────────────────────────

/**
 * Maps a risk score to a display colour.
 * @param {number} score  0–10
 * @returns {string} CSS colour
 */
function scoreToColor(score) {
  if (score >= 7) return '#ef4444';   // red   — Malicious
  if (score >= 4) return '#f59e0b';   // amber — Suspicious
  return '#10b981';                   // green — Safe
}

/**
 * Returns an appropriate icon HTML string for a status.
 * @param {string} status  'safe' | 'suspicious' | 'malicious'
 */
function statusIcon(status) {
  if (status === 'malicious')  return '<i class="fas fa-skull-crossbones"></i>';
  if (status === 'suspicious') return '<i class="fas fa-triangle-exclamation"></i>';
  return '<i class="fas fa-shield-check"></i>';
}

/**
 * Toggles the loading / results / input visibility.
 * @param {boolean} on
 */
function setLoading(on) {
  const loading = document.getElementById('url-loading');
  const results = document.getElementById('url-results');
  const btn     = document.getElementById('scan-btn');

  if (on) {
    loading.style.display = 'block';
    results.style.display = 'none';
    btn.disabled          = true;
    btn.innerHTML         = '<i class="fas fa-circle-notch fa-spin"></i> Scanning…';
  } else {
    loading.style.display = 'none';
    btn.disabled          = false;
    btn.innerHTML         = '<i class="fas fa-magnifying-glass-chart"></i> Scan URL';
  }
}

/**
 * Displays an inline error message without using alert().
 * @param {string} msg
 */
function showError(msg) {
  const results = document.getElementById('url-results');
  results.style.display = 'block';
  results.innerHTML = `
    <div class="glass-card" style="padding:2rem;text-align:center;border-color:rgba(239,68,68,0.4);">
      <i class="fas fa-circle-xmark" style="font-size:2.5rem;color:var(--high-color);margin-bottom:1rem;"></i>
      <p style="color:var(--text-secondary);font-size:0.95rem;">${msg}</p>
      <button class="scan-btn btn-secondary" style="margin-top:1.25rem;" onclick="clearScan()">
        <i class="fas fa-arrow-left"></i> Try Again
      </button>
    </div>
  `;
}

/**
 * Briefly shakes the input field when submitted empty.
 */
function shakeInput() {
  const input = document.getElementById('url-input');
  input.style.transition   = 'transform 0.1s ease';
  input.style.borderColor  = 'rgba(239,68,68,0.7)';

  let count = 0;
  const shake = setInterval(() => {
    input.style.transform = count % 2 === 0 ? 'translateX(-5px)' : 'translateX(5px)';
    count++;
    if (count > 5) {
      clearInterval(shake);
      input.style.transform = '';
      setTimeout(() => { input.style.borderColor = ''; }, 600);
    }
  }, 60);

  input.focus();
}

// ─── Clear / Sample ───────────────────────────────────────────

/** Resets the page to the initial input state. */
function clearScan() {
  document.getElementById('url-input').value    = '';
  document.getElementById('url-results').style.display = 'none';
  document.getElementById('url-loading').style.display = 'none';
  document.getElementById('url-input').focus();
}

/**
 * Pre-fills the input with a demonstration URL.
 * @param {'phishing'|'safe'} type
 */
function loadSample(type) {
  document.getElementById('url-input').value = SAMPLES[type] || SAMPLES.phishing;
  document.getElementById('url-results').style.display = 'none';
  document.getElementById('url-input').focus();
}

function downloadCurrentReport() {
  if (currentScanId) {
    window.open(`/api/report/${currentScanId}?type=url`, '_blank');
  }
}

function explainCurrentScan() {
  if (currentScanId) {
    window.location.href = `/security_assistant?scan_id=${currentScanId}`;
  }
}

// ─── Expose globals for inline onclick handlers ────────────────
window.scanUrl    = scanUrl;
window.clearScan  = clearScan;
window.loadSample = loadSample;
window.downloadCurrentReport = downloadCurrentReport;
window.explainCurrentScan = explainCurrentScan;
