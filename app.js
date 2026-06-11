/* ============================================================
   PersonaShield — Chat Analyzer (app.js)
   ============================================================ */

// ─── State ────────────────────────────────────────────────────────
const state = {
  totalMessages: 0,
  threatsDetected: 0,
  lastScore: 0,
  recentItems: []
};

// ─── On Load ──────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  addWelcomeMessage();
  updateGauge(0);
});

function addWelcomeMessage() {
  const chatBox = document.getElementById('chat-box');
  const welcome = document.createElement('div');
  welcome.className = 'chat-message bot-message';
  welcome.innerHTML = `
    <img src="avatar.png" alt="Bot" class="msg-avatar">
    <div class="msg-bubble-wrap">
      <div class="msg-sender">PersonaShield AI</div>
      <div class="msg-bubble">
        👋 <strong>Welcome to PersonaShield!</strong><br><br>
        I analyze messages for <strong>social engineering</strong>, <strong>phishing</strong>,
        and <strong>manipulation tactics</strong> in real-time.<br><br>
        Type or paste any message — email, chat, SMS — and I'll tell you if it's a threat. 🛡️
      </div>
      <div class="msg-time">${getTime()}</div>
    </div>
  `;
  chatBox.appendChild(welcome);
}

// ─── Send Message ─────────────────────────────────────────────────
async function sendMessage() {
  const input = document.getElementById('message-input');
  const message = input.value.trim();
  if (!message) return;

  input.value = '';
  hideQuickReplies();
  addUserMessage(message);
  showTyping(true);

  try {
    const res  = await fetch('/api/detect_threat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message })
    });
    const data = await res.json();
    showTyping(false);

    state.totalMessages++;
    if (data.score > 4) state.threatsDetected++;
    state.lastScore = data.score;
    state.recentItems.unshift({ text: message, score: data.score, type: data.threat_type });
    if (state.recentItems.length > 5) state.recentItems.pop();

    addBotResponse(data);
    updateGauge(data.score);
    updateSessionStats();
    updateRecentList();
    showAlertToast(data);

  } catch (err) {
    showTyping(false);
    addErrorMessage('Could not connect to the server. Make sure Flask is running.');
  }
}

// ─── Messages ─────────────────────────────────────────────────────
function addUserMessage(text) {
  const chatBox = document.getElementById('chat-box');
  const div = document.createElement('div');
  div.className = 'chat-message user-message';
  div.style.animation = 'msg-appear 0.35s cubic-bezier(0.34,1.56,0.64,1) both';
  div.innerHTML = `
    <div class="msg-bubble-wrap">
      <div class="msg-sender" style="text-align:right;">You</div>
      <div class="msg-bubble">${escHtml(text)}</div>
      <div class="msg-time" style="text-align:right;">${getTime()}</div>
    </div>
    <img src="avatar.png" alt="You" class="msg-avatar" style="border-color:var(--accent-blue);">
  `;
  chatBox.appendChild(div);
  scrollChat();
}

function addBotResponse(data) {
  const chatBox = document.getElementById('chat-box');
  const div = document.createElement('div');
  div.className = 'chat-message bot-message';

  const severity  = data.severity || scoreToSeverity(data.score);
  const badgeClass = `badge-${severity === 'low' ? 'safe' : severity}`;
  const badgeLabel = data.threat_type || 'Safe';
  const scoreColor = getScoreColor(data.score);

  // Build triggers list
  const triggers = [...(data.matched_keywords || []), ...(data.matched_phrases || [])];
  const triggerHtml = triggers.length
    ? `<button class="triggers-toggle" onclick="toggleTriggers(this)">
         <i class="fas fa-chevron-right" style="font-size:0.65rem;transition:transform 0.2s;"></i>
         View ${triggers.length} trigger${triggers.length > 1 ? 's' : ''}
       </button>
       <div class="triggers-list" style="display:none;">
         ${triggers.map(t => `<span class="trigger-chip">${escHtml(t)}</span>`).join('')}
       </div>`
    : '<span style="font-size:0.78rem;color:var(--text-muted);">No suspicious triggers found.</span>';

  // Natural-language AI response
  const intro = buildNaturalResponse(data);

  // AI explanation block
  const aiBlock = data.explanation
    ? `<div class="ai-explanation">
         <strong>${data.ai_powered ? '🤖 AI Analysis' : '🔍 Analysis'}</strong><br>
         ${escHtml(data.explanation)}
         ${data.recommendation ? `<br><br><em>💡 ${escHtml(data.recommendation)}</em>` : ''}
       </div>`
    : '';

  div.innerHTML = `
    <img src="avatar.png" alt="Bot" class="msg-avatar">
    <div class="msg-bubble-wrap">
      <div class="msg-sender">PersonaShield AI</div>
      <div class="msg-bubble">
        ${intro}
        <div class="threat-result ${severity}" style="margin-top:0.75rem;">
          <div class="threat-header">
            <span class="threat-badge ${badgeClass}">
              ${getSeverityIcon(severity)} ${escHtml(badgeLabel)}
            </span>
            <div class="score-ring-wrap">
              ${buildScoreRing(data.score, scoreColor)}
            </div>
          </div>
          <div class="threat-triggers">${triggerHtml}</div>
          ${aiBlock}
        </div>
      </div>
      <div class="msg-time">${getTime()}</div>
    </div>
  `;
  chatBox.appendChild(div);
  scrollChat();

  // Animate score rings
  animateRings(div, data.score);
}

function addErrorMessage(msg) {
  const chatBox = document.getElementById('chat-box');
  const div = document.createElement('div');
  div.className = 'chat-message bot-message';
  div.innerHTML = `
    <img src="avatar.png" alt="Bot" class="msg-avatar">
    <div class="msg-bubble-wrap">
      <div class="msg-sender">PersonaShield AI</div>
      <div class="msg-bubble" style="border-color:rgba(239,68,68,0.4);">
        ⚠️ ${escHtml(msg)}
      </div>
      <div class="msg-time">${getTime()}</div>
    </div>
  `;
  chatBox.appendChild(div);
  scrollChat();
}

// ─── Natural Language Responses ───────────────────────────────────
function buildNaturalResponse(data) {
  const score = data.score;
  const type  = data.threat_type || 'Safe';

  if (score === 0) {
    return '✅ <strong>This message looks completely safe.</strong> No threat indicators detected.';
  } else if (score <= 3) {
    return `🟡 <strong>Mild concern detected.</strong> This message has a few suspicious elements — stay cautious.`;
  } else if (score <= 5) {
    return `⚠️ <strong>Moderate threat detected — "${escHtml(type)}".</strong> This message shows clear warning signs. Don't act without verifying.`;
  } else if (score <= 7) {
    return `🔴 <strong>High threat! "${escHtml(type)}" tactics identified.</strong> This message is likely a social engineering attempt. Do NOT comply.`;
  } else {
    return `🚨 <strong>CRITICAL THREAT! "${escHtml(type)}" — Score: ${score}/10.</strong> This is a highly dangerous message with multiple attack vectors. Ignore and report immediately.`;
  }
}

// ─── Score Ring SVG ───────────────────────────────────────────────
function buildScoreRing(score, color) {
  const circumference = 2 * Math.PI * 16; // r=16
  return `
    <svg class="score-ring-svg" viewBox="0 0 40 40">
      <circle class="score-ring-bg"   cx="20" cy="20" r="16"/>
      <circle class="score-ring-fill" cx="20" cy="20" r="16"
              stroke="${color}"
              stroke-dasharray="${circumference}"
              stroke-dashoffset="${circumference}"
              data-score="${score}"
              data-circ="${circumference}"/>
      <text class="score-ring-text" x="20" y="21">${score}</text>
    </svg>
    <div>
      <div class="score-value" style="color:${color};">${score}/10</div>
      <div class="score-label">Risk Score</div>
    </div>
  `;
}

function animateRings(container, score) {
  setTimeout(() => {
    container.querySelectorAll('.score-ring-fill').forEach(el => {
      const circ  = parseFloat(el.dataset.circ);
      const sc    = parseFloat(el.dataset.score);
      const offset = circ - (sc / 10) * circ;
      el.style.strokeDashoffset = offset;
    });
  }, 100);
}

// ─── Live Gauge ───────────────────────────────────────────────────
function updateGauge(score) {
  const arc      = document.getElementById('gauge-arc');
  const num      = document.getElementById('gauge-num');
  const status   = document.getElementById('gauge-status');
  if (!arc) return;

  // Arc goes from 135° to 405° (270° range)
  const r          = 48;
  const total      = 2 * Math.PI * r;   // full circumference
  const arcLen     = total * 0.75;       // 270° = 75% of full circle
  const dashOffset = arcLen - (score / 10) * arcLen;

  const color = getScoreColor(score);
  arc.style.stroke          = color;
  arc.style.strokeDasharray = `${arcLen} ${total}`;
  arc.style.strokeDashoffset = dashOffset;

  num.textContent = score;

  const { label, cls } = getStatusLabel(score);
  status.textContent = label;
  status.className   = `gauge-status ${cls}`;
}

// ─── Quick Replies ────────────────────────────────────────────────
function quickReply(type) {
  const chatBox = document.getElementById('chat-box');

  if (type === 'sample phishing') {
    document.getElementById('message-input').value =
      'Urgent! Your account has been compromised. Click here immediately to verify your credentials and reset your password.';
    sendMessage();
    return;
  }

  hideQuickReplies();

  let text = '';
  if (type === 'What can you do?') {
    text = `🛡️ <strong>What PersonaShield Can Do:</strong><br><br>
      • Detect <strong>phishing</strong>, <strong>urgency manipulation</strong>, and <strong>impersonation</strong><br>
      • Score any message from 0 (safe) to 10 (critical)<br>
      • Explain <em>why</em> something was flagged<br>
      • Power AI analysis using Google Gemini<br>
      • Log every scan to a secure dashboard<br>
      • Bulk-scan entire emails or documents`;
  } else if (type === 'Tell me about privacy') {
    text = `🔐 <strong>Privacy First:</strong><br><br>
      PersonaShield processes messages locally on your server. Messages are stored in your own MongoDB database — never sent to external servers (except Gemini API if enabled).<br><br>
      All logs are anonymized and used solely for system insights.`;
  } else if (type === 'Help!') {
    text = `💬 <strong>How to Use PersonaShield:</strong><br><br>
      1. Type or paste any suspicious message in the input box<br>
      2. Press <strong>Enter</strong> or click the ➤ button<br>
      3. Review the risk score, threat type, and AI explanation<br>
      4. Visit the <strong>Dashboard</strong> to see all past scans<br>
      5. Use <strong>Bulk Scanner</strong> to analyze entire emails`;
  }

  addUserMessage(type);

  setTimeout(() => {
    const div = document.createElement('div');
    div.className = 'chat-message bot-message';
    div.innerHTML = `
      <img src="avatar.png" alt="Bot" class="msg-avatar">
      <div class="msg-bubble-wrap">
        <div class="msg-sender">PersonaShield AI</div>
        <div class="msg-bubble">${text}</div>
        <div class="msg-time">${getTime()}</div>
      </div>
    `;
    chatBox.appendChild(div);
    scrollChat();
  }, 400);
}

// ─── Alert Toast ──────────────────────────────────────────────────
function showAlertToast(data) {
  const panel = document.getElementById('alert-panel');
  const inner = document.getElementById('alert-inner');
  const icon  = document.getElementById('alert-icon');
  const text  = document.getElementById('alert-text');
  const sub   = document.getElementById('alert-sub');

  if (data.score === 0) {
    inner.className = 'alert-inner safe';
    icon.textContent = '✓';
    text.textContent = 'Message is safe';
    sub.textContent  = 'No threats detected';
  } else if (data.score <= 4) {
    inner.className = 'alert-inner warning';
    icon.textContent = '⚠';
    text.textContent = 'Mild concern detected';
    sub.textContent  = `Score: ${data.score}/10 — ${data.threat_type}`;
  } else {
    inner.className = 'alert-inner danger';
    icon.textContent = '🚨';
    text.textContent = `${data.threat_type} threat!`;
    sub.textContent  = `Risk score: ${data.score}/10`;
  }

  panel.classList.add('show');
  setTimeout(() => panel.classList.remove('show'), 4000);
}

// ─── Session Stats ────────────────────────────────────────────────
function updateSessionStats() {
  const total   = document.getElementById('stat-total');
  const threats = document.getElementById('stat-threats');
  if (total)   total.textContent   = state.totalMessages;
  if (threats) threats.textContent = state.threatsDetected;
}

function updateRecentList() {
  const list = document.getElementById('recent-list');
  if (!list) return;

  if (state.recentItems.length === 0) {
    list.innerHTML = '<div style="font-size:0.78rem;color:var(--text-muted);padding:0.5rem 0;">No activity yet.</div>';
    return;
  }

  list.innerHTML = state.recentItems.map(item => {
    const cls = item.score === 0 ? 'safe' : item.score <= 5 ? 'medium' : 'high';
    return `
      <div class="recent-item">
        <div class="recent-dot ${cls}"></div>
        <div class="recent-text">${escHtml(item.text.substring(0, 40))}${item.text.length > 40 ? '…' : ''}</div>
        <div class="recent-score">${item.score}/10</div>
      </div>
    `;
  }).join('');
}

// ─── Helpers ──────────────────────────────────────────────────────
function clearChat() {
  const chatBox = document.getElementById('chat-box');
  chatBox.innerHTML = '';
  state.totalMessages  = 0;
  state.threatsDetected = 0;
  state.recentItems    = [];
  updateSessionStats();
  updateRecentList();
  updateGauge(0);
  addWelcomeMessage();
  document.getElementById('quick-replies').style.display = 'flex';
}

function showTyping(show) {
  const el = document.getElementById('typing-indicator');
  if (show) { el.classList.remove('hidden'); scrollChat(); }
  else       { el.classList.add('hidden'); }
}

function hideQuickReplies() {
  document.getElementById('quick-replies').style.display = 'none';
}

function scrollChat() {
  const chatBox = document.getElementById('chat-box');
  requestAnimationFrame(() => { chatBox.scrollTop = chatBox.scrollHeight; });
}

function toggleTriggers(btn) {
  const list = btn.nextElementSibling;
  const icon = btn.querySelector('i');
  const hidden = list.style.display === 'none';
  list.style.display = hidden ? 'flex' : 'none';
  icon.style.transform = hidden ? 'rotate(90deg)' : 'rotate(0deg)';
}

function showAbout() {
  const chatBox = document.getElementById('chat-box');
  const div = document.createElement('div');
  div.className = 'chat-message bot-message';
  div.innerHTML = `
    <img src="avatar.png" alt="Bot" class="msg-avatar">
    <div class="msg-bubble-wrap">
      <div class="msg-sender">PersonaShield AI</div>
      <div class="msg-bubble">
        🛡️ <strong>About PersonaShield</strong><br><br>
        Built to protect users from <strong>social engineering attacks</strong> — 
        the #1 cause of data breaches.<br><br>
        <strong>Tech Stack:</strong><br>
        • Backend: Flask + Python<br>
        • AI: Google Gemini 1.5 Flash<br>
        • Database: MongoDB<br>
        • Frontend: HTML + CSS + JavaScript<br><br>
        Made with ❤️ by <strong style="color:var(--accent-blue);">Arunima</strong>
      </div>
      <div class="msg-time">${getTime()}</div>
    </div>
  `;
  chatBox.appendChild(div);
  scrollChat();
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function getTime() {
  return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function getScoreColor(score) {
  if (score === 0)      return '#10b981'; // green
  if (score <= 3)       return '#10b981'; // green
  if (score <= 5)       return '#f59e0b'; // amber
  if (score <= 7)       return '#ef4444'; // red
  return '#dc2626';                       // critical red
}

function scoreToSeverity(score) {
  if (score === 0) return 'safe';
  if (score <= 3)  return 'safe';
  if (score <= 5)  return 'medium';
  if (score <= 7)  return 'high';
  return 'critical';
}

function getStatusLabel(score) {
  if (score === 0)     return { label: '✓ Safe',    cls: 'safe' };
  if (score <= 3)      return { label: '⚡ Low',    cls: 'safe' };
  if (score <= 5)      return { label: '⚠ Medium',  cls: 'medium' };
  if (score <= 7)      return { label: '🔴 High',   cls: 'high' };
  return                      { label: '🚨 Critical', cls: 'critical' };
}

function getSeverityIcon(severity) {
  const icons = { safe: '✓', low: '⚡', medium: '⚠️', high: '🔴', critical: '🚨' };
  return icons[severity] || '•';
}

// Expose to window
window.sendMessage  = sendMessage;
window.clearChat    = clearChat;
window.quickReply   = quickReply;
window.toggleTriggers = toggleTriggers;
window.showAbout    = showAbout;
