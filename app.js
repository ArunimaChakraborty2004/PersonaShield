function sendMessage() {
  const input = document.getElementById('message-input');
  const message = input.value.trim();
  if (!message) return;

  // Add user message to chat
  addMessageToChat(message, 'user');
  input.value = '';
  showTypingIndicator(true);

  fetch('http://localhost:5000/api/detect_threat', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ message })
  })
    .then(res => res.json())
    .then(data => {
      showTypingIndicator(false);
      addMessageToChat(formatBotResponse(data), 'bot');
      updateAlert(data.score, data.threat_type);
    })
    .catch(err => {
      showTypingIndicator(false);
      showAlert('Error connecting to server.');
    });
}

function addMessageToChat(text, sender) {
  const chatBox = document.getElementById('chat-box');
  const msgDiv = document.createElement('div');
  msgDiv.className = `chat-message ${sender}-message`;
  msgDiv.innerHTML = `
    <img src="avatar.png" alt="${sender === 'bot' ? 'Bot' : 'You'}" class="avatar">
    <div class="message-content">${text}</div>
  `;
  chatBox.appendChild(msgDiv);
  chatBox.scrollTop = chatBox.scrollHeight;
}

function formatBotResponse(data) {
  const triggers = [...(data.matched_keywords || []), ...(data.matched_phrases || [])];
  const triggerList = triggers.length
    ? `<ul>${triggers.map(t => `<li>${t}</li>`).join('')}</ul>`
    : `<p>No triggers matched.</p>`;

  return `
    <div>
      <strong>Threat Score:</strong> ${data.score}/10<br/>
      <strong>Threat Type:</strong> ${data.threat_type}<br/>
      ${data.text ? `<em>Message:</em> ${data.text}<br/>` : ""}
      <details style="margin-top: 8px;">
        <summary style="cursor:pointer; color:#aaa;">Why was this flagged?</summary>
        <div style="padding:8px; color:#ccc;">
          <strong>Triggers:</strong> ${triggerList}
        </div>
      </details>
    </div>
  `;
}


function showTypingIndicator(show) {
  document.getElementById('typing-indicator').style.display = show ? 'block' : 'none';
}

function showAlert(msg) {
  const alertPanel = document.getElementById('alert-panel');
  alertPanel.textContent = msg;
  alertPanel.style.display = 'block';
  setTimeout(() => {
    alertPanel.style.display = 'none';
  }, 3000);
}

function updateAlert(score, type) {
  const panel = document.getElementById("alert-panel");
  if (score >= 5) {
    panel.textContent = `⚠️ ${type} threat detected! Risk score: ${score}/10`;
  } else {
    panel.textContent = "";
  }
}

function clearChat() {
  document.getElementById("chat-box").innerHTML = "";
  document.getElementById("system-response").innerHTML = "";
  document.getElementById("alert-panel").textContent = "";
}

// Expose functions globally
window.sendMessage = sendMessage;
window.clearChat = clearChat;
