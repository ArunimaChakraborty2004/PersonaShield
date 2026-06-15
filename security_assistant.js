let assistantContextId = null;

document.addEventListener('DOMContentLoaded', () => {
    // Check if we came here with a context ID from another page
    const urlParams = new URLSearchParams(window.location.search);
    const scanId = urlParams.get('scan_id');
    
    if (scanId) {
        assistantContextId = scanId;
        // Auto-send a prompt asking to explain the scan
        addAssistantMessage("user", "Explain this scan result.");
        fetchAssistantResponse("Explain why this was flagged and break down the risk score.", scanId);
        // Remove from URL so refreshing doesn't trigger it again
        window.history.replaceState({}, document.title, "/security_assistant");
    } else {
        showWelcome();
    }
});

function showWelcome() {
    const box = document.getElementById('assistant-chat-box');
    box.innerHTML = `
        <div class="assistant-welcome">
            <div class="assistant-welcome-icon"><i class="fas fa-user-shield"></i></div>
            <h2>Hello. I'm PersonaShield AI.</h2>
            <p>Ask me anything about cybersecurity threats, online safety, and safe browsing practices.</p>
            
            <div class="assistant-topics">
                <span class="topic-badge"><i class="fas fa-check"></i> Phishing</span>
                <span class="topic-badge"><i class="fas fa-check"></i> Social Engineering</span>
                <span class="topic-badge"><i class="fas fa-check"></i> Malicious URLs</span>
                <span class="topic-badge"><i class="fas fa-check"></i> Password Security</span>
                <span class="topic-badge"><i class="fas fa-check"></i> Scam Detection</span>
            </div>

            <div class="suggested-questions">
                <button class="suggested-btn" onclick="sendSuggested('Why is phishing dangerous?')">
                    <i class="fas fa-comment-dots" style="color:var(--accent-purple);margin-right:0.5rem;"></i>
                    Why is phishing dangerous?
                </button>
                <button class="suggested-btn" onclick="sendSuggested('How do I spot fake websites?')">
                    <i class="fas fa-comment-dots" style="color:var(--accent-purple);margin-right:0.5rem;"></i>
                    How do I spot fake websites?
                </button>
                <button class="suggested-btn" onclick="sendSuggested('What makes a URL suspicious?')">
                    <i class="fas fa-comment-dots" style="color:var(--accent-purple);margin-right:0.5rem;"></i>
                    What makes a URL suspicious?
                </button>
                <button class="suggested-btn" onclick="sendSuggested('How do attackers steal credentials?')">
                    <i class="fas fa-comment-dots" style="color:var(--accent-purple);margin-right:0.5rem;"></i>
                    How do attackers steal credentials?
                </button>
                <button class="suggested-btn" style="grid-column: span 2;" onclick="sendSuggested('Explain my latest scan result.')">
                    <i class="fas fa-search" style="color:var(--accent-blue);margin-right:0.5rem;"></i>
                    Explain my latest scan result
                </button>
            </div>
        </div>
    `;
}

function sendSuggested(text) {
    document.getElementById('assistant-message-input').value = text;
    sendAssistantMessage();
}

async function sendAssistantMessage() {
    const input = document.getElementById('assistant-message-input');
    const text = input.value.trim();
    if (!text) return;

    // Clear welcome message if it's the first message
    const welcome = document.querySelector('.assistant-welcome');
    if (welcome) welcome.remove();

    addAssistantMessage('user', text);
    input.value = '';

    await fetchAssistantResponse(text, assistantContextId);
}

async function fetchAssistantResponse(text, explicitScanId) {
    showTyping(true);

    try {
        const res = await fetch('/api/security_assistant', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ question: text, scan_id: explicitScanId })
        });
        const data = await res.json();
        showTyping(false);

        if (data.error) {
            addAssistantMessage('bot', `**Error:** ${data.error}`);
        } else {
            addAssistantMessage('bot', data.answer);
            // Clear context ID after it's been used once explicitly
            if (assistantContextId) assistantContextId = null;
        }
    } catch (e) {
        showTyping(false);
        addAssistantMessage('bot', '**Connection Error:** Unable to reach the AI service.');
    }
}

function addAssistantMessage(sender, text) {
    const box = document.getElementById('assistant-chat-box');
    const isUser = sender === 'user';
    
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const avatar = isUser ? 'avatar.png' : 'avatar.png';
    const senderName = isUser ? 'You' : 'PersonaShield AI';
    
    // Parse markdown if bot
    const formattedText = isUser ? escapeHtml(text) : marked.parse(text);

    const msgId = 'msg-' + Date.now();

    const html = `
        <div class="chat-message ${isUser ? 'user-message' : 'bot-message'}" id="${msgId}">
            <img src="${avatar}" alt="Avatar" class="msg-avatar">
            <div class="msg-bubble-wrap assistant-wrap">
                <div class="msg-sender">${senderName} <span style="font-weight:normal;opacity:0.6;text-transform:none;">• ${time}</span></div>
                <div class="msg-bubble assistant-bubble" id="text-${msgId}">
                    ${formattedText}
                </div>
                ${!isUser ? `
                <div class="msg-toolbar">
                    <button onclick="copyMessage('text-${msgId}')"><i class="fas fa-copy"></i> Copy</button>
                </div>
                ` : ''}
            </div>
        </div>
    `;
    
    box.insertAdjacentHTML('beforeend', html);
    box.scrollTop = box.scrollHeight;
}

function showTyping(show) {
    const ind = document.getElementById('assistant-typing-indicator');
    if (show) {
        ind.classList.remove('hidden');
        const box = document.getElementById('assistant-chat-box');
        box.scrollTop = box.scrollHeight;
    } else {
        ind.classList.add('hidden');
    }
}

function clearAssistantChat() {
    showWelcome();
}

function copyMessage(elementId) {
    const el = document.getElementById(elementId);
    if (el) {
        navigator.clipboard.writeText(el.innerText).then(() => {
            // Optional: show small toast
            console.log('Copied to clipboard');
        });
    }
}

function escapeHtml(unsafe) {
    return unsafe
         .replace(/&/g, "&amp;")
         .replace(/</g, "&lt;")
         .replace(/>/g, "&gt;")
         .replace(/"/g, "&quot;")
         .replace(/'/g, "&#039;");
}
