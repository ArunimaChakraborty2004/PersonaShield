function loadLogs() {
  fetch('http://localhost:5000/api/logs')
    .then(response => {
      if (!response.ok) throw new Error("Failed to fetch logs");
      return response.json();
    })
    .then(data => {
      displayLogs(data);
      renderThreatChart(data);
    })
    .catch(error => console.error("Error loading logs:", error));
}

function searchLogs() {
  const query = document.getElementById('search-input').value.trim();
  fetch(`http://localhost:5000/api/search?q=${encodeURIComponent(query)}`)
    .then(response => {
      if (!response.ok) throw new Error("Search failed");
      return response.json();
    })
    .then(data => {
      displayLogs(data);
      renderThreatChart(data);
    })
    .catch(error => console.error("Search error:", error));
}

function displayLogs(logs) {
  const tbody = document.getElementById('log-entries');
  tbody.innerHTML = "";

  logs.forEach(log => {
    console.log("Message:", log.text);
    console.log("matched_keywords:", log.matched_keywords);
    console.log("matched_phrases:", log.matched_phrases);

    const triggers = [
      ...(log.matched_keywords ?? []),
      ...(log.matched_phrases ?? [])
    ];

    const triggerList = triggers.length
      ? `<ul>${triggers.map(t => `<li>${t}</li>`).join('')}</ul>`
      : `<p style="color:#888;">⚠️ No triggers matched (possibly safe or legacy log)</p>`;

    const explainPanel = `
      <details style="margin-top: 8px;">
        <summary style="cursor:pointer; color:#aaa;">Why was this flagged?</summary>
        <div style="padding: 8px; color: #ccc;">
          <strong>Threat Type:</strong> ${log.threat_type}<br/>
          <strong>Score:</strong> ${log.score}<br/>
          <strong>Triggers:</strong> ${triggerList}
        </div>
      </details>
    `;

    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${log.text}${explainPanel}</td>
      <td>${log.score}</td>
      <td>${log.threat_type}</td>
      <td>${new Date(log.timestamp).toLocaleString()}</td>
      <td>${log.feedback || "Not rated"}</td>
      <td>
        <button onclick="submitFeedback('${log._id}', 'accurate')">✅</button>
        <button onclick="submitFeedback('${log._id}', 'false_positive')">❌</button>
      </td>
    `;
    tbody.appendChild(row);
  });
}

function submitFeedback(id, feedbackValue) {
  fetch(`http://localhost:5000/api/feedback/${id}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ feedback: feedbackValue })
  })
  .then(response => {
    if (!response.ok) throw new Error("Feedback failed");
    return response.json();
  })
  .then(() => loadLogs())
  .catch(error => console.error("Feedback error:", error));
}

function renderThreatChart(logs) {
  const frequency = {};

  logs.forEach(log => {
    const type = log.threat_type || "Safe";
    frequency[type] = (frequency[type] || 0) + 1;
  });

  const labels = Object.keys(frequency);
  const counts = Object.values(frequency);

  const ctx = document.getElementById('threatChart').getContext('2d');

  if (window.threatChartInstance) {
    window.threatChartInstance.destroy();
  }

  window.threatChartInstance = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: labels,
      datasets: [{
        label: 'Threat Count',
        data: counts,
        backgroundColor: '#ff6384',
        borderColor: '#ff3c6f',
        borderWidth: 1
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          labels: {
            color: '#ccc',
            font: { size: 14 }
          }
        },
        title: {
          display: true,
          text: 'Threat Types Detected',
          color: '#eee',
          font: { size: 18 }
        }
      },
      scales: {
        x: {
          ticks: { color: '#ccc', font: { size: 14 } },
          title: {
            display: true,
            text: 'Threat Type',
            color: '#ccc',
            font: { size: 16 }
          }
        },
        y: {
          ticks: { color: '#ccc', font: { size: 14 } },
          title: {
            display: true,
            text: 'Count',
            color: '#ccc',
            font: { size: 16 }
          }
        }
      }
    }
  });
}

// ✅ Initial page load
window.onload = loadLogs;
