// Drainer Guard — Popup Logic
const container = document.getElementById('findings-container');
const criticalEl = document.getElementById('critical-count');
const highEl = document.getElementById('high-count');
const mediumEl = document.getElementById('medium-count');
const infoEl = document.getElementById('info-count');
const lastScanEl = document.getElementById('last-scan');

function render() {
  chrome.storage.local.get(null, (all) => {
    const findings = [];
    for (const key in all) {
      if (key.startsWith('scan_')) {
        const data = all[key];
        if (data && data.findings) {
          for (const f of data.findings) {
            findings.push(f);
          }
        }
      }
    }

    // Sort by severity then timestamp
    const order = { critical: 0, high: 1, medium: 2, info: 3 };
    findings.sort((a, b) => (order[a.severity] || 9) - (order[b.severity] || 9) || b.timestamp - a.timestamp);

    const criticalCount = findings.filter(f => f.severity === 'critical').length;
    const highCount = findings.filter(f => f.severity === 'high').length;
    const mediumCount = findings.filter(f => f.severity === 'medium').length;
    const infoCount = findings.filter(f => f.severity === 'info').length;

    criticalEl.textContent = criticalCount;
    highEl.textContent = highCount;
    mediumEl.textContent = mediumCount;
    infoEl.textContent = infoCount;

    if (findings.length === 0) {
      container.innerHTML = `
        <div class="empty">
          <div class="big">🛡️</div>
          <div>No drainer detected</div>
          <div style="font-size:11px;margin-top:4px;">All sites safe so far</div>
        </div>
      `;
      lastScanEl.textContent = 'All Clear ✅';
      return;
    }

    container.innerHTML = findings.map(f => {
      const icon = { critical: '🔴', high: '🟡', medium: '🔵', info: 'ℹ️' }[f.severity] || '⚪';
      const date = new Date(f.timestamp);
      const time = date.toLocaleTimeString();
      return `
        <div class="finding sev-${f.severity}">
          <div class="icon">${icon}</div>
          <div class="body">
            <div class="detail">${escHtml(f.detail)}</div>
            <div class="url">${escHtml(new URL(f.url).hostname)} — ${time}</div>
          </div>
          <span class="badge badge-${f.severity}">${f.severity.toUpperCase()}</span>
        </div>
      `;
    }).join('');

    const times = findings.map(f => f.timestamp);
    lastScanEl.textContent = `Scan: ${new Date(Math.max(...times)).toLocaleTimeString()}`;
  });
}

function escHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

document.getElementById('clear-btn').addEventListener('click', () => {
  chrome.storage.local.clear(() => {
    render();
  });
});

// Listen for updates from content script
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.action === 'finding' || msg.action === 'alert') {
    render();
  }
});

render();
