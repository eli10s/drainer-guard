// Drainer Guard — Background Service Worker
const DRAINER_WALLET_DB = [
  'GK4Note9oHQY84JEtBFBRb6rBS8mSqryFQffdrWv67cR',
];

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'finding') {
    // Store finding
    const key = 'scan_' + new URL(sender.tab ? sender.tab.url : 'unknown').hostname;
    chrome.storage.local.get(key, (data) => {
      const existing = data[key] || { findings: [], timestamp: Date.now(), url: sender.tab ? sender.tab.url : '' };
      existing.findings.push(message.finding);
      existing.timestamp = Date.now();
      chrome.storage.local.set({ [key]: existing });
    });
  }

  if (message.action === 'alert') {
    // Show notification
    chrome.notifications.create({
      type: 'basic',
      iconUrl: 'icons/icon128.png',
      title: message.alert.title,
      message: message.alert.message,
      priority: 2
    });
  }
});

// Scan tab when updated
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    // Content script akan jalan otomatis
  }
});
