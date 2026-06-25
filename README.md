# 🛡️ Drainer Guard

**Multi-chain browser extension** that automatically detects crypto wallet drainer sites before you lose your assets.

## 🔍 Features

| Feature | Detail |
|---------|--------|
| **Solana** 🟣 | Phantom approve, Token-2022, Helius RPC key leak |
| **EVM** 🔷 | MetaMask ERC-20 Approve, setApprovalForAll, Permit |
| **TON** 💎 | Tonkeeper sendTransaction, TonConnect |
| **Real-time** ⚡ | Intercept wallet calls before tx is sent |
| **Auto-scan** | Scans every page automatically + re-scans every 3s |
| **Notifications** 🔔 | Chrome notification when a drainer is detected — no intrusive page overlays |
| **Popup** | View all findings with severity levels |

## 🔧 Installation (Developer Mode)

1. Download / clone this repo
2. Open **chrome://extensions**
3. Enable **Developer Mode** (top-right corner)
4. Click **Load unpacked**
5. Select the `drainer-guard/` folder
6. ✅ Done — icon will appear in your toolbar

## 📸 Screenshots

*(add your screenshots here)*

## ⚙️ How It Works

The extension reads **frontend web content** in your browser through 3 detection layers:

1. **Static scan** — scans HTML, JS, title, buttons, forms on page load
2. **DOM monitoring** — re-scans every 3 seconds for dynamically loaded content
3. **Runtime hooking** — intercepts wallet API calls (fetch, signAndSendTransaction, ethereum.request) in real-time

All **client-side**, no data is sent to any server.

> ⚡ **CSP Safe**: Runtime hook script is loaded via `chrome.runtime.getURL('injected.js')` (not inline script), so it bypasses page Content Security Policy restrictions.

## 📁 Structure

```
drainer-guard/
├── manifest.json        # Chrome Extension Manifest V3
├── content.js           # Content script — drainer detection
├── injected.js          # Runtime hook — injected into page (CSP-safe)
├── background.js        # Service worker
├── popup.html           # Popup UI
├── popup.js             # Popup logic
└── icons/               # Extension icons
```

## 🛡️ Detection by Chain

### Solana
- Token approve to suspicious addresses
- Token-2022 (TokenzQdBNb) approve
- Helius/Alchemy RPC key leak in frontend

### EVM (Ethereum, BSC, Polygon, Arbitrum, Base)
- ERC-20 Approve unlimited (0x095ea7b3)
- setApprovalForAll (0xa22cb465)
- Permit / Permit2 (0xd505accf)

### TON
- sendTransaction to suspicious domains

### Generic
- "Claim Airdrop" + "Connect Wallet" — classic scam pattern
- API drainer endpoints (plan.php, telemetry.php, /claim.php)
- maxUint256 / type(uint256).max — unlimited approval
- WebSocket connections to unknown domains

## 📝 MIT License

Free to use, modify, and distribute. Attribution required.
