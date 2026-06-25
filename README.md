# 🛡️ Drainer Guard

**Multi-chain browser extension** yang mendeteksi otomatis situs crypto wallet drainer sebelum kamu kehilangan aset.

## 🔍 Fitur

| Fitur | Detail |
|-------|--------|
| **Solana** 🟣 | Phantom approve, Token-2022, Helius RPC key leak |
| **EVM** 🔷 | MetaMask ERC-20 Approve, setApprovalForAll, Permit |
| **TON** 💎 | Tonkeeper sendTransaction, TonConnect |
| **Real-time** ⚡ | Intercept panggilan wallet sebelum tx dikirim |
| **Auto-scan** | Scan otomatis tiap halaman + re-scan tiap 3 detik |
| **Popup warning** | Tampilkan semua temuan dengan severity level |

## 🔧 Cara Install (Developer Mode)

1. Download / clone repo ini
2. Buka **chrome://extensions**
3. Aktifkan **Developer Mode** (pojok kanan atas)
4. Klik **Load unpacked**
5. Pilih folder `drainer-guard/`
6. ✅ Selesai — icon akan muncul di toolbar

## 📸 Screenshot

*(tambahkan screenshot popup di sini)*

## 🧪 Cara Test

1. Buka https://solgame.pw — akan terdeteksi sebagai **CRITICAL** drainer
2. Klik icon extension — lihat daftar temuan
3. Warna merah = Critical, oranye = High, kuning = Medium

## ⚙️ Cara Kerja

Extension membaca **frontend web** di browser kamu melalui 3 lapisan deteksi:

1. **Static scan** — scan HTML, JS, title, tombol, form saat halaman dimuat
2. **DOM monitoring** — re-scan tiap 3 detik untuk konten dinamis
3. **Runtime hooking** — intercept panggilan wallet (fetch, signAndSendTransaction, ethereum.request)

Semua **client-side**, tidak ada data dikirim ke server.

## 📁 Struktur

```
drainer-guard/
├── manifest.json        # Chrome Extension Manifest V3
├── content.js           # Content script — deteksi drainer
├── background.js        # Service worker
├── popup.html           # Popup UI
├── popup.js             # Popup logic
└── icons/               # Icon extension
```

## 🛡️ Deteksi Berdasarkan Chain

### Solana
- Token approve ke address mencurigakan
- Token-2022 (TokenzQdBNb) approve
- Helius/Alchemy RPC key leak di frontend

### EVM (Ethereum, BSC, Polygon, Arbitrum, Base)
- ERC-20 Approve unlimited (0x095ea7b3)
- setApprovalForAll (0xa22cb465)
- Permit / Permit2 (0xd505accf)

### TON
- sendTransaction ke domain mencurigakan

### Generic
- "Claim Airdrop" + "Connect Wallet" — pola scam klasik
- API endpoint drainer (plan.php, telemetry.php, /claim.php)
- maxUint256 / type(uint256).max — unlimited approve
- WebSocket ke domain tidak dikenal

## 📝 Lisensi

MIT — bebas dipakai, dimodifikasi, dan didistribusikan.
