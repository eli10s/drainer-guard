// ============================================================
// Drainer Guard — Content Script
// Mendeteksi pola wallet drainer MULTI-CHAIN (Solana, EVM, TON, dll)
// ============================================================

(async function() {
  // ─── Konfigurasi ───────────────────────────────────────────
  const KNOWN_DRAINER_WALLETS = {
    solana: [
      'GK4Note9oHQY84JEtBFBRb6rBS8mSqryFQffdrWv67cR',
    ],
    evm: [
      // Known EVM drainer addresses (bisa ditambah dari database publik)
    ],
    ton: [],
    sui: [],
    cosmos: [],
  };

  const KNOWN_DRAINER_PATHS = [
    '/api/plan.php',
    '/api/telemetry.php',
    '/api/drain.php',
    '/api/approve.php',
    '/claim.php',
    '/drain.php',
    '/api/wallet/approve',
    '/api/claim/check',
  ];

  // Pattern kode drainer — multi-chain
  const SUSPICIOUS_JS_PATTERNS = [
    // Solana
    'minimum_lamports',
    'calculateTopTokens',
    'maxTokenAmount',
    'DEFAULT_APPROVE_AMOUNT',
    'remainingLamports',
    'tokenAccountBalance',
    // EVM
    'setApprovalForAll',
    'approve(',
    '0x095ea7b3',        // ERC-20 approve selector
    '0xa22cb465',        // ERC-721 setApprovalForAll
    '0xd505accf',        // ERC-2612 permit
    '0xffffffff',        // infinite approval value
    // Generic
    'unlimited.*approve',
    'approve.*unlimited',
    '99,999,999,999,999',
    '99999999999999',
    'maxUint256',
    'type(uint256).max',
    '-1.*approve',
    // TON
    'tonconnect',
    'tonkeeper',
    // Multi-chain RPC
    'getTokenAccountsByOwner',
    'getParsedTokenAccountsByOwner',
    'alchemy.*apiKey',
    'moralis.*apiKey',
    'quicknode.*endpoint',
  ];

  // Regex untuk detect API keys
  const API_KEY_REGEXES = {
    helius: /([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/gi,
    alchemy: /alchemy_[a-zA-Z0-9]{32,}/gi,
    moralis: /[a-zA-Z0-9]{32,}/gi,
    infura: /[a-f0-9]{32}/gi,
    quicknode: /[a-zA-Z0-9]{32,}/gi,
  };

  // ─── State ─────────────────────────────────────────────────
  let findings = [];
  let alreadyNotified = false;

  function addFinding(type, detail, severity) {
    const f = { type, detail, severity, url: location.href, timestamp: Date.now() };
    findings.push(f);
    chrome.runtime.sendMessage({ action: 'finding', finding: f });
  }

  // ─── Chain Detection Helpers ───────────────────────────────

  function detectChain() {
    const chains = [];
    const html = document.documentElement.outerHTML.toLowerCase();

    if (html.includes('phantom') || html.includes('solana') || html.includes('solflare') || html.includes('helius') || html.includes('solscan')) chains.push('solana');
    if (html.includes('metamask') || html.includes('ethereum') || html.includes('web3') || html.includes('ethers') || html.includes('0x')) chains.push('evm');
    if (html.includes('tonconnect') || html.includes('tonkeeper') || html.includes('tonhub')) chains.push('ton');
    if (html.includes('sui wallet') || html.includes('suiet')) chains.push('sui');
    if (html.includes('aptos') || html.includes('petra wallet') || html.includes('martian')) chains.push('aptos');
    if (html.includes('keplr') || html.includes('cosmos') || html.includes('leap wallet')) chains.push('cosmos');
    if (html.includes('near wallet') || html.includes('nearprotocol')) chains.push('near');

    // Check window objects
    if (typeof window.phantom !== 'undefined' || typeof window.solana !== 'undefined') chains.push('solana');
    if (typeof window.ethereum !== 'undefined') chains.push('evm');
    if (typeof window.ton !== 'undefined') chains.push('ton');
    if (typeof window.aptos !== 'undefined') chains.push('aptos');
    if (typeof window.keplr !== 'undefined') chains.push('cosmos');

    return [...new Set(chains)]; // unique
  }

  // ─── Deteksi ───────────────────────────────────────────────

  // 1. Scan page HTML untuk indikator drainer
  function scanPage() {
    const html = document.documentElement.outerHTML.toLowerCase();

    // Cek known drainer wallet addresses (all chains)
    for (const chain of Object.keys(KNOWN_DRAINER_WALLETS)) {
      for (const wallet of KNOWN_DRAINER_WALLETS[chain]) {
        if (html.includes(wallet.toLowerCase())) {
          addFinding('wallet', `[${chain.toUpperCase()}] Known drainer wallet: ${wallet}`, 'critical');
        }
      }
    }

    // Cek known path/endpoint
    for (const path of KNOWN_DRAINER_PATHS) {
      if (html.includes(path)) {
        addFinding('path', `Drainer endpoint: ${path}`, 'high');
      }
    }

    // Cek API keys (Helius, Alchemy, Moralis, Infura, QuickNode)
    for (const [provider, regex] of Object.entries(API_KEY_REGEXES)) {
      const matches = html.match(regex);
      if (matches) {
        for (const key of [...new Set(matches)].slice(0, 3)) {
          addFinding('apikey', `[${provider.toUpperCase()}] RPC API key exposed: ${key.slice(0, 16)}...`, 'medium');
        }
      }
    }

    // Cek chain apa yang ditarget
    const chains = detectChain();
    if (chains.length > 0) {
      addFinding('chain', `Target chain(s): ${chains.join(', ')}`, 'info');
    }

    // Cek title/slogan — generic claim + wallet button = red flag
    const title = document.title.toLowerCase();
    const claimKeywords = ['claim', 'airdrop', 'reward', 'bonus', 'free', 'giveaway', 'mint', 'withdraw'];
    const hasClaimKW = claimKeywords.some(kw => title.includes(kw));
    const hasWalletBtn = !!document.querySelector('[class*="wallet"], [id*="wallet"], [class*="connect"], [class*="login"]');
    if (hasClaimKW && hasWalletBtn) {
      addFinding('social', `"${document.title}" + wallet button — klasik drainer pattern`, 'high');
    }

    // Cek EVM-specific: ERC-20 approve selector di page
    if (html.includes('095ea7b3') || html.includes('a22cb465') || html.includes('d505accf')) {
      addFinding('evm', 'EVM approve/setApprovalForAll selector terdeteksi — potensi token drain', 'critical');
    }
  }

  // 2. Monitor DOM untuk elemen mencurigakan
  function scanDOM() {
    // Scan all inline scripts
    const scripts = document.querySelectorAll('script');
    for (const script of scripts) {
      const text = script.textContent || '';
      for (const pattern of SUSPICIOUS_JS_PATTERNS) {
        if (text.toLowerCase().includes(pattern.toLowerCase())) {
          addFinding('jspattern', `Drainer code pattern: ${pattern}`, 'high');
          break;
        }
      }
    }

    // Cek hidden inputs / fake claim forms
    const forms = document.querySelectorAll('form');
    for (const form of forms) {
      const formHTML = form.innerHTML.toLowerCase();
      if ((formHTML.includes('claim') || formHTML.includes('approve') || formHTML.includes('sign')) && formHTML.includes('wallet')) {
        addFinding('form', 'Claim/Approve form + wallet — potensi drain', 'high');
      }
    }

    // Cek multiple wallet buttons (common in drainers pretending to be dapps)
    const walletBtns = document.querySelectorAll('[class*="wallet"], [id*="wallet-connect"], [class*="connect-wallet"]');
    if (walletBtns.length > 3) {
      addFinding('ui', `${walletBtns.length} wallet buttons — suspicious (drainer often has many)`, 'medium');
    }
  }

  // 3. Inject runtime monitor untuk intercept wallet API calls — MULTI CHAIN
  function injectWalletMonitor() {
    const script = document.createElement('script');
    script.textContent = `
      (function() {
        const drainerLog = (type, detail) => {
          window.postMessage({ type: '__DRAINER_GUARD__', detail: { type, ...detail } }, '*');
        };

        // ── Monitor FETCH ────────────────────────────────────
        const origFetch = window.fetch;
        window.fetch = function(...args) {
          const url = typeof args[0] === 'string' ? args[0] : (args[0]?.url || '');
          if (url.includes('plan.php') || url.includes('telemetry.php') || url.includes('drain.php') || url.includes('approve.php')) {
            drainerLog('fetch', { url, method: args[1]?.method || 'GET' });
          }
          return origFetch.apply(this, args);
        };

        // ── Monitor SOLANA (Phantom / Solflare) ─────────────
        function hookSolana(provider, name) {
          if (!provider || !provider.signAndSendTransaction || provider.__hooked) return;
          provider.__hooked = true;
          const orig = provider.signAndSendTransaction.bind(provider);
          provider.signAndSendTransaction = async function(...args) {
            try {
              const tx = args[0];
              if (tx && tx.instructions) {
                for (const ix of tx.instructions) {
                  const pid = ix.programId ? ix.programId.toString() : '';
                  // SPL Token approve: TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
                  // Token-2022: TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb
                  if (pid.includes('TokenkegQfe') || pid.includes('TokenzQdBNb')) {
                    drainerLog('approve_tx', { chain: 'solana', program: pid, provider: name });
                  }
                }
              }
            } catch(e) {}
            return orig.apply(this, args);
          };
        }

        let solInterval = setInterval(() => {
          hookSolana(window.solana, 'window.solana');
          hookSolana(window.phantom?.solana, 'phantom.solana');
          if (window.solana && window.phantom?.solana) clearInterval(solInterval);
        }, 500);

        // ── Monitor EVM (MetaMask, WalletConnect, dll) ──────
        function hookEVM(provider, name) {
          if (!provider || !provider.request || provider.__hooked) return;
          provider.__hooked = true;
          const origReq = provider.request.bind(provider);
          provider.request = async function(...args) {
            const params = args[0] || {};
            
            // eth_sendTransaction — user signing a tx
            if (params.method === 'eth_sendTransaction') {
              for (const tx of (params.params || [])) {
                if (tx.data) {
                  // ERC-20 approve selector: 0x095ea7b3
                  if (tx.data.startsWith('0x095ea7b3') || tx.data.startsWith('095ea7b3')) {
                    drainerLog('approve_tx', { chain: 'evm', method: 'erc20_approve', to: tx.to, provider: name });
                  }
                  // ERC-721/1155 setApprovalForAll: 0xa22cb465
                  if (tx.data.startsWith('0xa22cb465') || tx.data.startsWith('a22cb465')) {
                    drainerLog('approve_tx', { chain: 'evm', method: 'setApprovalForAll', to: tx.to, provider: name });
                  }
                  // ERC-2612 permit: 0xd505accf
                  if (tx.data.startsWith('0xd505accf') || tx.data.startsWith('d505accf')) {
                    drainerLog('approve_tx', { chain: 'evm', method: 'permit', to: tx.to, provider: name });
                  }
                }
              }
            }

            // eth_call with approve selector (drainer checking allowance)
            if (params.method === 'eth_call') {
              for (const call of (params.params || [])) {
                if (call.data && (call.data.includes('095ea7b3') || call.data.includes('dd62ed3e') || call.data.includes('a22cb465'))) {
                  drainerLog('approve_check', { chain: 'evm', data: call.data.slice(0, 20), provider: name });
                }
              }
            }

            return origReq.apply(this, args);
          };
        }

        let evmInterval = setInterval(() => {
          hookEVM(window.ethereum, 'window.ethereum');
          // Also check provider arrays
          if (window.ethereum?.providers) {
            window.ethereum.providers.forEach((p, i) => hookEVM(p, 'ethereum.providers[' + i + ']'));
          }
        }, 500);

        // ── Monitor TON (Tonkeeper / TonConnect) ────────────
        function hookTON(provider, name) {
          if (!provider || !provider.send || provider.__hooked) return;
          provider.__hooked = true;
          const origSend = provider.send.bind(provider);
          provider.send = async function(...args) {
            const method = args[0]?.method || args[0];
            if (method === 'ton_sendTransaction' || method === 'sendTransaction') {
              drainerLog('tx_request', { chain: 'ton', method, provider: name });
            }
            return origSend.apply(this, args);
          };
        }

        let tonInterval = setInterval(() => {
          hookTON(window.ton, 'window.ton');
          hookTON(window.tonkeeper, 'window.tonkeeper');
        }, 500);
      })();
    `;
    document.documentElement.appendChild(script);
    script.remove();
  }

  // 4. Listen for postMessage dari injected script — MULTI CHAIN
  window.addEventListener('message', function(event) {
    if (event.data && event.data.type === '__DRAINER_GUARD__') {
      const d = event.data.detail;

      if (d.type === 'fetch') {
        if (d.url.includes('plan.php')) addFinding('runtime', `Fetch drainer API: ${d.url}`, 'critical');
        else if (d.url.includes('telemetry.php')) addFinding('runtime', `Kirim telemetry ke drainer server`, 'critical');
        else addFinding('runtime', `Fetch endpoint mencurigakan: ${d.url}`, 'high');
      }

      if (d.type === 'approve_tx') {
        const chain = d.chain || 'unknown';
        const method = d.method || 'approve';
        addFinding('approve', `[${chain.toUpperCase()}] ${method} terdeteksi! Program: ${d.program || d.to || '?'}`, 'critical');
      }

      if (d.type === 'approve_check') {
        addFinding('approve', `[${d.chain.toUpperCase()}] Drainer mengecek allowance token anda`, 'high');
      }

      if (d.type === 'tx_request') {
        addFinding('runtime', `[${d.chain.toUpperCase()}] Minta tanda tangan transaksi via ${d.provider}`, 'critical');
      }
    }
  });

  // ─── Eksekusi ──────────────────────────────────────────────

  // Tunggu page selesai load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(() => {
        scanPage();
        scanDOM();
        injectWalletMonitor();
        showWarningIfNeeded();
      }, 1000);
    });
  } else {
    setTimeout(() => {
      scanPage();
      scanDOM();
      injectWalletMonitor();
      showWarningIfNeeded();
    }, 1000);
  }

  // Re-scan periodically for dynamic content
  setInterval(scanDOM, 3000);

  // ─── UI Warning ────────────────────────────────────────────
  function showWarningIfNeeded() {
    const critical = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
    if (critical.length === 0) return;
    if (alreadyNotified) return;
    alreadyNotified = true;

    const overlay = document.createElement('div');
    overlay.id = 'drainer-guard-overlay';
    overlay.innerHTML = `
      <div style="position:fixed;top:0;left:0;right:0;z-index:9999999;background:#dc2626;color:white;padding:12px 20px;font-family:Arial,sans-serif;font-size:14px;box-shadow:0 4px 12px rgba(0,0,0,0.3);display:flex;align-items:center;justify-content:space-between;">
        <div>
          <strong>⚠️ DRAINER GUARD</strong> — Situs ini terdeteksi berbahaya!
          <span style="display:block;font-size:12px;margin-top:2px;opacity:0.9;">
            ${critical.map(f => `🔴 ${f.detail}`).join('<br>')}
          </span>
        </div>
        <button id="drainer-guard-close" style="background:rgba(255,255,255,0.2);border:1px solid rgba(255,255,255,0.4);color:white;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:12px;white-space:nowrap;margin-left:12px;">Tutup</button>
      </div>
    `;
    document.body.appendChild(overlay);
    document.getElementById('drainer-guard-close').onclick = () => overlay.remove();

    // Kirim notifikasi
    chrome.runtime.sendMessage({
      action: 'alert',
      alert: {
        title: '⚠️ Situs Drainer Terdeteksi!',
        message: `Ditemukan ${critical.length} indikasi drainer di ${location.hostname}`,
        findings: critical
      }
    });
  }

  // ─── Kirim hasil ke popup via storage ──────────────────────
  chrome.storage.local.set({
    ['scan_' + location.hostname]: {
      findings,
      timestamp: Date.now(),
      url: location.href
    }
  });

  console.log('[Drainer Guard] Scan selesai:', findings.length, 'finding(s)');
})();
