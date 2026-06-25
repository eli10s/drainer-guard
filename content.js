// ============================================================
// Drainer Guard — Content Script
// Detects wallet drainer patterns across MULTI-CHAIN (Solana, EVM, TON, etc.)
// ============================================================

(async function() {
  // ─── Configuration ──────────────────────────────────────────
  const KNOWN_DRAINER_WALLETS = {
    solana: [
      'GK4Note9oHQY84JEtBFBRb6rBS8mSqryFQffdrWv67cR',
    ],
    evm: [
      // Add known EVM drainer addresses here (from public databases)
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

  // Drainer code patterns — multi-chain
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

  // Regex patterns for RPC API key detection
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

    return [...new Set(chains)];
  }

  // ─── Detection ──────────────────────────────────────────────

  // 1. Scan page HTML for drainer indicators
  function scanPage() {
    const html = document.documentElement.outerHTML.toLowerCase();

    // Check known drainer wallet addresses (all chains)
    for (const chain of Object.keys(KNOWN_DRAINER_WALLETS)) {
      for (const wallet of KNOWN_DRAINER_WALLETS[chain]) {
        if (html.includes(wallet.toLowerCase())) {
          addFinding('wallet', `[${chain.toUpperCase()}] Known drainer wallet: ${wallet}`, 'critical');
        }
      }
    }

    // Check known drainer paths/endpoints
    for (const path of KNOWN_DRAINER_PATHS) {
      if (html.includes(path)) {
        addFinding('path', `Drainer endpoint: ${path}`, 'high');
      }
    }

    // Check exposed API keys (Helius, Alchemy, Moralis, Infura, QuickNode)
    for (const [provider, regex] of Object.entries(API_KEY_REGEXES)) {
      const matches = html.match(regex);
      if (matches) {
        for (const key of [...new Set(matches)].slice(0, 3)) {
          addFinding('apikey', `[${provider.toUpperCase()}] RPC API key exposed: ${key.slice(0, 16)}...`, 'medium');
        }
      }
    }

    // Detect which chains are being targeted
    const chains = detectChain();
    if (chains.length > 0) {
      addFinding('chain', `Target chain(s): ${chains.join(', ')}`, 'info');
    }

    // Check title + wallet button — classic drainer pattern
    const title = document.title.toLowerCase();
    const claimKeywords = ['claim', 'airdrop', 'reward', 'bonus', 'free', 'giveaway', 'mint', 'withdraw'];
    const hasClaimKW = claimKeywords.some(kw => title.includes(kw));
    const hasWalletBtn = !!document.querySelector('[class*="wallet"], [id*="wallet"], [class*="connect"], [class*="login"]');
    if (hasClaimKW && hasWalletBtn) {
      addFinding('social', `"${document.title}" + wallet button — classic drainer pattern`, 'high');
    }

    // EVM-specific: ERC-20 approve selectors in page
    if (html.includes('095ea7b3') || html.includes('a22cb465') || html.includes('d505accf')) {
      addFinding('evm', 'EVM approve/setApprovalForAll selector detected — potential token drain', 'critical');
    }
  }

  // 2. Monitor DOM for suspicious elements
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

    // Check hidden inputs / fake claim forms
    const forms = document.querySelectorAll('form');
    for (const form of forms) {
      const formHTML = form.innerHTML.toLowerCase();
      if ((formHTML.includes('claim') || formHTML.includes('approve') || formHTML.includes('sign')) && formHTML.includes('wallet')) {
        addFinding('form', 'Claim/Approve form + wallet — potential drain', 'high');
      }
    }

    // Check for multiple wallet buttons (common in drainers pretending to be dapps)
    const walletBtns = document.querySelectorAll('[class*="wallet"], [id*="wallet-connect"], [class*="connect-wallet"]');
    if (walletBtns.length > 3) {
      addFinding('ui', `${walletBtns.length} wallet buttons — suspicious (drainers often have many)`, 'medium');
    }
  }

  // 3. Inject runtime monitor via external file (bypasses page CSP)
  function injectWalletMonitor() {
    const script = document.createElement('script');
    script.src = chrome.runtime.getURL('injected.js');
    script.onload = () => script.remove();
    document.documentElement.appendChild(script);
  }

  // 4. Listen for postMessage from injected script — MULTI CHAIN
  window.addEventListener('message', function(event) {
    if (event.data && event.data.type === '__DRAINER_GUARD__') {
      const d = event.data.detail;

      if (d.type === 'fetch') {
        if (d.url.includes('plan.php')) addFinding('runtime', `Fetch drainer API: ${d.url}`, 'critical');
        else if (d.url.includes('telemetry.php')) addFinding('runtime', `Sending telemetry to drainer server`, 'critical');
        else addFinding('runtime', `Suspicious endpoint fetch: ${d.url}`, 'high');
      }

      if (d.type === 'approve_tx') {
        const chain = d.chain || 'unknown';
        const method = d.method || 'approve';
        addFinding('approve', `[${chain.toUpperCase()}] ${method} detected! Program: ${d.program || d.to || '?'}`, 'critical');
      }

      if (d.type === 'approve_check') {
        addFinding('approve', `[${d.chain.toUpperCase()}] Drainer checking your token allowance`, 'high');
      }

      if (d.type === 'tx_request') {
        addFinding('runtime', `[${d.chain.toUpperCase()}] Requesting transaction signature via ${d.provider}`, 'critical');
      }
    }
  });

  // ─── Execute ───────────────────────────────────────────────

  // Wait for page load
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(() => {
        scanPage();
        scanDOM();
        injectWalletMonitor();
        sendNotificationIfNeeded();
      }, 1000);
    });
  } else {
    setTimeout(() => {
      scanPage();
      scanDOM();
      injectWalletMonitor();
      sendNotificationIfNeeded();
    }, 1000);
  }

  // Re-scan periodically for dynamic content
  setInterval(scanDOM, 3000);

  // ─── Notification (no page overlay) ────────────────────────
  function sendNotificationIfNeeded() {
    const critical = findings.filter(f => f.severity === 'critical' || f.severity === 'high');
    if (critical.length === 0) return;
    if (alreadyNotified) return;
    alreadyNotified = true;

    // Chrome notification only — no intrusive overlay on the page
    chrome.runtime.sendMessage({
      action: 'alert',
      alert: {
        title: '⚠️ Drainer Site Detected!',
        message: `Found ${critical.length} drainer indicators on ${location.hostname}`,
        findings: critical
      }
    });
  }

  // ─── Send results to popup via storage ─────────────────────
  chrome.storage.local.set({
    ['scan_' + location.hostname]: {
      findings,
      timestamp: Date.now(),
      url: location.href
    }
  });

  console.log('[Drainer Guard] Scan complete:', findings.length, 'finding(s)');
})();
