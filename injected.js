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
      
      if (params.method === 'eth_sendTransaction') {
        for (const tx of (params.params || [])) {
          if (tx.data) {
            if (tx.data.startsWith('0x095ea7b3') || tx.data.startsWith('095ea7b3')) {
              drainerLog('approve_tx', { chain: 'evm', method: 'erc20_approve', to: tx.to, provider: name });
            }
            if (tx.data.startsWith('0xa22cb465') || tx.data.startsWith('a22cb465')) {
              drainerLog('approve_tx', { chain: 'evm', method: 'setApprovalForAll', to: tx.to, provider: name });
            }
            if (tx.data.startsWith('0xd505accf') || tx.data.startsWith('d505accf')) {
              drainerLog('approve_tx', { chain: 'evm', method: 'permit', to: tx.to, provider: name });
            }
          }
        }
      }

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
