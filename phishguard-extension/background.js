const PHISHGUARD_API = 'http://localhost:8080/api/scan';
const cache = new Map();

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const url = details.url;

  if (url.startsWith('chrome://') ||
      url.startsWith('chrome-extension://') ||
      url.startsWith('about:') ||
      url.includes('localhost')) return;

  try {
    if (cache.has(url)) {
      const c = cache.get(url);
      if (c.decision === 'HIGH_RISK')
        chrome.tabs.update(details.tabId, {
          url: chrome.runtime.getURL('blocked.html') +
            '?url=' + encodeURIComponent(url) + '&score=' + c.score
        });
      return;
    }

    const r = await fetch(
      `${PHISHGUARD_API}?url=${encodeURIComponent(url)}`,
      { signal: AbortSignal.timeout(3000) }
    );
    if (!r.ok) return;

    const data = await r.json();
    cache.set(url, { decision: data.decision, score: data.score });
    setTimeout(() => cache.delete(url), 600000);

    if (data.decision === 'HIGH_RISK') {
      chrome.tabs.update(details.tabId, {
        url: chrome.runtime.getURL('blocked.html') +
          '?url=' + encodeURIComponent(url) + '&score=' + (data.score || 0)
      });
    }
  } catch (e) {}
});

// ── Gmail Warning Banner ───────────────────────────────────────────
// Inject a threat alert banner directly into Gmail when threats are present
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' &&
        tab.url && tab.url.includes('mail.google.com')) {
        chrome.scripting.executeScript({
            target: { tabId },
            func: injectGmailWarning
        });
    }
});

function injectGmailWarning() {
    fetch('http://localhost:8080/api/incidents?limit=5')
    .then(r => r.json())
    .then(data => {
        const threats = data.filter(i => i.decision === 'HIGH_RISK');
        if (threats.length === 0) {
            // Clear any existing banner if inbox is now clean
            document.getElementById('phishguard-banner')?.remove();
            return;
        }

        // Remove existing banner to avoid duplicates
        document.getElementById('phishguard-banner')?.remove();

        const banner = document.createElement('div');
        banner.id = 'phishguard-banner';
        banner.style.cssText = [
            'position:fixed', 'top:0', 'left:0', 'right:0', 'z-index:99999',
            'background:linear-gradient(135deg,#3c1414,#2d0f0f)',
            'border-bottom:2px solid #f85149',
            'padding:10px 20px',
            'display:flex', 'align-items:center', 'gap:12px',
            'font-family:system-ui,sans-serif', 'font-size:13px', 'color:#fff',
            'box-shadow:0 4px 20px rgba(248,81,73,0.35)',
            'animation:pgSlideIn 0.4s ease'
        ].join(';');

        // Inject keyframe animation
        if (!document.getElementById('phishguard-style')) {
            const s = document.createElement('style');
            s.id = 'phishguard-style';
            s.textContent = '@keyframes pgSlideIn{from{transform:translateY(-100%)}to{transform:translateY(0)}}';
            document.head.appendChild(s);
        }

        const latestUrl = threats[0].url || 'Unknown URL';
        const truncated = latestUrl.length > 60 ? latestUrl.slice(0, 57) + '...' : latestUrl;

        banner.innerHTML = `
            <span style="font-size:20px;flex-shrink:0">🚨</span>
            <div style="flex:1">
                <strong>PhishGuard Alert:</strong>
                ${threats.length} HIGH RISK phishing threat(s) detected in your inbox.
                <div style="font-size:11px;opacity:0.7;margin-top:2px">Latest: ${truncated}</div>
            </div>
            <a href="http://localhost:8080" target="_blank"
               style="color:#f85149;text-decoration:underline;font-size:12px;flex-shrink:0">
                View Dashboard →
            </a>
            <button id="phishguard-close-btn"
                    style="background:rgba(255,255,255,0.1);border:1px solid rgba(255,255,255,0.2);color:#fff;cursor:pointer;font-size:14px;padding:4px 8px;border-radius:4px;margin-left:8px;flex-shrink:0">✕</button>
        `;

        document.body.prepend(banner);

        // CSP-compliant event listener
        document.getElementById('phishguard-close-btn').addEventListener('click', () => {
            document.getElementById('phishguard-banner').remove();
        });
    })
    .catch(() => {});
}

// ── System-Wide Tab Monitoring ───────────────────────────────────────────
// Intercept EVERY URL opened in Chrome (WhatsApp, YouTube, Telegram, etc.)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url) {
        // Skip internal/chrome pages
        if (tab.url.startsWith('http')) {
            // Send to PhishGuard for scanning
            fetch('http://localhost:8080/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    url: tab.url,
                    source: 'BROWSER_TAB',
                    sender: 'browser'
                })
            })
            .then(r => r.json())
            .then(result => {
                if (result.decision === 'HIGH_RISK') {
                    // Block the tab immediately
                    chrome.tabs.update(tabId, {
                        url: chrome.runtime.getURL('blocked.html') 
                             + '?url=' + encodeURIComponent(tab.url)
                             + '&score=' + (result.score || 1.0)
                    });
                }
            })
            .catch(() => {});
        }
    }
});
