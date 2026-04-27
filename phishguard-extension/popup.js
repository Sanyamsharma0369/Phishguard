const API = 'http://localhost:8080';

// ── Timeout-safe fetch ────────────────────────────────────────────────────────
async function fetchWithTimeout(url, options = {}, timeout = 4000) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
        const res = await fetch(url, { ...options, signal: controller.signal });
        clearTimeout(timer);
        return res;
    } catch (e) {
        clearTimeout(timer);
        throw e;
    }
}

// ── Button event listeners (NO onclick in HTML) ───────────────────────────────
document.getElementById('scan-btn').addEventListener('click', scanCurrentTab);
document.getElementById('dashboard-btn').addEventListener('click', openDashboard);

function openDashboard() {
    chrome.tabs.create({ url: API });
}

// ── Scan current tab ──────────────────────────────────────────────────────────
async function scanCurrentTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) return;

    const url = tab.url;
    document.getElementById('tab-url').textContent =
        url.length > 45 ? url.substring(0, 45) + '...' : url;
    document.getElementById('tab-status-label').className =
        'tab-status-label status-loading';
    document.getElementById('tab-status-label').textContent = '⏳ Scanning...';
    document.getElementById('scanning-text').style.display = 'inline';

    const btn = document.getElementById('scan-btn');
    btn.textContent = '⏳ Scanning...';
    btn.disabled = true;

    try {
        const res = await fetchWithTimeout(`${API}/api/scan/quick`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, source: 'EXTENSION_POPUP' })
        }, 4000);
        const data = await res.json();
        displayScanResult(data, url);
    } catch (e) {
        document.getElementById('tab-status-label').className =
            'tab-status-label status-warn';
        document.getElementById('tab-status-label').textContent = '⚠️ Backend Offline';
        document.getElementById('scanning-text').style.display = 'none';
    } finally {
        btn.textContent = '🔍 Scan Page';
        btn.disabled = false;
    }
}

// ── Display scan result ───────────────────────────────────────────────────────
function displayScanResult(data, url) {
    const score    = data.riskScore || 0;
    const decision = data.decision  || 'SAFE';

    document.getElementById('scanning-text').style.display = 'none';
    document.getElementById('tab-url').textContent =
        url.length > 45 ? url.substring(0, 45) + '...' : url;
    document.getElementById('risk-score-val').textContent = score.toFixed(4);

    const bar = document.getElementById('risk-bar');
    bar.style.width = (score * 100) + '%';

    const label = document.getElementById('tab-status-label');
    if (decision === 'HIGH_RISK') {
        label.className = 'tab-status-label status-danger';
        label.textContent = '🚨 HIGH RISK';
        bar.style.background = '#f85149';
    } else if (decision === 'SUSPICIOUS') {
        label.className = 'tab-status-label status-warn';
        label.textContent = '⚠️ SUSPICIOUS';
        bar.style.background = '#d29922';
    } else {
        label.className = 'tab-status-label status-safe';
        label.textContent = '✅ SAFE';
        bar.style.background = '#3fb950';
    }
}

// ── Load today's stats ────────────────────────────────────────────────────────
async function loadStats() {
    try {
        const data = await fetchWithTimeout(`${API}/api/stats`, {}, 3000)
            .then(r => r.json());
        document.getElementById('stat-blocked').textContent    = data.blocked     || 0;
        document.getElementById('stat-suspicious').textContent = data.suspicious  || 0;
        document.getElementById('stat-safe').textContent       = data.safe        || 0;
        document.getElementById('sys-blocked-total').textContent =
            (data.blocked || 0) + ' total';
    } catch (e) {}
}

// ── Load recent threats ───────────────────────────────────────────────────────
async function loadRecentThreats() {
    try {
        const data = await fetchWithTimeout(
            `${API}/api/incidents?limit=5`, {}, 3000).then(r => r.json());
        const threats = data.filter(i =>
            i.decision === 'HIGH_RISK' || i.decision === 'SUSPICIOUS');

        const list = document.getElementById('threat-list');
        if (threats.length === 0) {
            list.innerHTML = '<div class="no-threats">✅ No recent threats</div>';
            return;
        }
        list.innerHTML = threats.slice(0, 3).map(t => {
            let domain = t.url || '';
            try { domain = new URL(t.url).hostname; } catch(e) {}
            const isHigh = t.decision === 'HIGH_RISK';
            return `<div class="threat-item">
                <span class="threat-url">${domain}</span>
                <span class="threat-badge ${isHigh ? '' : 'warn'}">
                    ${isHigh ? 'HIGH RISK' : 'SUSPICIOUS'}
                </span>
            </div>`;
        }).join('');
    } catch(e) {}
}

// ── Check system health ───────────────────────────────────────────────────────
async function checkSystem() {
    try {
        const health = await fetchWithTimeout(
            `${API}/api/health/layers`, {}, 3000).then(r => r.json());

        document.getElementById('sys-api').textContent = '✅ Running';
        document.getElementById('sys-api').style.color = '#3fb950';

        const cnn = health.flask_cnn || '';
        document.getElementById('sys-cnn').textContent =
            cnn.includes('✅') ? '✅ Running' : '❌ Offline';
        document.getElementById('sys-cnn').style.color =
            cnn.includes('✅') ? '#3fb950' : '#f85149';
    } catch (e) {
        document.getElementById('sys-api').textContent = '❌ Offline';
        document.getElementById('sys-api').style.color = '#f85149';
        document.getElementById('sys-cnn').textContent = '❌ Offline';
        document.getElementById('sys-cnn').style.color = '#f85149';

        const badge = document.getElementById('main-status-badge');
        badge.style.background    = 'rgba(248,81,73,0.15)';
        badge.style.color         = '#f85149';
        badge.style.borderColor   = 'rgba(248,81,73,0.3)';
        badge.innerHTML =
            '<div style="width:7px;height:7px;border-radius:50%;background:#f85149"></div> OFFLINE';
    }
}

// ── Auto-scan on popup open ───────────────────────────────────────────────────
async function autoScanCurrentTab() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || !tab.url) return;

    const url = tab.url;

    // Skip chrome internal pages
    if (url.startsWith('chrome://') || url.startsWith('chrome-extension://')
        || url.startsWith('about:') || url.startsWith('edge://')) {
        document.getElementById('tab-status-label').className =
            'tab-status-label status-safe';
        document.getElementById('tab-status-label').textContent = '— Browser Page';
        document.getElementById('scanning-text').style.display = 'none';
        document.getElementById('tab-url').textContent =
            'Chrome internal page (not scanned)';
        return;
    }

    document.getElementById('tab-url').textContent =
        url.length > 45 ? url.substring(0, 45) + '...' : url;

    try {
        const res = await fetchWithTimeout(`${API}/api/scan/quick`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, source: 'EXTENSION_POPUP_AUTO' })
        }, 4000);
        const data = await res.json();
        displayScanResult(data, url);
    } catch(e) {
        document.getElementById('tab-status-label').className =
            'tab-status-label status-warn';
        document.getElementById('tab-status-label').textContent = '⚠️ Backend Offline';
        document.getElementById('scanning-text').style.display = 'none';
    }
}

// ── Init — runs when popup opens ──────────────────────────────────────────────
checkSystem();
loadStats();
loadRecentThreats();
autoScanCurrentTab();
