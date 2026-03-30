let pieChart;

document.addEventListener('DOMContentLoaded', () => {
    initChart();
    fetchDashboardData();
    setupWebSocket();
    setInterval(fetchDashboardData, 5000);
    
    // Live clock
    setInterval(() => {
        document.getElementById('clock').textContent = new Date().toLocaleTimeString();
    }, 1000);
});

function initChart() {
    const ctx = document.getElementById('pieChart').getContext('2d');
    
    // Tooltip and Legend colors for dark mode
    Chart.defaults.color = '#9ca3af';
    
    pieChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Safe', 'Suspicious', 'High Risk'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '70%',
            plugins: {
                legend: { position: 'right' }
            }
        }
    });
}

async function fetchDashboardData() {
    try {
        const res = await fetch('/api/dashboard');
        const data = await res.json();
        
        // Update Stats
        document.getElementById('stat-total').innerText = data.totalEmails;
        document.getElementById('stat-threats').innerText = data.threats;
        document.getElementById('stat-blocked').innerText = data.blocked;
        document.getElementById('stat-avg').innerText = (data.avgRisk * 100).toFixed(1);
        
        // Update Chart
        if (pieChart) {
            pieChart.data.datasets[0].data = [
                data.breakdown.safe || 0,
                data.breakdown.suspicious || 0,
                data.breakdown.highRisk || 0
            ];
            pieChart.update();
        }
        
        // Update Table
        updateTable(data.recent);
        
    } catch (e) {
        console.error('Failed to fetch dashboard data:', e);
    }
}

function updateTable(incidents) {
    const tbody = document.getElementById('incidents-body');
    tbody.innerHTML = '';
    
    incidents.forEach(inc => {
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-gray-800 transition-colors group';
        
        let badgeClass = 'badge-safe';
        if (inc.decision === 'HIGH_RISK') badgeClass = 'badge-risk';
        else if (inc.decision === 'SUSPICIOUS') badgeClass = 'badge-suspicious';
        
        const urlDisplay = inc.url.length > 50 ? inc.url.substring(0, 47) + '...' : inc.url;
        
        tr.innerHTML = `
            <td class="px-6 py-4 text-gray-300 group-hover:text-white">${inc.sender || '—'}</td>
            <td class="px-6 py-4 text-cyan-500 font-mono text-xs" title="${inc.url}">${urlDisplay}</td>
            <td class="px-6 py-4 font-semibold text-gray-300">${parseFloat(inc.score).toFixed(3)}</td>
            <td class="px-6 py-4">
                <span class="status-badge ${badgeClass}">${inc.decision.replace('_', ' ')}</span>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function setupWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws`;
    
    const ws = new WebSocket(wsUrl);
    const statusDot = document.querySelector('.pulse-dot');
    const statusText = document.getElementById('ws-status');
    
    ws.onopen = () => {
        statusDot.className = 'w-2 h-2 rounded-full bg-emerald-500 mr-2 pulse-dot';
        statusText.innerHTML = statusDot.outerHTML + ' Live Connected';
    };
    
    ws.onclose = () => {
        statusDot.className = 'w-2 h-2 rounded-full bg-red-500 mr-2';
        statusText.innerHTML = statusDot.outerHTML + ' Offline (Reconnecting...)';
        statusDot.style.animation = 'none';
        setTimeout(setupWebSocket, 3000);
    };
    
    ws.onmessage = (event) => {
        if (event.data === 'pong') return;
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'NEW_INCIDENT') {
                fetchDashboardData();
            }
        } catch (e) {}
    };
    
    // Heartbeat
    setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) {
            ws.send('ping');
        }
    }, 30000);
}
