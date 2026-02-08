/**
 * WP-Hunter Dashboard Application
 * 
 * Handles scan configuration, WebSocket communication, and results display.
 */

class WPHunterDashboard {
    constructor() {
        this.ws = null;
        this.currentSessionId = null;
        this.results = [];

        this.init();
    }

    init() {
        this.bindEvents();
        this.loadHistory();
    }

    bindEvents() {
        // Start scan button
        document.getElementById('startScanBtn').addEventListener('click', () => this.startScan());

        // Sort results
        document.getElementById('sortResults').addEventListener('change', (e) => this.sortResults(e.target.value));

        // Export button
        document.getElementById('exportBtn').addEventListener('click', () => this.exportResults());
    }

    getConfig() {
        return {
            pages: parseInt(document.getElementById('pages').value) || 5,
            limit: parseInt(document.getElementById('limit').value) || 0,
            min_installs: parseInt(document.getElementById('minInstalls').value) || 1000,
            max_installs: parseInt(document.getElementById('maxInstalls').value) || 0,
            sort: document.getElementById('sortBy').value,
            smart: document.getElementById('smartFilter').checked,
            abandoned: document.getElementById('abandonedFilter').checked,
            user_facing: document.getElementById('userFacingFilter').checked,
            deep_analysis: document.getElementById('deepAnalysis').checked,
            min_days: parseInt(document.getElementById('minDays').value) || 0,
            max_days: parseInt(document.getElementById('maxDays').value) || 0,
        };
    }

    async startScan() {
        const config = this.getConfig();
        const btn = document.getElementById('startScanBtn');

        btn.disabled = true;
        btn.innerHTML = '<span class="btn-icon">⏳</span> Starting...';

        try {
            const response = await fetch('/api/scans', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(config)
            });

            const data = await response.json();
            this.currentSessionId = data.session_id;

            // Reset results
            this.results = [];
            this.updateResultsTable();
            this.updateStats({ total: 0, highRisk: 0, abandoned: 0 });

            // Show progress
            document.getElementById('progressContainer').style.display = 'block';
            document.getElementById('emptyState').style.display = 'none';
            document.getElementById('dataGrid').style.display = 'block';

            // Connect WebSocket
            this.connectWebSocket(data.session_id);

            // Update status
            this.updateStatus('RUNNING', true);

            btn.innerHTML = '<span class="btn-icon">⏹</span> Stop Scan';
            btn.disabled = false;
            btn.onclick = () => this.stopScan();

        } catch (error) {
            console.error('Failed to start scan:', error);
            btn.disabled = false;
            btn.innerHTML = '<span class="btn-icon">▶</span> Start Scan';
            alert('Failed to start scan: ' + error.message);
        }
    }

    async stopScan() {
        if (!this.currentSessionId) return;

        try {
            await fetch(`/api/scans/${this.currentSessionId}/stop`, { method: 'POST' });
            this.onScanComplete({ stopped: true });
        } catch (error) {
            console.error('Failed to stop scan:', error);
        }
    }

    connectWebSocket(sessionId) {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/scans/${sessionId}`;

        this.ws = new WebSocket(wsUrl);

        this.ws.onmessage = (event) => {
            const message = JSON.parse(event.data);
            this.handleWebSocketMessage(message);
        };

        this.ws.onclose = () => {
            console.log('WebSocket closed');
        };

        this.ws.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }

    handleWebSocketMessage(message) {
        switch (message.type) {
            case 'progress':
                this.updateProgress(message.percent, message.current, message.total);
                break;

            case 'result':
                this.addResult(message.data);
                document.getElementById('foundValue').textContent = message.found_count;
                break;

            case 'complete':
                this.onScanComplete(message);
                break;

            case 'error':
                this.onScanError(message.message);
                break;
        }
    }

    updateProgress(percent, current, total) {
        document.getElementById('progressBar').style.width = `${percent}%`;
        document.getElementById('progressText').textContent = `Page ${current} of ${total}`;
        document.getElementById('progressValue').textContent = `${percent}%`;
    }

    addResult(result) {
        this.results.push(result);
        this.appendResultRow(result);
        this.updateStats({
            total: this.results.length,
            highRisk: this.results.filter(r => r.score >= 50).length,
            abandoned: this.results.filter(r => r.days_since_update > 730).length
        });
    }

    appendResultRow(result) {
        const tbody = document.getElementById('resultsBody');
        const row = document.createElement('tr');

        const scoreClass = result.score >= 80 ? 'critical' : (result.score >= 50 ? 'high' : 'low');
        const riskTags = (result.risk_tags || []).slice(0, 3).map(t =>
            `<span class="risk-tag">${this.escapeHtml(t)}</span>`
        ).join('');

        row.innerHTML = `
            <td>
                <div class="plugin-name">${this.escapeHtml(result.name)}</div>
                <div class="plugin-slug">${result.slug}</div>
            </td>
            <td><span class="score-badge ${scoreClass}">${result.score}</span></td>
            <td>${this.formatNumber(result.installations)}+</td>
            <td>${result.days_since_update} days</td>
            <td>${riskTags || '-'}</td>
            <td>
                <button class="action-btn" onclick="dashboard.viewPlugin('${result.slug}')">View</button>
                <button class="action-btn" onclick="dashboard.downloadPlugin('${result.slug}', '${result.download_link}')">⬇</button>
            </td>
        `;

        tbody.appendChild(row);
    }

    updateResultsTable() {
        const tbody = document.getElementById('resultsBody');
        tbody.innerHTML = '';
        this.results.forEach(result => this.appendResultRow(result));
    }

    updateStats(stats) {
        document.getElementById('totalFound').textContent = stats.total;
        document.getElementById('highRisk').textContent = stats.highRisk;
        document.getElementById('abandoned').textContent = stats.abandoned;
    }

    updateStatus(status, running = false) {
        const el = document.getElementById('statusValue');
        el.textContent = status;
        el.className = 'value' + (running ? ' running' : '');
    }

    onScanComplete(data) {
        document.getElementById('progressContainer').style.display = 'none';
        this.updateStatus('COMPLETED');

        const btn = document.getElementById('startScanBtn');
        btn.innerHTML = '<span class="btn-icon">▶</span> Start Scan';
        btn.disabled = false;
        btn.onclick = () => this.startScan();

        // Refresh history
        this.loadHistory();

        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }

    onScanError(message) {
        this.updateStatus('FAILED');
        alert('Scan error: ' + message);
        this.onScanComplete({});
    }

    async loadHistory() {
        try {
            const response = await fetch('/api/scans?limit=10');
            const data = await response.json();
            this.renderHistory(data.sessions);
        } catch (error) {
            console.error('Failed to load history:', error);
        }
    }

    renderHistory(sessions) {
        const list = document.getElementById('historyList');
        list.innerHTML = '';

        if (!sessions.length) {
            list.innerHTML = '<div class="empty-history">No past scans</div>';
            return;
        }

        sessions.forEach(session => {
            const item = document.createElement('div');
            item.className = 'history-item' + (session.id === this.currentSessionId ? ' active' : '');

            const date = new Date(session.created_at).toLocaleString();
            const statusClass = session.status === 'completed' ? 'completed' :
                (session.status === 'failed' ? 'failed' : '');

            item.innerHTML = `
                <div class="date">${date}</div>
                <div class="count">${session.total_found} plugins found</div>
                <span class="status-tag ${statusClass}">${this.escapeHtml(session.status).toUpperCase()}</span>
            `;

            item.addEventListener('click', () => this.loadSession(session.id));
            list.appendChild(item);
        });
    }

    async loadSession(sessionId) {
        try {
            const response = await fetch(`/api/scans/${sessionId}/results`);
            const data = await response.json();

            this.currentSessionId = sessionId;
            this.results = data.results;

            document.getElementById('emptyState').style.display = 'none';
            document.getElementById('dataGrid').style.display = 'block';

            this.updateResultsTable();
            this.updateStats({
                total: this.results.length,
                highRisk: this.results.filter(r => r.score >= 50).length,
                abandoned: this.results.filter(r => r.days_since_update > 730).length
            });

            // Highlight active session in history
            document.querySelectorAll('.history-item').forEach(el => el.classList.remove('active'));

        } catch (error) {
            console.error('Failed to load session:', error);
        }
    }

    sortResults(sortKey) {
        const [field, order] = sortKey.split('-');

        this.results.sort((a, b) => {
            let aVal, bVal;

            switch (field) {
                case 'score':
                    aVal = a.score;
                    bVal = b.score;
                    break;
                case 'installations':
                    aVal = a.installations;
                    bVal = b.installations;
                    break;
                case 'days':
                    aVal = a.days_since_update;
                    bVal = b.days_since_update;
                    break;
                default:
                    aVal = a.score;
                    bVal = b.score;
            }

            return order === 'asc' ? aVal - bVal : bVal - aVal;
        });

        this.updateResultsTable();
    }

    async downloadPlugin(slug, downloadUrl) {
        try {
            const response = await fetch('/api/plugins/download', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ slug, download_url: downloadUrl })
            });

            const data = await response.json();
            alert(`Downloaded ${slug} to ${data.path}`);
        } catch (error) {
            alert('Download failed: ' + error.message);
        }
    }

    viewPlugin(slug) {
        window.open(`https://wordpress.org/plugins/${slug}/`, '_blank');
    }

    exportResults() {
        if (!this.results.length) {
            alert('No results to export');
            return;
        }

        const blob = new Blob([JSON.stringify(this.results, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `wp-hunter-results-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }

    formatNumber(num) {
        if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
        if (num >= 1000) return (num / 1000).toFixed(0) + 'K';
        return num.toString();
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize dashboard
const dashboard = new WPHunterDashboard();
