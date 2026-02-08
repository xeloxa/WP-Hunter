// Global state
let currentScanId = null;
let socket = null;
let terminalLines = [];
window.currentScanResults = []; // Store results for modal access

function escapeHtml(text) {
    if (text === null || text === undefined) return '';
    return String(text)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}


document.addEventListener('DOMContentLoaded', () => {
    // Server Address Badge - Update immediately
    const addressBadge = document.getElementById('server-address');
    if (addressBadge) {
        const host = window.location.host;
        addressBadge.textContent = host;
        
        addressBadge.addEventListener('click', () => {
            if (navigator.clipboard) {
                navigator.clipboard.writeText(host).then(() => {
                    const original = addressBadge.textContent;
                    addressBadge.textContent = 'COPIED!';
                    addressBadge.style.color = '#00FF9D';
                    addressBadge.style.borderColor = '#00FF9D';
                    
                    setTimeout(() => {
                        addressBadge.textContent = original;
                        addressBadge.style.color = '';
                        addressBadge.style.borderColor = '';
                    }, 2000);
                }).catch(err => {
                    console.error('Copy failed:', err);
                });
            } else {
                // Fallback for non-secure contexts
                const textArea = document.createElement("textarea");
                textArea.value = host;
                document.body.appendChild(textArea);
                textArea.select();
                try {
                    document.execCommand('copy');
                    const original = addressBadge.textContent;
                    addressBadge.textContent = 'COPIED!';
                    addressBadge.style.color = '#00FF9D';
                    setTimeout(() => {
                        addressBadge.textContent = original;
                        addressBadge.style.color = '';
                    }, 2000);
                } catch (err) {
                    console.error('Fallback copy failed', err);
                }
                document.body.removeChild(textArea);
            }
        });
    }

    // Initial setup
    updateCommand();
    
    // Form listeners
    const form = document.getElementById('configForm');
    if (form) {
        form.addEventListener('change', updateCommand);
        form.addEventListener('input', updateCommand);
    }
    
    // Load history
    loadHistory();
    
    // Close modal on outside click
    const modalOverlay = document.getElementById('plugin-modal');
    if (modalOverlay) {
        modalOverlay.addEventListener('click', (e) => {
            if (e.target.id === 'plugin-modal') closeModal();
        });
    }
});

window.switchTab = function(tabId) {
    // Hide all views
    document.getElementById('scan-view').style.display = 'none';
    document.getElementById('history-view').style.display = 'none';
    document.getElementById('favorites-view').style.display = 'none';
    const detailsView = document.getElementById('scan-details-view');
    if (detailsView) detailsView.style.display = 'none';
    
    // Reset nav active state
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    
    // Show selected view and set active
    if (tabId === 'scan') {
        document.getElementById('scan-view').style.display = 'block';
        document.getElementById('nav-scan').classList.add('active');
    } else if (tabId === 'history') {
        document.getElementById('history-view').style.display = 'block';
        document.getElementById('nav-history').classList.add('active');
        loadHistory();
    } else if (tabId === 'favorites') {
        document.getElementById('favorites-view').style.display = 'block';
        document.getElementById('nav-favorites').classList.add('active');
        loadFavorites();
    } else if (tabId === 'details') {
        if (detailsView) detailsView.style.display = 'block';
    }
}

function updateCommand() {
    const form = document.getElementById('configForm');
    if (!form) return;
    const formData = new FormData(form);
    // Logic kept simple for brevity
}

window.runScan = async function() {
    const form = document.getElementById('configForm');
    const formData = new FormData(form);
    
    const requestData = {
        pages: parseInt(formData.get('pages')) || 5,
        limit: parseInt(formData.get('limit')) || 0,
        min_installs: parseInt(formData.get('min_installs')) || 0,
        max_installs: parseInt(formData.get('max_installs')) || 0,
        sort: formData.get('sort') || 'updated',
        smart: formData.get('smart') === 'on',
        abandoned: formData.get('abandoned') === 'on',
        user_facing: formData.get('user_facing') === 'on',
        themes: formData.get('themes') === 'on',
        min_days: parseInt(formData.get('min_days')) || 0,
        max_days: parseInt(formData.get('max_days')) || 0,
        deep_analysis: formData.get('deep_analysis') === 'on',
        download: 0,
        auto_download_risky: 0,
        output: formData.get('output'),
        format: formData.get('format')
    };

    const downloadMode = formData.get('download_mode');
    const downloadQty = parseInt(formData.get('download_qty')) || 0;
    
    if (downloadMode === 'all') {
        requestData.download = downloadQty;
    } else if (downloadMode === 'risky') {
        requestData.auto_download_risky = downloadQty;
    }
    
    const runBtn = document.getElementById('runBtn');
    runBtn.disabled = true;
    runBtn.innerHTML = '<span>STARTING...</span>';
    
    clearTerminal();
    logTerminal('Initializing scan...', 'info');
    
    try {
        const response = await fetch('/api/scans', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(requestData)
        });
        
        const data = await response.json();
        
        if (data.session_id) {
            currentScanId = data.session_id;
            logTerminal(`Scan session started: ID ${currentScanId}`, 'success');
            connectWebSocket(currentScanId);
            
            document.getElementById('scan-status').textContent = 'RUNNING';
            document.getElementById('scan-status').className = 'info-value running';
        } else {
            logTerminal('Failed to start scan', 'error');
            runBtn.disabled = false;
            runBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg><span>RUN SCAN</span>';
        }
    } catch (error) {
        logTerminal(`Error: ${error.message}`, 'error');
        runBtn.disabled = false;
        runBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg><span>RUN SCAN</span>';
    }
}

function connectWebSocket(sessionId) {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/scans/${sessionId}`;
    if (socket) socket.close();
    
    socket = new WebSocket(wsUrl);
    socket.onopen = () => logTerminal('WebSocket connected', 'info');
    socket.onmessage = (event) => handleMessage(JSON.parse(event.data));
    socket.onclose = () => logTerminal('WebSocket connection closed', 'info');
    socket.onerror = () => logTerminal('WebSocket error', 'error');
}

function handleMessage(msg) {
    const runBtn = document.getElementById('runBtn');
    
    switch(msg.type) {
        case 'start':
            logTerminal('Scan execution started...', 'info');
            break;
        case 'result':
            logTerminal(`${msg.data.score >= 50 ? '[HIGH RISK]' : '[INFO]'} Found: ${msg.data.slug} (Score: ${msg.data.score})`, msg.data.score >= 50 ? 'high-risk' : 'low-risk');
            document.getElementById('scan-found').textContent = msg.found_count;
            break;
        case 'deduplicated':
            logTerminal(`Scan identical to Session #${msg.original_session_id}. Merging...`, 'warn');
            logTerminal(`Session merged. History updated.`, 'success');
            currentScanId = msg.original_session_id;
            document.getElementById('scan-status').textContent = 'MERGED';
            document.getElementById('scan-status').className = 'info-value completed';
            runBtn.disabled = false;
            runBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg><span>RUN SCAN</span>';
            loadHistory();
            break;
        case 'complete':
            logTerminal(`Scan completed. Found: ${msg.total_found}, High Risk: ${msg.high_risk_count}`, 'success');
            document.getElementById('scan-status').textContent = 'COMPLETED';
            document.getElementById('scan-status').className = 'info-value completed';
            runBtn.disabled = false;
            runBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg><span>RUN SCAN</span>';
            loadHistory();
            break;
        case 'error':
            logTerminal(`Error: ${msg.message}`, 'error');
            document.getElementById('scan-status').textContent = 'FAILED';
            document.getElementById('scan-status').className = 'info-value failed';
            runBtn.disabled = false;
            runBtn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polygon points="5 3 19 12 5 21 5 3"></polygon></svg><span>RUN SCAN</span>';
            break;
    }
}

function logTerminal(text, type = 'info') {
    const terminal = document.getElementById('terminal-content');
    const div = document.createElement('div');
    div.className = 'line';
    
    let color = '#ccc';
    if (type === 'error' || type === 'high-risk') color = '#ff5f56';
    if (type === 'success') color = '#27c93f';
    if (type === 'info') color = '#00f3ff';
    if (type === 'warn') color = '#ffbd2e';
    
    div.innerHTML = `<span class="prompt">$</span> <span style="color: ${color}">${text}</span>`;
    
    const existingCursor = terminal.querySelector('.cursor');
    if (existingCursor) existingCursor.remove();
    
    terminal.appendChild(div);
    const cursor = document.createElement('span');
    cursor.className = 'cursor';
    cursor.textContent = '_';
    div.appendChild(cursor);
    
    terminal.scrollTop = terminal.scrollHeight;
}

function clearTerminal() {
    const terminal = document.getElementById('terminal-content');
    terminal.innerHTML = '<div class="line"><span class="prompt">$</span> <span class="cmd-text">Ready to scan...</span><span class="cursor">_</span></div>';
}

window.loadHistory = async function() {
    const list = document.getElementById('history-list');
    if (!list) return;
    
    try {
        const response = await fetch('/api/scans');
        const data = await response.json();
        const sessions = data.sessions.sort((a, b) => new Date(b.created_at || b.start_time) - new Date(a.created_at || a.start_time));
        list.innerHTML = sessions.map(s => `
            <tr>
                <td>#${s.id}</td>
                <td><span class="status-badge ${s.status.toLowerCase()}">${s.status}</span></td>
                <td>${s.total_found}</td>
                <td>${s.high_risk_count}</td>
                <td>${new Date(s.created_at || s.start_time).toLocaleString()}</td>
                <td>
                    <div style="display: flex; gap: 8px;">
                        <button onclick="viewScan(${s.id})" class="action-btn" title="View Results" style="width: 32px; height: 32px; padding: 0; background: #333; color: white;">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"></path><circle cx="12" cy="12" r="3"></circle></svg>
                        </button>
                        <button onclick="deleteScan(${s.id})" class="action-btn" title="Delete Scan" style="width: 32px; height: 32px; padding: 0; background: rgba(255, 0, 85, 0.1); color: #ff0055; border: 1px solid rgba(255, 0, 85, 0.2);">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path><line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line></svg>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        list.innerHTML = '<tr><td colspan="6">Error loading history</td></tr>';
    }
}

window.deleteScan = async function(id) {
    if (!confirm('Are you sure you want to delete this scan session? This will remove all associated results from the database.')) return;
    try {
        const response = await fetch(`/api/scans/${id}`, { method: 'DELETE' });
        if (response.ok) loadHistory();
        else {
            const err = await response.json();
            alert('Failed to delete scan: ' + (err.detail || 'Unknown error'));
        }
    } catch (error) {
        alert('Error deleting scan: ' + error.message);
    }
}

window.loadFavorites = async function() {
    const list = document.getElementById('favorites-list');
    list.innerHTML = '<tr><td colspan="4">Loading...</td></tr>';
    try {
        const resp = await fetch('/api/favorites');
        const data = await resp.json();
        
        window.currentScanResults = data.favorites || [];
        
        list.innerHTML = window.currentScanResults.map((r, index) => `
            <tr>
                <td style="color: #fff;">${escapeHtml(r.slug)}</td>
                <td>${escapeHtml(r.version)}</td>
                <td><span class="${r.score >= 50 ? 'risk-high' : 'risk-low'}">${r.score}</span></td>
                <td>
                    <div style="display: flex; gap: 8px; align-items: center;">
                        <button onclick="openPluginModal(${index})" class="action-btn" style="height: 28px; padding: 0 12px; background: var(--accent-primary); color: #000; font-size: 10px; font-weight: 700; border-radius: 2px;">DETAILS</button>
                        <button onclick="removeFromFavorites('${escapeHtml(r.slug)}')" class="action-btn" style="width: 28px; height: 28px; padding: 0; background: rgba(255, 0, 85, 0.1); color: #ff0055; border: 1px solid rgba(255, 0, 85, 0.2); border-radius: 2px;" title="Remove Favorite">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                        </button>
                    </div>
                </td>
            </tr>
        `).join('');
        if(window.currentScanResults.length === 0) list.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#666;">No favorites yet</td></tr>';
    } catch(e) { 
        console.error(e);
        list.innerHTML = '<tr><td colspan="4">Error loading favorites</td></tr>'; 
    }
}

window.removeFromFavorites = async function(slug) {
    if(!confirm('Remove from favorites?')) return;
    await fetch(`/api/favorites/${slug}`, {method: 'DELETE'});
    loadFavorites();
}

window.toggleFavorite = async function(slug) {
    const plugin = window.currentScanResults.find(p => p.slug === slug);
    if (plugin) {
        const response = await fetch('/api/favorites', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(plugin)
        });
        const res = await response.json();
        if (res.success) {
            alert('Plugin added to favorites');
        } else {
            if(confirm('This plugin is already in favorites. Remove it?')) {
                await fetch(`/api/favorites/${slug}`, {method: 'DELETE'});
                alert('Plugin removed from favorites');
            }
        }
    }
}

window.viewScan = async function(id) {
    switchTab('details');
    const summary = document.getElementById('details-summary');
    const list = document.getElementById('details-list');
    const title = document.getElementById('details-title');
    title.textContent = `Scan #${id} Details`;
    summary.innerHTML = 'Loading details...';
    list.innerHTML = 'Loading results...';
    
    try {
        const sessionResp = await fetch(`/api/scans/${id}`);
        const session = await sessionResp.json();
        
        const config = session.config || {};
        const configHtml = `
            <div style="margin-top: 15px; padding-top: 15px; border-top: 1px dashed #333; grid-column: 1 / -1;">
                <label style="display: block; font-size: 10px; color: var(--text-muted); margin-bottom: 8px; font-family: var(--font-mono);">CONFIGURATION</label>
                <div style="display: flex; flex-wrap: wrap; gap: 8px; font-size: 11px; font-family: var(--font-mono); color: #888;">
                    <span style="background: #1a1a1a; padding: 4px 8px; border-radius: 2px;">SORT: <span style="color: #ccc">${(config.sort || 'UPDATED').toUpperCase()}</span></span>
                    <span style="background: #1a1a1a; padding: 4px 8px; border-radius: 2px;">PAGES: <span style="color: #ccc">${config.pages || 5}</span></span>
                    <span style="background: #1a1a1a; padding: 4px 8px; border-radius: 2px;">LIMIT: <span style="color: #ccc">${config.limit || '∞'}</span></span>
                    <span style="background: #1a1a1a; padding: 4px 8px; border-radius: 2px;">INSTALLS: <span style="color: #ccc">${config.min_installs || 0} - ${config.max_installs || '∞'}</span></span>
                    <span style="background: #1a1a1a; padding: 4px 8px; border-radius: 2px;">UPDATED: <span style="color: #ccc">${config.min_days || 0}-${config.max_days || '∞'}d</span></span>
                    
                    ${config.smart ? '<span style="background: rgba(0, 255, 157, 0.1); color: var(--accent-primary); padding: 4px 8px; border-radius: 2px;">SMART</span>' : ''}
                    ${config.abandoned ? '<span style="background: rgba(255, 0, 85, 0.1); color: var(--accent-secondary); padding: 4px 8px; border-radius: 2px;">ABANDONED</span>' : ''}
                    ${config.user_facing ? '<span style="background: rgba(255, 189, 46, 0.1); color: #ffbd2e; padding: 4px 8px; border-radius: 2px;">USER-FACING</span>' : ''}
                    ${config.deep_analysis ? '<span style="background: rgba(255, 0, 85, 0.1); color: var(--accent-secondary); padding: 4px 8px; border-radius: 2px;">DEEP-ANALYSIS</span>' : ''}
                    ${config.themes ? '<span style="background: #333; color: #ccc; padding: 4px 8px; border-radius: 2px;">THEMES</span>' : '<span style="background: #333; color: #ccc; padding: 4px 8px; border-radius: 2px;">PLUGINS</span>'}
                </div>
            </div>
        `;
        
        summary.innerHTML = `
            <div class="detail-item"><label>STATUS</label><span class="status-badge ${escapeHtml(session.status).toLowerCase()}">${escapeHtml(session.status)}</span></div>
            <div class="detail-item"><label>PLUGINS FOUND</label><span>${session.total_found}</span></div>
            <div class="detail-item"><label>HIGH RISK</label><span class="${session.high_risk_count > 0 ? 'risk-high' : 'risk-low'}">${session.high_risk_count}</span></div>
            <div class="detail-item"><label>DATE</label><span>${new Date(session.created_at || session.start_time).toLocaleString()}</span></div>
            ${configHtml}
        `;
        
        const resultsResp = await fetch(`/api/scans/${id}/results?limit=500`);
        const resultsData = await resultsResp.json();
        window.currentScanResults = resultsData.results || [];
        
        if (window.currentScanResults.length > 0) {
            list.innerHTML = window.currentScanResults.map((r, index) => `
                <tr>
                    <td style="color: #fff; font-weight: 500;">${escapeHtml(r.slug)} ${r.is_duplicate ? '<span style="background: rgba(100,100,100,0.3); color: #aaa; padding: 2px 4px; border-radius: 2px; font-size: 9px; margin-left: 5px;">SEEN BEFORE</span>' : ''}</td>
                    <td>${escapeHtml(r.version)}</td>
                    <td><span class="${r.score >= 50 ? 'risk-high' : (r.score > 20 ? 'risk-medium' : 'risk-low')}">${r.score}</span></td>
                    <td>${r.days_since_update} days</td>
                    <td>${r.installations}+</td>
                    <td style="display: flex; gap: 5px;">
                        <button onclick="toggleFavorite('${escapeHtml(r.slug)}')" class="action-btn" style="height: 24px; width: 24px; padding: 0; background: transparent; border: 1px solid var(--border-color); color: #666;" title="Add to Favorites">
                            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"></path></svg>
                        </button>
                        <a href="https://wordpress.org/plugins/${escapeHtml(r.slug)}/" target="_blank" class="action-btn" style="height: 24px; padding: 0 8px; background: #222; color: #ccc; border: 1px solid #333;">WP</a>
                        <button onclick="openPluginModal(${index})" class="action-btn" style="height: 24px; width: auto; background: var(--accent-primary); color: #000;">DETAILS</button>
                    </td>
                </tr>
            `).join('');
        } else {
            list.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #666;">No results found</td></tr>';
        }
    } catch (error) {
        summary.innerHTML = `Error: ${error.message}`;
    }
}

window.openPluginModal = function(index) {
    const plugin = window.currentScanResults[index];
    if (!plugin) return;
    
    const modal = document.getElementById('plugin-modal');
    const title = document.getElementById('modal-title');
    const content = document.getElementById('modal-content');
    
    title.textContent = `${escapeHtml(plugin.name || plugin.slug)} (v${escapeHtml(plugin.version)})`;
    
    const getLink = (url, fallback) => url ? url : fallback;
    
    let tagsHtml = '';
    if (plugin.is_user_facing) tagsHtml += '<span class="tag warn">USER FACING</span>';
    if (plugin.is_risky_category) tagsHtml += '<span class="tag risk">RISKY CATEGORY</span>';
    if (plugin.author_trusted) tagsHtml += '<span class="tag safe">TRUSTED AUTHOR</span>';
    if (plugin.is_duplicate) tagsHtml += '<span class="tag" style="background: #333;">PREVIOUSLY FOUND</span>';
    
    const linksHtml = `
        <div class="link-grid">
            ${plugin.download_link ? `<a href="${plugin.download_link}" target="_blank" class="ext-link">📥 Download Zip</a>` : ''}
            <a href="${getLink(plugin.trac_link, `https://plugins.trac.wordpress.org/log/${plugin.slug}/`)}" target="_blank" class="ext-link">📜 View Source (Trac)</a>
            <a href="${getLink(plugin.cve_search_link, `https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=${plugin.slug}`)}" target="_blank" class="ext-link">🛡️ CVE Search</a>
            <a href="${getLink(plugin.wpscan_link, `https://wpscan.com/plugin/${plugin.slug}`)}" target="_blank" class="ext-link">🔍 WPScan</a>
            <a href="${getLink(plugin.patchstack_link, `https://patchstack.com/database?search=${plugin.slug}`)}" target="_blank" class="ext-link">🩹 Patchstack</a>
            <a href="${getLink(plugin.wordfence_link, `https://www.wordfence.com/threat-intel/vulnerabilities/search?search=${plugin.slug}`)}" target="_blank" class="ext-link">🦁 Wordfence</a>
            <a href="${getLink(plugin.google_dork_link, `https://www.google.com/search?q=${plugin.slug}+site:wpscan.com+OR+site:patchstack.com+OR+site:cve.mitre.org+%22vulnerability%22`)}" target="_blank" class="ext-link">🔎 Google Dork</a>
        </div>
    `;

    content.innerHTML = `
        <div style="margin-bottom: 20px; display: flex; justify-content: space-between; align-items: start;">
            <div>
                <div style="display: flex; gap: 20px; margin-bottom: 15px; font-size: 12px; color: #888;">
                    <span>Score: <strong style="color: ${plugin.score >= 50 ? '#ff5f56' : '#00ff9d'}">${plugin.score}/100</strong></span>
                    <span>Installs: <strong style="color: #fff">${plugin.installations}+</strong></span>
                    <span>Updated: <strong style="color: #fff">${plugin.days_since_update} days ago</strong></span>
                </div>
                <div>${tagsHtml}</div>
            </div>
            <button onclick="toggleFavorite('${plugin.slug}')" class="action-btn" style="background: transparent; border: 1px solid var(--accent-primary); color: var(--accent-primary); width: auto; height: 30px;">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z"></path></svg>
                FAVORITE
            </button>
        </div>
        
        <div class="section-title">SECURITY RESOURCES</div>
        ${linksHtml}
    `;
    
    modal.classList.add('active');
}

window.closeModal = function() {
    document.getElementById('plugin-modal').classList.remove('active');
}
