/**
 * main.js — Agentless Scanner Dashboard
 * 
 * Fixed version:
 *  - Removed Windows Hello gate from scan buttons (auth is server-side)
 *  - Full console.log tracing at every step
 *  - Persistent error panel for failures (not just toast)
 *  - Scan history loads on page open
 *  - Backend connectivity check on load
 */

// API_BASE is already declared in api.js (loaded first) — do NOT redeclare it here.

// ─────────────────────────────────────────────────────────────
// Diagnostic helpers
// ─────────────────────────────────────────────────────────────
function dbg(label, value) {
    if (value !== undefined) {
        console.log(`[SCANNER] ${label}:`, value);
    } else {
        console.log(`[SCANNER] ${label}`);
    }
}

function showError(msg) {
    console.error('[SCANNER ERROR]', msg);
    UI.notify(msg, 'error');

    // Also show in persistent error panel if it exists
    const panel = document.getElementById('error-debug-panel');
    if (panel) {
        panel.textContent = `⚠ ${new Date().toLocaleTimeString()} — ${msg}`;
        panel.style.display = 'block';
    }
}

// ─────────────────────────────────────────────────────────────
// DOMContentLoaded bootstrap
// ─────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
    dbg('DOMContentLoaded fired — main.js loaded correctly');

    // Inject a persistent error panel just below the header
    injectErrorPanel();

    // --- Check backend connectivity first ---
    await checkBackend();

    // --- Check Authentication on Load ---
    await checkAuthOnLoad();

    // --- Navigation Binding ---
    document.getElementById('nav-list').addEventListener('click', (e) => {
        const link = e.target.closest('.nav-item');
        if (link) {
            e.preventDefault();
            const target = link.getAttribute('data-target');
            dbg('Nav click → section', target);
            UI.switchSection(target);
            if (target === 'overview-section') loadOverview();
            if (target === 'history-section') loadHistory();
        }
    });

    // --- Modal Binding ---
    document.getElementById('modal-close').addEventListener('click', UI.closeModal);
    document.getElementById('modal-close-btn').addEventListener('click', UI.closeModal);
    document.getElementById('details-modal').addEventListener('click', (e) => {
        if (e.target.id === 'details-modal') UI.closeModal();
    });

    // --- Load Initial Data ---
    loadOverview();
    loadHistory();

    dbg('Init complete — listening for form submits');

    // ─────────────────────────────────────────────────────────
    // Inject debug error panel into DOM
    // ─────────────────────────────────────────────────────────
    function injectErrorPanel() {
        const existing = document.getElementById('error-debug-panel');
        if (existing) return;
        const div = document.createElement('div');
        div.id = 'error-debug-panel';
        div.style.cssText = `
            display:none; position:fixed; bottom:16px; left:50%; transform:translateX(-50%);
            background:#1a0010; border:1px solid #ff3366; border-radius:6px;
            color:#ff3366; padding:10px 20px; font-size:13px; font-family:monospace;
            z-index:9999; max-width:90vw; text-align:center; box-shadow:0 0 20px rgba(255,51,102,0.3);
        `;
        document.body.appendChild(div);
    }

    // ─────────────────────────────────────────────────────────
    // Backend connectivity check
    // ─────────────────────────────────────────────────────────
    async function checkBackend() {
        try {
            dbg('Checking backend at', API_BASE);
            const r = await fetch(`${API_BASE}/ping`, { method: 'GET' });
            if (r.ok) {
                const d = await r.json();
                dbg('Backend ping OK', d);
                UI.notify('Backend connected ✓', 'success');
            } else {
                showError(`Backend responded with HTTP ${r.status} — check Flask terminal`);
            }
        } catch (err) {
            showError(`Cannot reach backend at ${API_BASE} — is Flask running? Error: ${err.message}`);
            dbg('Backend ping FAILED', err);
        }
    }

    // ─────────────────────────────────────────────────────────
    // Auth helpers (non-blocking)
    // ─────────────────────────────────────────────────────────
    async function checkAuthOnLoad() {
        try {
            const isAuth = await Api.checkAuthStatus();
            dbg('Auth status on load', isAuth);
            updateAuthUI(isAuth);
        } catch (err) {
            dbg('Auth check failed (non-fatal)', err.message);
        }
    }

    function updateAuthUI(isAuthenticated) {
        document.querySelectorAll('.auth-indicator').forEach(el => {
            el.classList.toggle('authenticated', isAuthenticated);
            el.textContent = isAuthenticated ? 'Authenticated' : 'Not Authenticated';
        });
    }

    // ─────────────────────────────────────────────────────────
    // Overview
    // ─────────────────────────────────────────────────────────
    async function loadOverview() {
        try {
            dbg('Loading overview...');
            const data = await Api.getOverview();
            document.getElementById('metric-hosts').textContent = data.totalHosts;
            document.getElementById('metric-ports').textContent = data.openPorts;
            document.getElementById('metric-services').textContent = data.highRiskServices;
            document.getElementById('metric-hotfixes').textContent = data.missingHotfixes;
            document.getElementById('last-scan-time').textContent = UI.formatDate(data.lastScan);
            UI.renderVulnChart(data.vulnData);

            const tbody = document.querySelector('#overview-hosts-table tbody');
            tbody.innerHTML = '';
            if (!data.recentHosts.length) {
                tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No hosts yet — run Phase 2 scan</td></tr>';
            }
            data.recentHosts.forEach(host => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${host.ip}</td><td>${host.hostname}</td><td>${UI.getRiskBadge(host.risk)}</td><td>${UI.timeAgo(host.lastSeen)}</td>`;
                tbody.appendChild(tr);
            });
            dbg('Overview loaded OK');
        } catch (err) {
            dbg('Overview load failed', err.message);
        }
    }

    // ─────────────────────────────────────────────────────────
    // PHASE 2 — Submit handler (NO Windows Hello gate)
    // ─────────────────────────────────────────────────────────
    const formP2 = document.getElementById('form-phase2');
    if (!formP2) {
        console.error('[SCANNER] CRITICAL: #form-phase2 not found in DOM!');
    } else {
        dbg('#form-phase2 found in DOM');
        formP2.addEventListener('submit', async (e) => {
            e.preventDefault();
            dbg('═══ Phase 2 form submitted ═══');

            const target = document.getElementById('p2-target').value.trim();
            const btn = document.getElementById('btn-p2-scan');
            const btnText = btn.querySelector('.btn-text');

            dbg('Phase 2 target', target);

            if (!target) {
                showError('Please enter a target IP address or CIDR range');
                return;
            }

            // Disable button + show spinner
            UI.setButtonLoading(btn, true);
            if (btnText) btnText.textContent = 'Scanning...';
            document.getElementById('p2-results-panel').classList.add('hidden');

            try {
                dbg('Calling POST /api/scan/phase2 with target:', target);
                UI.notify('Running Phase 2 Network Exposure Scan...', 'info');

                const response = await fetch(`${API_BASE}/scan/phase2`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target })
                });

                dbg('Phase 2 fetch status', response.status);

                const payload = await response.json();
                dbg('Phase 2 response payload', payload);

                if (!response.ok || payload.status === 'error') {
                    const msg = payload.message || payload.errors?.[0]?.message || `HTTP ${response.status}`;
                    throw new Error(msg);
                }

                UI.notify('Phase 2 Scan Completed ✓', 'success');
                dbg('Phase 2 SUCCESS — rendering results');

                const scanData = payload.data;
                renderPhase2Results(scanData.result || scanData, scanData);
                document.getElementById('p2-results-panel').classList.remove('hidden');

                // Refresh overview + history
                await Promise.allSettled([loadOverview(), loadHistory()]);

            } catch (err) {
                dbg('Phase 2 FAILED', err.message);
                showError(`Phase 2 scan failed: ${err.message}`);
            } finally {
                UI.setButtonLoading(btn, false);
                if (btnText) btnText.textContent = 'Start Exposure Scan';
            }
        });
    }

    // ─────────────────────────────────────────────────────────
    // PHASE 2 Result Renderer
    // ─────────────────────────────────────────────────────────
    function renderPhase2Results(data, meta) {
        const panel = document.getElementById('p2-results-panel');
        const summary = data?.summary || {};
        const hosts = data?.hosts || [];
        const scanInfo = data?.scan_info || {};
        const scanTarget = meta?.target || scanInfo.target || 'Unknown';

        let html = `
            <div class="result-section">
                <div class="result-section-header">
                    <span class="result-section-icon">📡</span>
                    <h3>Network Exposure Scan Results</h3>
                    <div class="scan-meta-row">
                        <span class="meta-chip">🎯 Target: <strong>${scanTarget}</strong></span>
                        <span class="meta-chip">⏱ ${UI.formatDate(meta?.timestamp || scanInfo.timestamp)}</span>
                        <span class="meta-chip">Risk: ${UI.getRiskBadge(summary.risk_level || 'LOW')}</span>
                    </div>
                </div>
                <div class="metrics-grid phase2-metrics">
                    <div class="metric-card">
                        <div class="metric-title">Hosts Discovered</div>
                        <div class="metric-value">${summary.total_hosts || 0}</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-title">Open Ports</div>
                        <div class="metric-value">${summary.total_open_ports || 0}</div>
                    </div>
                    <div class="metric-card ${['CRITICAL', 'HIGH'].includes(summary.risk_level) ? 'alert' : ''}">
                        <div class="metric-title">Risk Level</div>
                        <div class="metric-value ${['CRITICAL', 'HIGH'].includes(summary.risk_level) ? 'text-danger' : ''}">${summary.risk_level || 'LOW'}</div>
                    </div>
                </div>
                <div class="exposure-summary-box">
                    <span class="summary-icon">ℹ️</span>
                    <p>${summary.exposure_summary || 'Scan complete.'}</p>
                </div>
            </div>
        `;

        // Open ports table
        const allPorts = [];
        hosts.forEach(h => (h.ports || []).forEach(p => allPorts.push({ host: h.ip, ...p })));

        if (allPorts.length > 0) {
            html += `
                <div class="result-section">
                    <h4 class="result-sub-header">🔌 Open Ports (${allPorts.length} total)</h4>
                    <div class="table-container">
                        <table class="data-table">
                            <thead><tr><th>Host</th><th>Port</th><th>Service</th><th>State</th><th>Version</th><th>Risk</th></tr></thead>
                            <tbody>
                                ${allPorts.map(p => `
                                    <tr>
                                        <td><code>${p.host}</code></td>
                                        <td><span class="port-number">${p.port}</span></td>
                                        <td>${p.service || '-'}</td>
                                        <td>${p.state || '-'}</td>
                                        <td><code>${p.version || '-'}</code></td>
                                        <td>${UI.getRiskBadge(p.risk_level || 'LOW')}</td>
                                    </tr>`).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        } else {
            html += `<div class="result-section"><p class="empty-state">No open ports detected on the target range.</p></div>`;
        }

        // Risk distribution
        const dist = summary.risk_distribution || {};
        if (Object.values(dist).some(v => v > 0)) {
            html += `
                <div class="result-section">
                    <h4 class="result-sub-header">📊 Risk Distribution</h4>
                    <div class="risk-dist-grid">
                        <div class="risk-dist-card critical"><span>${dist.CRITICAL || 0}</span><label>Critical</label></div>
                        <div class="risk-dist-card high"><span>${dist.HIGH || 0}</span><label>High</label></div>
                        <div class="risk-dist-card medium"><span>${dist.MEDIUM || 0}</span><label>Medium</label></div>
                        <div class="risk-dist-card low"><span>${dist.LOW || 0}</span><label>Low</label></div>
                    </div>
                </div>
            `;
        }

        html += buildRawJsonToggle(data);
        panel.innerHTML = html;
        bindRawJsonToggles(panel);
    }

    // ─────────────────────────────────────────────────────────
    // PHASE 3 — Submit handler (NO Windows Hello gate)
    // ─────────────────────────────────────────────────────────
    const formP3 = document.getElementById('form-phase3');
    if (!formP3) {
        console.error('[SCANNER] CRITICAL: #form-phase3 not found in DOM!');
    } else {
        dbg('#form-phase3 found in DOM');
        formP3.addEventListener('submit', async (e) => {
            e.preventDefault();
            dbg('═══ Phase 3 form submitted ═══');

            const btn = document.getElementById('btn-p3-scan');
            const btnText = btn.querySelector('.btn-text');

            UI.setButtonLoading(btn, true);
            if (btnText) btnText.textContent = 'Scanning...';
            document.getElementById('p3-results-panel').classList.add('hidden');

            try {
                dbg('Calling POST /api/scan/phase3');
                UI.notify('Running Phase 3 System Vulnerability Scan...', 'info');

                const response = await fetch(`${API_BASE}/scan/phase3`, {
                    method: 'POST'
                });

                dbg('Phase 3 fetch status', response.status);

                const payload = await response.json();
                dbg('Phase 3 response payload (summary)', payload?.data?.result?.summary);

                if (!response.ok || payload.status === 'error') {
                    const msg = payload.message || payload.errors?.[0]?.message || `HTTP ${response.status}`;
                    throw new Error(msg);
                }

                UI.notify('Phase 3 Scan Completed ✓', 'success');
                dbg('Phase 3 SUCCESS — rendering results');

                const scanData = payload.data;
                renderPhase3Results(scanData.result || scanData, scanData);
                document.getElementById('p3-results-panel').classList.remove('hidden');

                await Promise.allSettled([loadOverview(), loadHistory()]);

            } catch (err) {
                dbg('Phase 3 FAILED', err.message);
                showError(`Phase 3 scan failed: ${err.message}`);
            } finally {
                UI.setButtonLoading(btn, false);
                if (btnText) btnText.textContent = 'Start System Scan';
            }
        });
    }

    // ─────────────────────────────────────────────────────────
    // PHASE 3 Result Renderer
    // ─────────────────────────────────────────────────────────
    function renderPhase3Results(data, meta) {
        const container = document.getElementById('p3-categories');
        const summary = data?.summary || {};
        const scanInfo = data?.scan_info || {};
        const allVulns = data?.all_vulnerabilities || [];
        const cveFinding = data?.all_cve_findings || [];
        const categories = data?.categories || [];
        const softwareAn = data?.software_analysis || [];
        const osInfo = data?.os_profiling || {};

        let html = `
            <div class="result-section">
                <div class="result-section-header">
                    <span class="result-section-icon">🔐</span>
                    <h3>System Vulnerability Assessment</h3>
                    <div class="scan-meta-row">
                        <span class="meta-chip">⏱ ${UI.formatDate(meta?.timestamp || scanInfo.timestamp)}</span>
                        <span class="meta-chip">Categories: <strong>${scanInfo.total_categories || categories.length || 0}</strong></span>
                    </div>
                </div>
                <div class="metrics-grid phase3-metrics">
                    <div class="metric-card ${summary.total_vulnerabilities > 0 ? 'alert' : ''}">
                        <div class="metric-title">Total Findings</div>
                        <div class="metric-value ${summary.total_vulnerabilities > 0 ? 'text-danger' : ''}">${summary.total_vulnerabilities || 0}</div>
                    </div>
                    <div class="metric-card alert">
                        <div class="metric-title">Critical</div>
                        <div class="metric-value text-danger">${summary.critical_count || 0}</div>
                    </div>
                    <div class="metric-card warning">
                        <div class="metric-title">High Risk</div>
                        <div class="metric-value text-warning">${summary.high_count || 0}</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-title">Risk Score</div>
                        <div class="metric-value ${summary.risk_score > 50 ? 'text-danger' : summary.risk_score > 20 ? 'text-warning' : ''}">${summary.risk_score || 0}</div>
                    </div>
                </div>
            </div>
        `;

        // OS Info
        const osData = osInfo?.command_output || osInfo?.summary || null;
        html += `
            <div class="result-section">
                <h4 class="result-sub-header">💻 OS Information</h4>
                <div class="os-info-grid">
                    <div class="os-info-item"><span class="os-label">Scanner</span><span class="os-value">${scanInfo.scanner || 'Agentless Windows Scanner'}</span></div>
                    <div class="os-info-item"><span class="os-label">Categories Scanned</span><span class="os-value">${scanInfo.total_categories || categories.length || 0}</span></div>
                    <div class="os-info-item"><span class="os-label">OS Profile</span><span class="os-value">${osData ? osData.substring(0, 120) + (osData.length > 120 ? '…' : '') : 'Not available'}</span></div>
                    <div class="os-info-item"><span class="os-label">Scan Status</span><span class="os-value">${meta?.status || 'Completed'}</span></div>
                </div>
            </div>
        `;

        // Vulnerabilities table
        if (allVulns.length > 0) {
            html += `
                <div class="result-section">
                    <h4 class="result-sub-header">🔎 Security Configuration Findings (${allVulns.length})</h4>
                    <div class="table-container">
                        <table class="data-table">
                            <thead><tr><th>ID</th><th>Title</th><th>Category</th><th>Severity</th><th>Description</th><th>Recommendation</th></tr></thead>
                            <tbody>
                                ${allVulns.map(v => `
                                    <tr class="vuln-row severity-${(v.severity || 'low').toLowerCase()}">
                                        <td><code class="vuln-id">${v.id || '-'}</code></td>
                                        <td><strong>${v.title || '-'}</strong></td>
                                        <td><span class="category-tag">${v.category || '-'}</span></td>
                                        <td>${UI.getRiskBadge(v.severity || 'LOW')}</td>
                                        <td class="description-cell">${v.description || '-'}</td>
                                        <td class="recommendation-cell">${v.recommendation || '-'}</td>
                                    </tr>`).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }

        // CVE table
        if (cveFinding.length > 0) {
            html += `
                <div class="result-section">
                    <h4 class="result-sub-header">🛡 NVD CVE Findings (${cveFinding.length})</h4>
                    <div class="table-container">
                        <table class="data-table">
                            <thead><tr><th>CVE ID</th><th>Product</th><th>Severity</th><th>CVSS</th><th>Title</th></tr></thead>
                            <tbody>
                                ${cveFinding.map(c => {
                const prod = `${c.affected_product || ''} ${c.affected_version || ''}`.trim() || '-';
                return `
                                    <tr class="cve-row severity-${(c.severity || 'low').toLowerCase()}">
                                        <td><code class="cve-id">${c.id || '-'}</code></td>
                                        <td>${prod}</td>
                                        <td>${UI.getRiskBadge(c.severity || 'LOW')}</td>
                                        <td><span class="cvss-score">${c.cvss_score || '-'}</span></td>
                                        <td class="description-cell">${c.title || '-'}</td>
                                    </tr>`;
            }).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }

        // Software analysis
        if (softwareAn.length > 0) {
            html += `
                <div class="result-section">
                    <h4 class="result-sub-header">📦 Software Security Analysis</h4>
                    <div class="table-container">
                        <table class="data-table">
                            <thead><tr><th>Application</th><th>Version</th><th>Status</th><th>Reason</th></tr></thead>
                            <tbody>
                                ${softwareAn.map(sw => `
                                    <tr>
                                        <td>${sw.application || '-'}</td>
                                        <td><code>${sw.version || '-'}</code></td>
                                        <td><span class="status-badge ${sw.status === 'SECURE' ? 'success' : sw.status === 'INSECURE' ? 'danger' : 'warning'}">${sw.status || '?'}</span></td>
                                        <td>${sw.reason || '-'}</td>
                                    </tr>`).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        }

        // Categories accordion
        if (categories.length > 0) {
            html += `<div class="result-section"><h4 class="result-sub-header">📂 Scan Categories</h4>`;
            categories.forEach(cat => {
                const vc = (cat.vulnerabilities || []).length;
                const cc = (cat.cve_findings || []).length;
                html += `
                    <div class="accordion-item">
                        <div class="accordion-header">
                            <span>${cat.name}</span>
                            <span class="accordion-meta">
                                ${vc > 0 ? `<span class="badge danger">${vc} vulns</span>` : ''}
                                ${cc > 0 ? `<span class="badge warning">${cc} CVEs</span>` : ''}
                                <span class="accordion-icon">▼</span>
                            </span>
                        </div>
                        <div class="accordion-content">
                            <div class="category-details">
                                <p><strong>Summary:</strong> ${cat.summary || 'N/A'}</p>
                                <p><strong>Logic:</strong> ${cat.logic || 'N/A'}</p>
                                <p><strong>Risk Score:</strong> ${cat.risk_score || 0}</p>
                            </div>
                        </div>
                    </div>
                `;
            });
            html += `</div>`;
        }

        html += buildRawJsonToggle(data);
        container.innerHTML = html;

        container.querySelectorAll('.accordion-header').forEach(h =>
            h.addEventListener('click', () => h.closest('.accordion-item').classList.toggle('open'))
        );
        bindRawJsonToggles(container);
    }

    // ─────────────────────────────────────────────────────────
    // Raw JSON toggle helpers
    // ─────────────────────────────────────────────────────────
    function buildRawJsonToggle(data) {
        const json = JSON.stringify(data, null, 2);
        const kb = (new TextEncoder().encode(json).length / 1024).toFixed(1);
        return `
            <div class="result-section raw-json-section">
                <details class="raw-json-toggle">
                    <summary class="raw-json-summary">
                        <span>{ } View Raw JSON</span>
                        <span class="raw-json-size">${kb} KB</span>
                    </summary>
                    <div class="raw-json-body">
                        <button class="copy-json-btn">📋 Copy</button>
                        <pre class="raw-json-pre">${escapeHtml(json)}</pre>
                    </div>
                </details>
            </div>
        `;
    }

    function bindRawJsonToggles(container) {
        container.querySelectorAll('.copy-json-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const pre = btn.nextElementSibling;
                navigator.clipboard.writeText(pre.textContent).then(() => {
                    btn.textContent = '✅ Copied!';
                    setTimeout(() => { btn.textContent = '📋 Copy'; }, 2000);
                });
            });
        });
    }

    function escapeHtml(str) {
        return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    // ─────────────────────────────────────────────────────────
    // Scan History
    // ─────────────────────────────────────────────────────────
    const btnRefresh = document.getElementById('btn-refresh-history');
    if (btnRefresh) btnRefresh.addEventListener('click', loadHistory);

    const btnExportAll = document.getElementById('btn-export-all');
    if (btnExportAll) {
        btnExportAll.addEventListener('click', async () => {
            const format = document.getElementById('export-format')?.value || 'json';
            try {
                UI.notify(`Exporting all scans as ${format.toUpperCase()}...`, 'info');
                await Api.exportAllScans(format);
                UI.notify('Export completed', 'success');
            } catch (err) {
                showError(err.message || 'Export failed');
            }
        });
    }

    const btnClearHistory = document.getElementById('btn-clear-history');
    if (btnClearHistory) {
        btnClearHistory.addEventListener('click', async () => {
            if (!confirm('Clear all scan history? This cannot be undone.')) return;
            try {
                await Api.clearScanHistory();
                UI.notify('Scan history cleared', 'success');
                loadHistory();
            } catch (err) {
                showError(err.message || 'Failed to clear history');
            }
        });
    }

    async function loadHistory() {
        dbg('Loading scan history...');
        try {
            const data = await Api.getScanHistory();
            dbg('Scan history loaded', `${data.length} records`);

            const tbody = document.querySelector('#history-table tbody');
            if (!tbody) { console.error('[SCANNER] #history-table tbody not found!'); return; }
            tbody.innerHTML = '';

            if (!data.length) {
                tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No scan history yet. Run a Phase 2 or Phase 3 scan to get started.</td></tr>';
                return;
            }

            data.forEach(scan => {
                const tr = document.createElement('tr');
                tr.style.cursor = 'pointer';
                tr.innerHTML = `
                    <td><code>#${scan.id}</code></td>
                    <td><span class="target-label">${scan.target}</span></td>
                    <td><span class="phase-badge">${scan.phase}</span></td>
                    <td>${UI.formatDate(scan.timestamp)}<br><small style="color:var(--text-muted)">${UI.timeAgo(scan.timestamp)}</small></td>
                    <td>${UI.getStatusBadge(scan.status)}</td>
                    <td class="export-actions">
                        <button class="btn btn-sm btn-export" data-id="${scan.id}" data-format="json">JSON</button>
                        <button class="btn btn-sm btn-export" data-id="${scan.id}" data-format="csv">CSV</button>
                        <button class="btn btn-sm btn-export" data-id="${scan.id}" data-format="pdf">PDF</button>
                    </td>
                `;

                tr.querySelectorAll('.btn-export').forEach(btn => {
                    btn.addEventListener('click', async (ev) => {
                        ev.stopPropagation();
                        const id = parseInt(btn.dataset.id);
                        const fmt = btn.dataset.format;
                        try {
                            UI.notify(`Exporting scan #${id} as ${fmt.toUpperCase()}...`, 'info');
                            await Api.exportScan(id, fmt);
                            UI.notify('Export completed', 'success');
                        } catch (exportErr) {
                            showError(exportErr.message || 'Export failed');
                        }
                    });
                });

                tr.addEventListener('click', async () => {
                    dbg('History row clicked, loading scan details for id', scan.id);
                    const record = await Api.getScanDetails(scan.id);
                    showScanDetailModal(scan, record);
                });

                tbody.appendChild(tr);
            });

        } catch (err) {
            dbg('loadHistory FAILED', err.message);
            showError('Failed to load scan history: ' + err.message);
        }
    }

    // ─────────────────────────────────────────────────────────
    // Scan Detail Modal
    // ─────────────────────────────────────────────────────────
    function showScanDetailModal(scan, record) {
        const dataSummary = record?.data_summary || null;
        const isPhase2 = scan.phase === 'Phase 2';

        let summaryHtml = '';
        if (dataSummary) {
            if (isPhase2) {
                summaryHtml = `
                    <div class="modal-summary-grid">
                        <div class="modal-summary-card"><span>${dataSummary.total_hosts || 0}</span><label>Hosts</label></div>
                        <div class="modal-summary-card"><span>${dataSummary.total_open_ports || 0}</span><label>Open Ports</label></div>
                        <div class="modal-summary-card"><span>${UI.getRiskBadge(dataSummary.risk_level || 'LOW')}</span><label>Risk</label></div>
                    </div>`;
            } else {
                summaryHtml = `
                    <div class="modal-summary-grid">
                        <div class="modal-summary-card danger"><span>${dataSummary.total_vulnerabilities || 0}</span><label>Vulns</label></div>
                        <div class="modal-summary-card danger"><span>${dataSummary.critical_count || 0}</span><label>Critical</label></div>
                        <div class="modal-summary-card warning"><span>${dataSummary.high_count || 0}</span><label>High</label></div>
                        <div class="modal-summary-card"><span>${dataSummary.risk_score || 0}</span><label>Score</label></div>
                    </div>`;
            }
        }

        const rawJson = record ? JSON.stringify(record, null, 2) : '{}';
        const contentHtml = `
            <div class="scan-detail-modal">
                <div class="detail-meta-grid">
                    <div><strong>Scan ID:</strong> #${scan.id}</div>
                    <div><strong>Phase:</strong> ${scan.phase}</div>
                    <div><strong>Target:</strong> ${scan.target}</div>
                    <div><strong>Status:</strong> ${UI.getStatusBadge(scan.status)}</div>
                    <div><strong>Time:</strong> ${UI.formatDate(scan.timestamp)}</div>
                </div>
                ${summaryHtml}
                <div class="modal-export-row">
                    <strong>Export:</strong>
                    <button class="btn btn-sm btn-modal-export" data-id="${scan.id}" data-format="json">JSON</button>
                    <button class="btn btn-sm btn-modal-export" data-id="${scan.id}" data-format="csv">CSV</button>
                    <button class="btn btn-sm btn-modal-export" data-id="${scan.id}" data-format="pdf">PDF</button>
                </div>
                <details class="raw-json-toggle" style="margin-top:1rem;">
                    <summary class="raw-json-summary"><span>{ } Full Record</span></summary>
                    <div class="raw-json-body">
                        <pre class="raw-json-pre">${escapeHtml(rawJson)}</pre>
                    </div>
                </details>
            </div>
        `;
        UI.showModal(`Scan Details — ${scan.phase} #${scan.id}`, contentHtml);
        document.querySelectorAll('.btn-modal-export').forEach(btn => {
            btn.addEventListener('click', async () => {
                try { await Api.exportScan(parseInt(btn.dataset.id), btn.dataset.format); }
                catch (e) { showError(e.message || 'Export failed'); }
            });
        });
    }

}); // end DOMContentLoaded
