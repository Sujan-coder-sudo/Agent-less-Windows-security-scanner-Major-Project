/**
 * main.js — Agentless Scanner Dashboard
 * Clean rebuild: Port Scanner + OS Inspection, unified /api/scan endpoint.
 */

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
    dbg('DOMContentLoaded fired — main.js loaded');

    injectErrorPanel();
    await checkBackend();

    // Navigation
    document.getElementById('nav-list').addEventListener('click', (e) => {
        const link = e.target.closest('.nav-item');
        if (link) {
            e.preventDefault();
            const target = link.getAttribute('data-target');
            UI.switchSection(target);
            if (target === 'overview-section') loadOverview();
            if (target === 'history-section') loadHistory();
        }
    });

    // Modal
    document.getElementById('modal-close').addEventListener('click', UI.closeModal);
    document.getElementById('modal-close-btn').addEventListener('click', UI.closeModal);
    document.getElementById('details-modal').addEventListener('click', (e) => {
        if (e.target.id === 'details-modal') UI.closeModal();
    });

    loadOverview();
    loadHistory();

    // ─────────────────────────────────────────────────────────
    // Error panel
    // ─────────────────────────────────────────────────────────
    function injectErrorPanel() {
        if (document.getElementById('error-debug-panel')) return;
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
    // Backend ping
    // ─────────────────────────────────────────────────────────
    async function checkBackend() {
        try {
            await Api.ping();
            UI.notify('Backend connected ✓', 'success');
        } catch (err) {
            showError(`Cannot reach backend at ${API_BASE} — is Flask running? ${err.message}`);
        }
    }

    // ─────────────────────────────────────────────────────────
    // Overview
    // ─────────────────────────────────────────────────────────
    async function loadOverview() {
        try {
            const data = await Api.getOverview();
            document.getElementById('metric-hosts').textContent     = data.totalHosts;
            document.getElementById('metric-ports').textContent     = data.openPorts;
            document.getElementById('metric-services').textContent  = data.highRiskServices;
            document.getElementById('metric-hotfixes').textContent  = data.missingHotfixes;
            document.getElementById('last-scan-time').textContent   = UI.formatDate(data.lastScan);
            UI.renderVulnChart(data.vulnData);

            const tbody = document.querySelector('#overview-hosts-table tbody');
            if (!tbody) return;
            tbody.innerHTML = '';
            if (!data.recentHosts.length) {
                tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No hosts yet — run a Port Scanner scan</td></tr>';
            }
            data.recentHosts.forEach(host => {
                const tr = document.createElement('tr');
                tr.innerHTML = `<td>${host.ip}</td><td>${host.hostname}</td><td>${UI.getRiskBadge(host.risk)}</td><td>${UI.timeAgo(host.lastSeen)}</td>`;
                tbody.appendChild(tr);
            });
        } catch (err) {
            dbg('Overview load failed', err.message);
        }
    }

    // ─────────────────────────────────────────────────────────
    // PORT SCANNER — form submit
    // ─────────────────────────────────────────────────────────
    const formPortScan = document.getElementById('form-phase2');
    if (!formPortScan) {
        console.error('[SCANNER] CRITICAL: #form-phase2 not found in DOM!');
    } else {
        formPortScan.addEventListener('submit', async (e) => {
            e.preventDefault();
            dbg('═══ Port Scanner submitted ═══');

            const target  = document.getElementById('p2-target').value.trim();
            const btn     = document.getElementById('btn-p2-scan');
            const btnText = btn.querySelector('.btn-text');

            if (!target) {
                showError('Please enter a target IP address or localhost');
                return;
            }

            UI.setButtonLoading(btn, true);
            if (btnText) btnText.textContent = 'Scanning...';
            document.getElementById('p2-results-panel').classList.add('hidden');

            try {
                UI.notify('Running Port Scanner…', 'info');

                const payload = await Api.startScan(target, 'port_scan');

                if (payload.status !== 'success') {
                    throw new Error(payload.message || 'Scan returned error status');
                }

                UI.notify('Port Scan completed ✓', 'success');
                const scanData = payload.data;
                renderPortScanResults(scanData.result || scanData, scanData);
                document.getElementById('p2-results-panel').classList.remove('hidden');
                await Promise.allSettled([loadOverview(), loadHistory()]);

            } catch (err) {
                showError(`Port Scan failed: ${err.message}`);
            } finally {
                UI.setButtonLoading(btn, false);
                if (btnText) btnText.textContent = 'Start Exposure Scan';
            }
        });
    }

    // ─────────────────────────────────────────────────────────
    // PORT SCANNER — result renderer
    // ─────────────────────────────────────────────────────────
    function renderPortScanResults(data, meta) {
        const panel    = document.getElementById('p2-results-panel');
        const summary  = data?.summary  || {};
        const hosts    = data?.hosts    || [];
        const scanInfo = data?.scan_info || {};
        const target   = meta?.target   || scanInfo.target || 'Unknown';

        let html = `
            <div class="result-section">
                <div class="result-section-header">
                    <span class="result-section-icon">📡</span>
                    <h3>Port Scanner Results</h3>
                    <div class="scan-meta-row">
                        <span class="meta-chip">🎯 Target: <strong>${target}</strong></span>
                        <span class="meta-chip">⏱ ${UI.formatDate(meta?.timestamp || scanInfo.timestamp)}</span>
                        <span class="meta-chip">Risk: ${UI.getRiskBadge(summary.risk_level || 'LOW')}</span>
                    </div>
                </div>
                <div class="metrics-grid phase2-metrics">
                    <div class="metric-card">
                        <div class="metric-title">Hosts Discovered</div>
                        <div class="metric-value">${summary.total_hosts || hosts.length || 0}</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-title">Open Ports</div>
                        <div class="metric-value">${summary.total_open_ports || 0}</div>
                    </div>
                    <div class="metric-card ${['CRITICAL','HIGH'].includes(summary.risk_level) ? 'alert' : ''}">
                        <div class="metric-title">Risk Level</div>
                        <div class="metric-value ${['CRITICAL','HIGH'].includes(summary.risk_level) ? 'text-danger' : ''}">${summary.risk_level || 'LOW'}</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-title">Risk Score</div>
                        <div class="metric-value">${summary.risk_score ?? '-'}</div>
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
            html += `<div class="result-section"><p class="empty-state">No open ports detected on the target.</p></div>`;
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
    // OS INSPECTION — form submit
    // ─────────────────────────────────────────────────────────
    const formOsInspect = document.getElementById('form-phase3');
    if (!formOsInspect) {
        console.error('[SCANNER] CRITICAL: #form-phase3 not found in DOM!');
    } else {
        formOsInspect.addEventListener('submit', async (e) => {
            e.preventDefault();
            dbg('═══ OS Inspection submitted ═══');

            const btn     = document.getElementById('btn-p3-scan');
            const btnText = btn.querySelector('.btn-text');

            UI.setButtonLoading(btn, true);
            if (btnText) btnText.textContent = 'Inspecting...';
            document.getElementById('p3-results-panel').classList.add('hidden');

            try {
                UI.notify('Running OS Inspection…', 'info');

                const payload = await Api.startScan('localhost', 'os_inspection');

                if (payload.status !== 'success') {
                    throw new Error(payload.message || 'Inspection returned error status');
                }

                UI.notify('OS Inspection completed ✓', 'success');
                const scanData = payload.data;
                renderOsInspectionResults(scanData.result || scanData, scanData);
                document.getElementById('p3-results-panel').classList.remove('hidden');
                await Promise.allSettled([loadOverview(), loadHistory()]);

            } catch (err) {
                showError(`OS Inspection failed: ${err.message}`);
            } finally {
                UI.setButtonLoading(btn, false);
                if (btnText) btnText.textContent = 'Start System Scan';
            }
        });
    }

    // ─────────────────────────────────────────────────────────
    // OS INSPECTION — result renderer
    // ─────────────────────────────────────────────────────────
    function renderOsInspectionResults(data, meta) {
        const container = document.getElementById('p3-categories');
        const summary   = data?.summary   || {};
        const scanInfo  = data?.scan_info || {};
        const results   = data?.results   || [];

        let html = `
            <div class="result-section">
                <div class="result-section-header">
                    <span class="result-section-icon">🔐</span>
                    <h3>OS Inspection Results</h3>
                    <div class="scan-meta-row">
                        <span class="meta-chip">⏱ ${UI.formatDate(meta?.timestamp || scanInfo.timestamp)}</span>
                        <span class="meta-chip">Checks: <strong>${summary.total_checks || results.length || 0}</strong></span>
                    </div>
                </div>
                <div class="metrics-grid phase3-metrics">
                    <div class="metric-card alert">
                        <div class="metric-title">Critical</div>
                        <div class="metric-value text-danger">${summary.critical || 0}</div>
                    </div>
                    <div class="metric-card warning">
                        <div class="metric-title">High</div>
                        <div class="metric-value text-warning">${summary.high || 0}</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-title">Medium</div>
                        <div class="metric-value">${summary.medium || 0}</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-title">Total Checks</div>
                        <div class="metric-value">${summary.total_checks || results.length || 0}</div>
                    </div>
                </div>
            </div>
        `;

        // Per-category results
        if (results.length > 0) {
            html += `<div class="result-section"><h4 class="result-sub-header">📂 Inspection Categories</h4>`;
            results.forEach(item => {
                const nvd = item.nvd || [];
                html += `
                    <div class="accordion-item">
                        <div class="accordion-header">
                            <span>${item.category || 'Unknown'}</span>
                            <span class="accordion-meta">
                                ${UI.getRiskBadge(item.risk || 'LOW')}
                                ${nvd.length > 0 ? `<span class="badge warning">${nvd.length} CVEs</span>` : ''}
                                <span class="accordion-icon">▼</span>
                            </span>
                        </div>
                        <div class="accordion-content">
                            <div class="category-details">
                                <p><strong>Status:</strong> ${item.status || '-'}</p>
                                <p><strong>Logic:</strong> ${item.analysis?.logic || '-'}</p>
                                <p><strong>Command:</strong> <code>${(item.command?.executed || '-').substring(0, 120)}</code></p>
                                ${nvd.length > 0 ? `
                                <div class="table-container" style="margin-top:.5rem">
                                    <table class="data-table">
                                        <thead><tr><th>CVE ID</th><th>Severity</th><th>Description</th></tr></thead>
                                        <tbody>
                                            ${nvd.map(c => `
                                                <tr>
                                                    <td><code class="cve-id">${c.cve_id || '-'}</code></td>
                                                    <td>${UI.getRiskBadge(c.severity || 'LOW')}</td>
                                                    <td class="description-cell">${(c.description || '-').substring(0, 200)}</td>
                                                </tr>`).join('')}
                                        </tbody>
                                    </table>
                                </div>` : ''}
                            </div>
                        </div>
                    </div>
                `;
            });
            html += `</div>`;
        } else {
            html += `<div class="result-section"><p class="empty-state">No inspection results returned.</p></div>`;
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
        const kb   = (new TextEncoder().encode(json).length / 1024).toFixed(1);
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

    const btnClearHistory = document.getElementById('btn-clear-history');
    if (btnClearHistory) {
        btnClearHistory.addEventListener('click', async () => {
            if (!confirm('This will delete all stored scan files. Continue?')) return;
            UI.notify('Clear scan history is not implemented in this build.', 'info');
        });
    }

    async function loadHistory() {
        dbg('Loading scan history…');
        try {
            const data = await Api.getScanHistory();
            dbg('History records', data.length);

            const tbody = document.querySelector('#history-table tbody');
            if (!tbody) { console.error('[SCANNER] #history-table tbody not found!'); return; }
            tbody.innerHTML = '';

            if (!data.length) {
                tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No scan history yet. Run a Port Scanner or OS Inspection scan to get started.</td></tr>';
                return;
            }

            data.forEach(scan => {
                const typeLabel = scan.scan_type === 'port_scan' ? '🔍 Port Scanner' : '🔐 OS Inspection';
                const tr = document.createElement('tr');
                tr.style.cursor = 'pointer';
                tr.innerHTML = `
                    <td><code>${scan.id}</code></td>
                    <td><span class="target-label">${scan.target}</span></td>
                    <td><span class="phase-badge">${typeLabel}</span></td>
                    <td>${UI.formatDate(scan.timestamp)}<br><small style="color:var(--text-muted)">${UI.timeAgo(new Date(scan.timestamp).getTime())}</small></td>
                    <td>${UI.getStatusBadge('Completed')}</td>
                    <td class="export-actions">
                        <button class="btn btn-sm btn-view-detail" data-id="${scan.id}">View</button>
                        <button class="btn btn-sm btn-secondary" data-id="${scan.id}" onclick="Api.downloadPdf('${scan.id}')">PDF</button>
                    </td>
                `;

                tr.querySelector('.btn-view-detail').addEventListener('click', async (ev) => {
                    ev.stopPropagation();
                    try {
                        const record = await Api.getScanDetails(scan.id);
                        showScanDetailModal(scan, record);
                    } catch (err) {
                        showError('Failed to load scan details: ' + err.message);
                    }
                });

                tr.addEventListener('click', async () => {
                    try {
                        const record = await Api.getScanDetails(scan.id);
                        showScanDetailModal(scan, record);
                    } catch (err) {
                        showError('Failed to load scan details: ' + err.message);
                    }
                });

                tbody.appendChild(tr);
            });

        } catch (err) {
            showError('Failed to load scan history: ' + err.message);
        }
    }

    // ─────────────────────────────────────────────────────────
    // Scan Detail Modal
    // ─────────────────────────────────────────────────────────
    function showScanDetailModal(scan, record) {
        const isPortScan = scan.scan_type === 'port_scan';
        const result     = record?.result || {};
        const summary    = result.summary || {};

        let summaryHtml = '';
        if (isPortScan) {
            summaryHtml = `
                <div class="modal-summary-grid">
                    <div class="modal-summary-card"><span>${summary.total_hosts || 0}</span><label>Hosts</label></div>
                    <div class="modal-summary-card"><span>${summary.total_open_ports || 0}</span><label>Open Ports</label></div>
                    <div class="modal-summary-card"><span>${UI.getRiskBadge(summary.risk_level || 'LOW')}</span><label>Risk</label></div>
                    <div class="modal-summary-card"><span>${summary.risk_score ?? '-'}</span><label>Score</label></div>
                </div>`;
        } else {
            summaryHtml = `
                <div class="modal-summary-grid">
                    <div class="modal-summary-card danger"><span>${summary.critical || 0}</span><label>Critical</label></div>
                    <div class="modal-summary-card warning"><span>${summary.high || 0}</span><label>High</label></div>
                    <div class="modal-summary-card"><span>${summary.medium || 0}</span><label>Medium</label></div>
                    <div class="modal-summary-card"><span>${summary.total_checks || 0}</span><label>Checks</label></div>
                </div>`;
        }

        const rawJson = record ? JSON.stringify(record, null, 2) : '{}';
        const typeLabel = isPortScan ? '🔍 Port Scanner' : '🔐 OS Inspection';

        const contentHtml = `
            <div class="scan-detail-modal">
                <div class="detail-meta-grid">
                    <div><strong>Scan ID:</strong> <code>${scan.id}</code></div>
                    <div><strong>Type:</strong> ${typeLabel}</div>
                    <div><strong>Target:</strong> ${scan.target}</div>
                    <div><strong>Status:</strong> ${UI.getStatusBadge('Completed')}</div>
                    <div><strong>Time:</strong> ${UI.formatDate(scan.timestamp)}</div>
                </div>
                ${summaryHtml}
                <div class="modal-actions" style="margin-top:1rem;">
                    <button class="btn btn-primary" onclick="Api.downloadPdf('${scan.id}')">📥 Download PDF Report</button>
                </div>
                <details class="raw-json-toggle" style="margin-top:1rem;">
                    <summary class="raw-json-summary"><span>{ } Full Record</span></summary>
                    <div class="raw-json-body">
                        <pre class="raw-json-pre">${escapeHtml(rawJson)}</pre>
                    </div>
                </details>
            </div>
        `;
        UI.showModal(`${typeLabel} — ${scan.id}`, contentHtml);
    }

}); // end DOMContentLoaded
