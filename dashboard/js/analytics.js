/**
 * analytics.js
 * Renders analytics section using the unified API result shape:
 *   latest.result = { summary: {...}, data: [...] }
 *
 * scan_type === 'port_scan':
 *   summary: { total_findings, open_ports, risk_score, risk_distribution:{Critical,High,Medium,Low} }
 *   data:    [ { port, state, issue, risk, note, cves:[...] }, ... ]
 *
 * scan_type === 'os_inspection':
 *   summary: { total_checks, critical, high, medium, low, failed }
 *   data:    [ { category, status, risk, findings:{...}, analysis:{...}, nvd:[...] }, ... ]
 */

document.addEventListener('DOMContentLoaded', () => {
    const btnRefresh = document.getElementById('btn-refresh-analytics');
    if (btnRefresh) {
        btnRefresh.addEventListener('click', fetchScanData);
    }

    document.getElementById('nav-list').addEventListener('click', (e) => {
        const link = e.target.closest('.nav-item');
        if (link && link.getAttribute('data-target') === 'analytics-section') {
            fetchScanData();
        }
    });

    const activeSection = document.querySelector('.section.active');
    if (activeSection && activeSection.id === 'analytics-section') {
        fetchScanData();
    }
});

let riskChartInstance = null;
let currentScanData   = null;

// ── Fetch ──────────────────────────────────────────────────────────────────────

async function fetchScanData() {
    try {
        const response = await fetch(`${API_BASE}/scans/latest`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const res = await response.json();

        // API envelope: { status:"success", data: { scan_id, scan_type, target, timestamp, result } }
        currentScanData = res.data || res;

        if (!currentScanData || !currentScanData.result) {
            UI.notify('No scan data available yet.', 'info');
            return;
        }

        const scanType = currentScanData.scan_type || 'unknown';
        const result   = currentScanData.result    || {};
        const summary  = result.summary            || {};
        const data     = result.data               || [];

        renderMetaHeader(currentScanData);
        renderSummaryCards(scanType, summary);
        renderRiskChart(scanType, summary);
        renderTable(scanType, data);
        UI.notify('Analytics data loaded', 'success');

    } catch (err) {
        console.error('[Analytics] fetchScanData error:', err);
        UI.notify('Failed to load analytics: ' + err.message, 'error');
    }
}

// ── Meta header ────────────────────────────────────────────────────────────────

function renderMetaHeader(scan) {
    const el = document.getElementById('analytics-meta');
    if (!el) return;
    const label = UI.getScanTypeLabel(scan.scan_type);
    el.innerHTML = `
        <span class="meta-chip">${label}</span>
        <span class="meta-chip">🎯 ${scan.target || 'N/A'}</span>
        <span class="meta-chip">🕒 ${UI.formatDate(scan.timestamp)}</span>
    `;
}

// ── Summary cards ──────────────────────────────────────────────────────────────

function renderSummaryCards(scanType, summary) {
    if (scanType === 'port_scan') {
        const rd = summary.risk_distribution || {};
        _setCard('analytic-checks',   summary.total_findings || 0);
        _setCard('analytic-critical', rd.Critical            || 0);
        _setCard('analytic-high',     rd.High                || 0);
        _setCard('analytic-medium',   rd.Medium              || 0);
        _setCard('analytic-low',      rd.Low                 || 0);
    } else {
        // os_inspection
        _setCard('analytic-checks',   summary.total_checks || 0);
        _setCard('analytic-critical', summary.critical      || 0);
        _setCard('analytic-high',     summary.high          || 0);
        _setCard('analytic-medium',   summary.medium        || 0);
        _setCard('analytic-low',      summary.low           || 0);
    }
}

function _setCard(id, val) {
    const el = document.getElementById(id);
    if (el) el.textContent = val;
}

// ── Risk donut chart ───────────────────────────────────────────────────────────

function renderRiskChart(scanType, summary) {
    const canvas = document.getElementById('risk-donut-chart');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    if (riskChartInstance) {
        riskChartInstance.destroy();
        riskChartInstance = null;
    }

    let critical = 0, high = 0, medium = 0, low = 0;

    if (scanType === 'port_scan') {
        const rd = summary.risk_distribution || {};
        critical = rd.Critical || 0;
        high     = rd.High     || 0;
        medium   = rd.Medium   || 0;
        low      = rd.Low      || 0;
    } else {
        critical = summary.critical || 0;
        high     = summary.high     || 0;
        medium   = summary.medium   || 0;
        low      = summary.low      || 0;
    }

    riskChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [critical, high, medium, low],
                backgroundColor: ['#ff3366', '#ffb84d', '#f5d142', '#00ff66'],
                borderWidth: 0,
                hoverOffset: 4,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '70%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: { color: '#e2e8f0', font: { family: "'Inter', sans-serif", size: 13 } },
                },
                tooltip: {
                    backgroundColor: '#131a28',
                    titleColor: '#e2e8f0',
                    bodyColor: '#8a9bbd',
                    borderColor: 'rgba(138,155,189,0.2)',
                    borderWidth: 1,
                    cornerRadius: 4,
                },
            },
        },
    });
}

// ── Results table ──────────────────────────────────────────────────────────────

function renderTable(scanType, data) {
    const tbody = document.querySelector('#analytics-table tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (!data || !data.length) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No findings available.</td></tr>';
        return;
    }

    if (scanType === 'port_scan') {
        _renderPortTable(tbody, data);
    } else {
        _renderOsTable(tbody, data);
    }
}

function _renderPortTable(tbody, data) {
    data.forEach((item, idx) => {
        const tr = document.createElement('tr');
        const portLabel = item.port ? `Port ${item.port}` : '-';
        const issue     = item.issue  || item.service || '-';
        const snippet   = item.note   || (item.cves && item.cves[0]) || '-';
        const truncated = String(snippet).length > 60 ? String(snippet).substring(0, 60) + '…' : snippet;

        tr.innerHTML = `
            <td><strong>${portLabel}</strong></td>
            <td>${UI.getRiskBadge(item.risk || 'Low')}</td>
            <td>${UI.getStatusBadge(item.state || 'unknown')}</td>
            <td><code style="font-size:11px">${escapeHtml(issue)}</code></td>
            <td><button class="btn btn-sm btn-primary btn-view-details" data-index="${idx}">View</button></td>
        `;
        tbody.appendChild(tr);
    });
    _bindDetailButtons(data, _renderPortModal);
}

function _renderOsTable(tbody, data) {
    data.forEach((item, idx) => {
        const tr = document.createElement('tr');
        const summary = item.analysis?.summary || '-';
        const truncated = summary.length > 60 ? summary.substring(0, 60) + '…' : summary;

        tr.innerHTML = `
            <td><strong>${item.category || '-'}</strong></td>
            <td>${UI.getRiskBadge(item.risk || 'LOW')}</td>
            <td>${UI.getStatusBadge(item.status || 'unknown')}</td>
            <td><code style="font-size:11px">${escapeHtml(truncated)}</code></td>
            <td><button class="btn btn-sm btn-primary btn-view-details" data-index="${idx}">View</button></td>
        `;
        tbody.appendChild(tr);
    });
    _bindDetailButtons(data, _renderOsModal);
}

function _bindDetailButtons(data, renderFn) {
    document.querySelectorAll('.btn-view-details').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const idx = parseInt(e.currentTarget.getAttribute('data-index'), 10);
            renderFn(data[idx]);
        });
    });
}

// ── Modals ─────────────────────────────────────────────────────────────────────

function _renderPortModal(item) {
    const title = `Port ${item.port || '?'} — ${item.issue || 'Finding'}`;
    let html = `
        <div class="result-section">
            <div class="result-section-header">
                <h3>${escapeHtml(item.issue || 'Port Finding')}</h3>
                <div class="scan-meta-row">
                    <span class="meta-chip">Port: ${item.port || '-'}</span>
                    <span class="meta-chip">State: ${UI.getStatusBadge(item.state || 'unknown')}</span>
                    <span class="meta-chip">Risk: ${UI.getRiskBadge(item.risk || 'Low')}</span>
                </div>
            </div>
            <div class="exposure-summary-box" style="margin-bottom:20px; display: flex; flex-direction: column; gap: 10px;">
                <p style="margin:0; color: #e2e8f0; line-height: 1.5;"><strong>Note:</strong> ${escapeHtml(item.note || 'N/A')}</p>
            </div>
    `;

    // CVEs
    const cves = Array.isArray(item.cves) ? item.cves : [];
    if (cves.length) {
        html += `<div class="result-section"><h4 class="result-sub-header">🛡 Referenced CVEs (${cves.length})</h4><ul style="padding-left:20px;color:var(--text-muted);font-size:13px">`;
        cves.forEach(c => { html += `<li>${escapeHtml(String(c))}</li>`; });
        html += `</ul></div>`;
    }

    html += `<div class="result-section raw-json-section" style="margin-top:24px">
        <details class="raw-json-toggle" open>
            <summary class="raw-json-summary"><span>{ } Raw Finding</span></summary>
            <div class="raw-json-body" style="margin-top:10px">
                <pre class="raw-json-pre">${escapeHtml(JSON.stringify(item, null, 2))}</pre>
            </div>
        </details>
    </div></div>`;

    UI.showModal(title, html);
}

function _renderOsModal(item) {
    const title = `${item.category || 'Finding'} — OS Inspection`;
    let html = `
        <div class="result-section">
            <div class="result-section-header">
                <h3>${escapeHtml(item.category || 'Check')}</h3>
                <div class="scan-meta-row">
                    <span class="meta-chip">Risk: ${UI.getRiskBadge(item.risk || 'LOW')}</span>
                    <span class="meta-chip">Status: ${UI.getStatusBadge(item.status || 'unknown')}</span>
                </div>
            </div>
            <div class="exposure-summary-box" style="margin-bottom:20px; display: flex; flex-direction: column; gap: 10px;">
                <p style="margin:0; color: #e2e8f0; line-height: 1.5;"><strong>Summary:</strong> ${escapeHtml(item.analysis?.summary || 'N/A')}</p>
                <p style="margin:0; color: #e2e8f0; line-height: 1.5;"><strong>Logic:</strong> ${escapeHtml(item.analysis?.logic || 'N/A')}</p>
            </div>
    `;

    // MITRE ATT&CK
    if (item.mitre && item.mitre.id) {
        let mitreUrlId = item.mitre.id;
        if (mitreUrlId.includes('.')) {
            const parts = mitreUrlId.split('.');
            mitreUrlId = parts[0] + '/' + parts[1];
        }
        html += `
        <div class="result-section">
            <h4 class="result-sub-header">🎯 MITRE ATT&CK Mapping</h4>
            <div class="exposure-summary-box" style="margin-bottom:20px; border-left: 4px solid #8e44ad; background-color: rgba(142, 68, 173, 0.05); display: flex; flex-direction: column; gap: 8px; padding: 12px 16px;">
                <div style="display: flex; gap: 10px;">
                    <span style="min-width: 80px; font-weight: 600; color: #a8b2c1;">ID:</span> 
                    <a href="https://attack.mitre.org/techniques/${escapeHtml(mitreUrlId)}" target="_blank" style="color:#a855f7; text-decoration:underline;">${escapeHtml(item.mitre.id)}</a>
                </div>
                <div style="display: flex; gap: 10px;">
                    <span style="min-width: 80px; font-weight: 600; color: #a8b2c1;">Tactic:</span> 
                    <span style="color: #e2e8f0;">${escapeHtml(item.mitre.tactic)}</span>
                </div>
                <div style="display: flex; gap: 10px;">
                    <span style="min-width: 80px; font-weight: 600; color: #a8b2c1;">Technique:</span> 
                    <span style="color: #e2e8f0;">${escapeHtml(item.mitre.technique)}</span>
                </div>
            </div>
        </div>`;
    }

    // Remediation Insights
    if (item.remediation && item.remediation.advice) {
        html += `
        <div class="result-section">
            <h4 class="result-sub-header">💡 Remediation Insights</h4>
            <div class="exposure-summary-box" style="margin-bottom:20px; border-left: 4px solid #10b981; background-color: rgba(16, 185, 129, 0.05); padding: 12px 16px;">
                <p style="color: #e2e8f0; line-height: 1.5; margin-bottom: 12px;"><strong>Advice:</strong> ${escapeHtml(item.remediation.advice)}</p>
                <div style="background-color: #0d1117; padding: 10px; border-radius: 4px; border: 1px solid #30363d;">
                    <p style="font-size: 11px; color: #8b949e; margin-bottom: 5px; text-transform: uppercase;">PowerShell Fix Script</p>
                    <code style="color: #10b981; font-family: 'JetBrains Mono', monospace; font-size: 13px;">${escapeHtml(item.remediation.script || 'Manual intervention required.')}</code>
                </div>
            </div>
        </div>`;
    }

    // NVD CVEs
    const nvd = Array.isArray(item.nvd) ? item.nvd : [];
    if (nvd.length) {
        html += `<div class="result-section"><h4 class="result-sub-header">🛡 CVE Insights (${nvd.length})</h4><div class="cve-accordion-container">`;
        nvd.forEach(cve => {
            html += `
                <div class="accordion-item">
                    <div class="accordion-header">
                        <span><strong>${escapeHtml(cve.cve_id || cve.id || 'Unknown')}</strong> — ${UI.getRiskBadge(cve.severity || 'LOW')}</span>
                        <span class="accordion-icon">▼</span>
                    </div>
                    <div class="accordion-content">
                        <p style="color:var(--text-main);line-height:1.6;font-size:13px">${escapeHtml(cve.description || 'No description.')}</p>
                    </div>
                </div>`;
        });
        html += `</div></div>`;
    }

    // Findings JSON
    html += `<div class="result-section raw-json-section" style="margin-top:24px">
        <details class="raw-json-toggle" open>
            <summary class="raw-json-summary"><span>{ } Full Findings Data</span></summary>
            <div class="raw-json-body" style="margin-top:10px">
                <pre class="raw-json-pre">${escapeHtml(JSON.stringify(item.findings || {}, null, 2))}</pre>
            </div>
        </details>
    </div></div>`;

    UI.showModal(title, html);

    // Accordion toggle
    const modalBody = document.getElementById('modal-body');
    if (modalBody) {
        modalBody.querySelectorAll('.accordion-header').forEach(h => {
            h.addEventListener('click', () => h.closest('.accordion-item').classList.toggle('open'));
        });
    }
}

// ── Utility ────────────────────────────────────────────────────────────────────

function escapeHtml(str) {
    if (!str) return '';
    if (typeof str !== 'string') return String(str);
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
