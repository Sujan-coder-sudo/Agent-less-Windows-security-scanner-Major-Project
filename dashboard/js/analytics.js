/**
 * analytics.js
 * Professional Security Analytics Dashboard
 * Executive-grade presentation with posture assessment and insights
 */

document.addEventListener('DOMContentLoaded', () => {
    const btnRefresh = document.getElementById('btn-refresh-analytics');
    if (btnRefresh) {
        btnRefresh.addEventListener('click', () => {
            btnRefresh.classList.add('loading-shimmer');
            fetchScanData().then(() => {
                setTimeout(() => btnRefresh.classList.remove('loading-shimmer'), 500);
            });
        });
    }

    document.getElementById('nav-list').addEventListener('click', (e) => {
        const link = e.target.closest('.nav-item');
        if (link && link.getAttribute('data-target') === 'analytics-section') {
            setTimeout(fetchScanData, 100);
        }
    });

    // Initial load if analytics is active
    setTimeout(() => {
        const activeSection = document.querySelector('.section.active');
        if (activeSection && activeSection.id === 'analytics-section') {
            fetchScanData();
        }
    }, 200);
});

// ── Fetch ──────────────────────────────────────────────────────────────────────

let riskChartInstance = null;
let currentScanData = null;

async function fetchScanData() {
    try {
        const response = await fetch(`${API_BASE}/scans/latest`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const res = await response.json();

        currentScanData = res.data || res;

        if (!currentScanData || !currentScanData.result) {
            renderEmptyState();
            return;
        }

        const scanType = currentScanData.scan_type || 'unknown';
        const result = currentScanData.result || {};
        const summary = result.summary || {};
        const data = result.data || result.results || [];

        // Render all dashboard components
        renderExecutiveSummary(currentScanData, scanType, summary);
        renderSummaryCards(scanType, summary);
        renderRiskChart(scanType, summary);
        renderRiskLegend(scanType, summary);
        renderTable(scanType, data);
        renderInsights(scanType, summary, data);
        
        UI.notify('Security analytics loaded', 'success');

    } catch (err) {
        console.error('[Analytics] fetchScanData error:', err);
        UI.notify('Failed to load analytics: ' + err.message, 'error');
        renderEmptyState();
    }
}

function renderEmptyState() {
    document.getElementById('exec-scan-type').textContent = 'NO DATA';
    document.getElementById('posture-score').textContent = '-';
    document.getElementById('posture-score').className = 'posture-score unknown';
    document.getElementById('exec-target').textContent = 'No scan data available';
    document.getElementById('exec-timestamp').textContent = '-';
    document.getElementById('exec-risk-score').textContent = '-';
    
    ['analytic-checks', 'analytic-critical', 'analytic-high', 'analytic-medium', 'analytic-low'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.textContent = '0';
    });
    
    document.getElementById('findings-count').textContent = '0 items';
    document.getElementById('insights-grid').innerHTML = '<div class="insight-card"><div class="insight-icon">📊</div><div class="insight-content"><h4>No Data Available</h4><p>Run a scan to see security analytics and insights.</p></div></div>';
}

// ── Executive Summary ───────────────────────────────────────────────────────────

function renderExecutiveSummary(scan, scanType, summary) {
    // Scan type badge
    const typeLabel = scanType === 'port_scan' ? 'Port Scan' : 
                      scanType === 'os_inspection' ? 'OS Inspection' : 'Unknown';
    document.getElementById('exec-scan-type').textContent = typeLabel;
    
    // Target and timestamp
    document.getElementById('exec-target').textContent = scan.target || 'localhost';
    document.getElementById('exec-timestamp').textContent = UI.formatDate(scan.timestamp);
    
    // Risk score and posture
    let riskScore, postureClass, postureText;
    
    if (scanType === 'port_scan') {
        riskScore = summary.risk_score || 0;
        const rd = summary.risk_distribution || {};
        const total = summary.total_findings || 1;
        const criticalHigh = (rd.Critical || 0) + (rd.High || 0);
        
        if (criticalHigh > 0 || riskScore >= 7) {
            postureClass = 'critical';
            postureText = 'CRITICAL';
        } else if (riskScore >= 4 || (rd.Medium || 0) > 0) {
            postureClass = 'high';
            postureText = 'HIGH RISK';
        } else if (riskScore > 0) {
            postureClass = 'medium';
            postureText = 'MEDIUM';
        } else {
            postureClass = 'low';
            postureText = 'LOW RISK';
        }
    } else {
        const critical = summary.critical || 0;
        const high = summary.high || 0;
        riskScore = critical > 0 ? 10 : high > 0 ? 7 : summary.medium > 0 ? 4 : 1;
        
        if (critical > 0) {
            postureClass = 'critical';
            postureText = 'CRITICAL';
        } else if (high > 0) {
            postureClass = 'high';
            postureText = 'HIGH RISK';
        } else if (summary.medium > 0) {
            postureClass = 'medium';
            postureText = 'MEDIUM';
        } else {
            postureClass = 'low';
            postureText = 'LOW RISK';
        }
    }
    
    const scoreEl = document.getElementById('posture-score');
    scoreEl.textContent = postureText;
    scoreEl.className = `posture-score ${postureClass}`;
    document.getElementById('exec-risk-score').textContent = `${riskScore}/10`;
}

// ── Summary Cards ──────────────────────────────────────────────────────────────

function renderSummaryCards(scanType, summary) {
    let checks, critical, high, medium, low;
    
    if (scanType === 'port_scan') {
        const rd = summary.risk_distribution || {};
        checks = summary.total_findings || 0;
        critical = rd.Critical || 0;
        high = rd.High || 0;
        medium = rd.Medium || 0;
        low = rd.Low || 0;
    } else {
        checks = summary.total_checks || 0;
        critical = summary.critical || 0;
        high = summary.high || 0;
        medium = summary.medium || 0;
        low = summary.low || 0;
    }
    
    _setCard('analytic-checks', checks);
    _setCard('analytic-critical', critical);
    _setCard('analytic-high', high);
    _setCard('analytic-medium', medium);
    _setCard('analytic-low', low);
    
    // Update findings count
    const totalFindings = critical + high + medium + low;
    document.getElementById('findings-count').textContent = `${totalFindings} ${totalFindings === 1 ? 'item' : 'items'}`;
}

function _setCard(id, val) {
    const el = document.getElementById(id);
    if (el) {
        // Animate number change
        const current = parseInt(el.textContent) || 0;
        const target = parseInt(val) || 0;
        animateNumber(el, current, target);
    }
}

function animateNumber(el, from, to) {
    const duration = 500;
    const start = performance.now();
    
    function update(now) {
        const elapsed = now - start;
        const progress = Math.min(elapsed / duration, 1);
        const current = Math.round(from + (to - from) * progress);
        el.textContent = current;
        
        if (progress < 1) {
            requestAnimationFrame(update);
        }
    }
    
    requestAnimationFrame(update);
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
            <div class="exposure-summary-box" style="margin-bottom:20px">
                <p><strong>Note:</strong> ${escapeHtml(item.note || 'N/A')}</p>
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
            <div class="exposure-summary-box" style="margin-bottom:20px">
                <p><strong>Summary:</strong> ${escapeHtml(item.analysis?.summary || 'N/A')}</p>
                <p style="margin-top:8px"><strong>Logic:</strong> ${escapeHtml(item.analysis?.logic || 'N/A')}</p>
            </div>
    `;

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

// ── Risk Legend ───────────────────────────────────────────────────────────────

function renderRiskLegend(scanType, summary) {
    const legend = document.getElementById('risk-legend');
    if (!legend) return;
    
    let critical, high, medium, low;
    
    if (scanType === 'port_scan') {
        const rd = summary.risk_distribution || {};
        critical = rd.Critical || 0;
        high = rd.High || 0;
        medium = rd.Medium || 0;
        low = rd.Low || 0;
    } else {
        critical = summary.critical || 0;
        high = summary.high || 0;
        medium = summary.medium || 0;
        low = summary.low || 0;
    }
    
    legend.innerHTML = `
        <div class="legend-item">
            <span class="legend-dot critical"></span>
            <span>Critical (${critical})</span>
        </div>
        <div class="legend-item">
            <span class="legend-dot high"></span>
            <span>High (${high})</span>
        </div>
        <div class="legend-item">
            <span class="legend-dot medium"></span>
            <span>Medium (${medium})</span>
        </div>
        <div class="legend-item">
            <span class="legend-dot low"></span>
            <span>Low (${low})</span>
        </div>
    `;
}

// ── Insights ────────────────────────────────────────────────────────────────────

function renderInsights(scanType, summary, data) {
    const grid = document.getElementById('insights-grid');
    if (!grid) return;
    
    const insights = [];
    
    if (scanType === 'port_scan') {
        const rd = summary.risk_distribution || {};
        const criticalHigh = (rd.Critical || 0) + (rd.High || 0);
        
        if (criticalHigh > 0) {
            insights.push({
                icon: '🚨',
                title: 'Critical Exposures Detected',
                text: `${criticalHigh} high-risk port exposure${criticalHigh > 1 ? 's' : ''} require immediate attention.`
            });
        }
        
        const openPorts = summary.open_ports || 0;
        if (openPorts > 10) {
            insights.push({
                icon: '🌐',
                title: 'Large Attack Surface',
                text: `${openPorts} open ports detected. Consider reviewing service necessity.`
            });
        }
        
        // Check for common risky services
        const riskyServices = data.filter(d => ['RDP', 'SMB', 'Telnet', 'FTP'].includes(d.service));
        if (riskyServices.length > 0) {
            insights.push({
                icon: '⚠️',
                title: 'High-Risk Services Exposed',
                text: `${riskyServices.length} potentially vulnerable service${riskyServices.length > 1 ? 's' : ''} detected (RDP/SMB/Telnet/FTP).`
            });
        }
        
        // CVE insights
        const withCves = data.filter(d => d.cves && d.cves.length > 0);
        if (withCves.length > 0) {
            insights.push({
                icon: '🛡️',
                title: 'CVE References Found',
                text: `${withCves.length} finding${withCves.length > 1 ? 's' : ''} ha${withCves.length > 1 ? 've' : 's'} known CVE associations. Review for patching priorities.`
            });
        }
        
    } else {
        // OS Inspection insights
        const critical = summary.critical || 0;
        const high = summary.high || 0;
        
        if (critical > 0) {
            insights.push({
                icon: '🔴',
                title: 'Critical System Issues',
                text: `${critical} critical configuration issue${critical > 1 ? 's' : ''} require immediate remediation.`
            });
        }
        
        if (high > 0) {
            insights.push({
                icon: '🟠',
                title: 'High-Risk Configurations',
                text: `${high} high-severity finding${high > 1 ? 's' : ''} should be addressed soon.`
            });
        }
        
        // Check for EDR/AV issues
        const edrIssues = data.filter(d => 
            d.category?.includes('EDR') || d.category?.includes('AV') || d.category?.includes('Defender')
        );
        if (edrIssues.length > 0 && edrIssues.some(d => d.risk === 'CRITICAL' || d.risk === 'HIGH')) {
            insights.push({
                icon: '🛡️',
                title: 'Endpoint Protection Gap',
                text: 'Endpoint protection issues detected. Review EDR/AV configuration.'
            });
        }
        
        // Check for missing patches
        const patchIssues = data.filter(d => d.category?.includes('Hotfix') || d.category?.includes('Patch'));
        if (patchIssues.length > 0) {
            insights.push({
                icon: '🔧',
                title: 'Patch Management',
                text: 'Missing security updates detected. Ensure regular patch deployment.'
            });
        }
        
        // Check for user/admin issues
        const userIssues = data.filter(d => d.category?.includes('User') || d.category?.includes('Admin'));
        if (userIssues.length > 0) {
            insights.push({
                icon: '👤',
                title: 'Account Security',
                text: 'Review privileged account configuration and access controls.'
            });
        }
    }
    
    // Default insight if none generated
    if (insights.length === 0) {
        insights.push({
            icon: '✅',
            title: 'No Major Issues',
            text: 'No critical or high-severity findings detected. Continue monitoring.'
        });
    }
    
    // Always add a recommendation
    insights.push({
        icon: '📋',
        title: 'Recommended Action',
        text: 'Generate and review the full PDF report for detailed findings and remediation guidance.'
    });
    
    grid.innerHTML = insights.map(insight => `
        <div class="insight-card">
            <div class="insight-icon">${insight.icon}</div>
            <div class="insight-content">
                <h4>${escapeHtml(insight.title)}</h4>
                <p>${escapeHtml(insight.text)}</p>
            </div>
        </div>
    `).join('');
}

// ── Utility ────────────────────────────────────────────────────────────────────

function escapeHtml(str) {
    if (!str) return '';
    if (typeof str !== 'string') return String(str);
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
