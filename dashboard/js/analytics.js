/**
 * analytics.js
 * Handles fetching JSON scan reports, rendering summary cards, 
 * Risk Distribution donut chart, category table, and drill-down modals.
 */

document.addEventListener('DOMContentLoaded', () => {
    // Only load if the analytics section is clicked or active
    // We bind to the nav item click, but also run immediately in case it's default
    const btnRefresh = document.getElementById('btn-refresh-analytics');
    if (btnRefresh) {
        btnRefresh.addEventListener('click', fetchScanData);
    }

    // Trigger loading when navigating to analytics
    document.getElementById('nav-list').addEventListener('click', (e) => {
        const link = e.target.closest('.nav-item');
        if (link && link.getAttribute('data-target') === 'analytics-section') {
            fetchScanData();
        }
    });

    // Check if we start on analytics section
    const activeSection = document.querySelector('.section.active');
    if (activeSection && activeSection.id === 'analytics-section') {
        fetchScanData();
    }
});

let riskChartInstance = null;
let currentScanData = null; // Store for modal drill-downs

async function fetchScanData() {
    try {
        dbg('Fetching analytics scan data...');
        // Try the API first (if available) - Assuming an endpoint /api/scans/latest
        // The user suggested GET /api/scans/latest or mock_data.json
        // Let's first try to get the real Phase 3 data or fallback to a known location
        
        let reportData = null;
        const response = await fetch(`${API_BASE}/scans/latest`);
        if (response.ok) {
            const res = await response.json();
            reportData = res.data || res;
        } else {
            throw new Error(`Failed to load data from API: HTTP ${response.status}`);
        }
        
        // Handle array wrap issue (scan_report.json comes as array of reports)
        if (Array.isArray(reportData)) {
            // Get the most recent one (last in array usually, or sort by timestamp)
            const sorted = reportData.sort((a,b) => new Date(b.scan_info.timestamp) - new Date(a.scan_info.timestamp));
            currentScanData = sorted[0];
        } else {
            currentScanData = reportData;
        }

        if (currentScanData) {
            dbg('Analytics data loaded', currentScanData);
            renderSummaryCards(currentScanData.summary);
            renderRiskChart(currentScanData.summary);
            renderTable(currentScanData.results);
            UI.notify('Analytics data loaded successfully', 'success');
        } else {
            UI.notify('No scan data available', 'warning');
        }

    } catch (err) {
        console.error('Failed to load analytics data:', err);
        UI.notify('Failed to load scan data: ' + err.message, 'error');
    }
}

function renderSummaryCards(summary) {
    if (!summary) return;
    
    document.getElementById('analytic-checks').textContent = summary.total_vulnerabilities || summary.total_checks || 0;
    document.getElementById('analytic-critical').textContent = summary.critical_count || summary.critical || 0;
    document.getElementById('analytic-high').textContent = summary.high_count || summary.high || 0;
    document.getElementById('analytic-medium').textContent = summary.medium_count || summary.medium || 0;
    document.getElementById('analytic-low').textContent = summary.low_count || summary.low || 0;
}

function renderRiskChart(summary) {
    if (!summary) return;
    
    const ctx = document.getElementById('risk-donut-chart').getContext('2d');
    
    // Destroy existing chart if present
    if (riskChartInstance) {
        riskChartInstance.destroy();
    }
    
    // Determine colors based on CSS variables or hex
    const chartColors = [
        '#ff3366', // Critical (Red)
        '#ffb84d', // High (Orange/Yellow)
        '#f5d142', // Medium (Yellow)
        '#00ff66'  // Low (Green)
    ];

    riskChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [
                    summary.critical_count || summary.critical || 0, 
                    summary.high_count || summary.high || 0, 
                    summary.medium_count || summary.medium || 0, 
                    summary.low_count || summary.low || 0
                ],
                backgroundColor: chartColors,
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: '70%',
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#e2e8f0', // text-main
                        font: {
                            family: "'Inter', sans-serif",
                            size: 13
                        }
                    }
                },
                tooltip: {
                    backgroundColor: '#131a28', // bg-panel
                    titleColor: '#e2e8f0',
                    bodyColor: '#8a9bbd',
                    borderColor: 'rgba(138, 155, 189, 0.2)',
                    borderWidth: 1,
                    cornerRadius: 4
                }
            }
        }
    });
}

function renderTable(results) {
    const tbody = document.querySelector('#analytics-table tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    
    if (!results || results.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No findings available.</td></tr>';
        return;
    }
    
    results.forEach((result, index) => {
        const tr = document.createElement('tr');
        
        // Extract key finding (first item in findings array, or object values)
        let keyFinding = '';
        if (result.findings) {
            if (Array.isArray(result.findings)) {
                keyFinding = result.findings[0] || 'N/A';
            } else if (typeof result.findings === 'object') {
                const keys = Object.keys(result.findings);
                if (keys.length > 0) {
                    const firstVal = result.findings[keys[0]];
                    keyFinding = Array.isArray(firstVal) ? `${keys[0]}: ${firstVal.join(', ')}` : `${keys[0]}: ${firstVal}`;
                }
            }
        }
        
        // Truncate keyFinding if too long
        if (keyFinding.length > 60) {
            keyFinding = keyFinding.substring(0, 60) + '...';
        }
        
        tr.innerHTML = `
            <td><strong>${result.category || '-'}</strong></td>
            <td>${UI.getRiskBadge(result.risk || 'LOW')}</td>
            <td>${UI.getStatusBadge(result.status || 'unknown')}</td>
            <td><code style="font-size: 11px;">${escapeHtml(keyFinding) || '-'}</code></td>
            <td>
                <button class="btn btn-sm btn-primary btn-view-details" data-index="${index}">View Details</button>
            </td>
        `;
        
        tbody.appendChild(tr);
    });
    
    // Bind detail buttons
    document.querySelectorAll('.btn-view-details').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const index = e.currentTarget.getAttribute('data-index');
            renderModal(results[index]);
        });
    });
}

function renderModal(result) {
    if (!result) return;
    
    const categoryStr = result.category || 'Details';
    
    let html = `
        <div class="result-section">
            <div class="result-section-header">
                <h3>${categoryStr} Analysis</h3>
                <div class="scan-meta-row">
                    <span class="meta-chip">Risk: ${UI.getRiskBadge(result.risk || 'LOW')}</span>
                    <span class="meta-chip">Status: ${UI.getStatusBadge(result.status || 'unknown')}</span>
                </div>
            </div>
            
            <div class="exposure-summary-box" style="margin-bottom: 20px;">
                <p><strong>Summary:</strong> ${result.analysis?.summary || 'N/A'}</p>
                <p style="margin-top: 8px;"><strong>Logic:</strong> ${result.analysis?.logic || 'N/A'}</p>
            </div>
    `;
    
    // CVE Insights Panel
    if (result.nvd && result.nvd.length > 0) {
        html += `
            <div class="result-section">
                <h4 class="result-sub-header">🛡 CVE Insights (${result.nvd.length})</h4>
                <div class="cve-accordion-container">
        `;
        
        result.nvd.forEach((cve, i) => {
            html += `
                <div class="accordion-item">
                    <div class="accordion-header">
                        <span><strong>${cve.cve_id || cve.id || 'Unknown CVE'}</strong> - ${UI.getRiskBadge(cve.severity || 'LOW')}</span>
                        <span class="accordion-icon">▼</span>
                    </div>
                    <div class="accordion-content">
                        <p style="color: var(--text-main); line-height: 1.6; font-size: 13px;">
                            ${cve.description || 'No description available.'}
                        </p>
                    </div>
                </div>
            `;
        });
        
        html += `
                </div>
            </div>
        `;
    }
    
    // Full JSON Findings
    const jsonStr = JSON.stringify(result.findings || {}, null, 2);
    html += `
        <div class="result-section raw-json-section" style="margin-top: 24px;">
            <details class="raw-json-toggle" open> <!-- Open by default for drill-down -->
                <summary class="raw-json-summary">
                    <span>{ } Full Findings Data</span>
                </summary>
                <div class="raw-json-body" style="margin-top: 10px;">
                    <pre class="raw-json-pre">${escapeHtml(jsonStr)}</pre>
                </div>
            </details>
        </div>
    `;
    
    html += `</div>`; // Close main wrapper
    
    UI.showModal(`Finding Details: ${categoryStr}`, html);
    
    // Re-bind accordion clicks inside modal
    const modalBody = document.getElementById('modal-body');
    if (modalBody) {
        modalBody.querySelectorAll('.accordion-header').forEach(h => {
            h.addEventListener('click', () => {
                h.closest('.accordion-item').classList.toggle('open');
            });
        });
    }
}

// Ensure escapeHtml exists here or rely on main.js if it's available globally.
// Defining a fallback just in case:
function escapeHtml(str) {
    if (!str) return '';
    if (typeof str !== 'string') return str.toString();
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
