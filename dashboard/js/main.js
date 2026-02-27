/**
 * main.js
 * Main orchestration logic binding UI and API.
 */

document.addEventListener('DOMContentLoaded', () => {

    // --- Navigation Binding ---
    document.getElementById('nav-list').addEventListener('click', (e) => {
        const link = e.target.closest('.nav-item');
        if (link) {
            e.preventDefault();
            const target = link.getAttribute('data-target');
            UI.switchSection(target);

            // Lazy load section data based on selection
            if(target === 'overview-section') loadOverview();
            if(target === 'history-section') loadHistory();
        }
    });

    // --- Modal Binding ---
    document.getElementById('modal-close').addEventListener('click', UI.closeModal);
    document.getElementById('modal-close-btn').addEventListener('click', UI.closeModal);
    document.getElementById('details-modal').addEventListener('click', (e) => {
        if (e.target.id === 'details-modal') UI.closeModal();
    });

    // --- Load Initial Overview ---
    loadOverview();

    // -----------------------------------------------------
    // Controller: Overview Data Flow
    // -----------------------------------------------------
    async function loadOverview() {
        try {
            const data = await Api.getOverview();
            
            // Populate Metrics
            document.getElementById('metric-hosts').textContent = data.totalHosts;
            document.getElementById('metric-ports').textContent = data.openPorts;
            document.getElementById('metric-services').textContent = data.highRiskServices;
            document.getElementById('metric-hotfixes').textContent = data.missingHotfixes;
            document.getElementById('last-scan-time').textContent = UI.formatDate(data.lastScan);

            // Render Chart
            UI.renderVulnChart(data.vulnData);

            // Render Hosts Table
            const tbody = document.querySelector('#overview-hosts-table tbody');
            tbody.innerHTML = '';
            data.recentHosts.forEach(host => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>${host.ip}</td>
                    <td>${host.hostname}</td>
                    <td>${UI.getRiskBadge(host.risk)}</td>
                    <td>${UI.timeAgo(host.lastSeen)}</td>
                `;
                tbody.appendChild(tr);
            });

        } catch (err) {
            UI.notify('Failed to load dashboard overview', 'error');
            console.error(err);
        }
    }

    // -----------------------------------------------------
    // Controller: Phase 2 orchestration
    // -----------------------------------------------------
    document.getElementById('form-phase2').addEventListener('submit', async (e) => {
        e.preventDefault();
        const target = document.getElementById('p2-target').value;
        const type = document.getElementById('p2-type').value;
        const btn = document.getElementById('btn-p2-scan');

        UI.setButtonLoading(btn, true);
        document.getElementById('p2-results-panel').classList.add('hidden');

        try {
            // 1. Trigger Job
            const startRes = await Api.startPhase2Scan(target, type);
            UI.notify(startRes.message, 'info');

            // 2. Poll for Phase 2 completion
            // In a real app, use setInterval polling. Given mock is fast, just await.
            const pollRes = await Api.pollPhase2Status(startRes.jobId);
            
            if(pollRes.status === 'completed') {
                UI.notify('Phase 2 Scan Completed', 'success');
                
                // Render Table
                const tbody = document.querySelector('#p2-results-table tbody');
                tbody.innerHTML = '';
                pollRes.results.forEach(res => {
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${res.ip}</td>
                        <td>${res.hostname}</td>
                        <td>${UI.getStatusBadge(res.status)}</td>
                        <td><span class="text-warning">${res.openPorts}</span> tcp</td>
                    `;
                    tbody.appendChild(tr);
                });

                document.getElementById('p2-results-panel').classList.remove('hidden');
            }

        } catch (err) {
            UI.notify(err.message, 'error');
        } finally {
            UI.setButtonLoading(btn, false);
        }
    });

    // -----------------------------------------------------
    // Controller: Phase 3 orchestration
    // -----------------------------------------------------
    document.getElementById('form-phase3').addEventListener('submit', async (e) => {
        e.preventDefault();
        const target = document.getElementById('p3-target').value;
        const user = document.getElementById('p3-user').value;
        const pass = document.getElementById('p3-pass').value; // In a real app don't log this!
        const domain = document.getElementById('p3-domain').value || 'WORKGROUP';
        const btn = document.getElementById('btn-p3-scan');

        UI.setButtonLoading(btn, true);
        document.getElementById('p3-results-panel').classList.add('hidden');

        try {
            // 1. Trigger Job
            const startRes = await Api.startPhase3Scan(target, user, pass, domain);
            UI.notify(startRes.message, 'info');

            // 2. Poll completion
            const pollRes = await Api.pollPhase3Status(startRes.jobId);

            if (pollRes.status === 'completed') {
                UI.notify('Phase 3 Inspection Completed successfully', 'success');
                
                // Render categories using accordion UI
                const container = document.getElementById('p3-categories');
                container.innerHTML = '';

                Object.entries(pollRes.categories).forEach(([name, data]) => {
                    const item = document.createElement('div');
                    item.className = 'accordion-item';
                    
                    const header = document.createElement('div');
                    header.className = 'accordion-header';
                    header.innerHTML = `<span>${name}</span> <span class="accordion-icon">▼</span>`;
                    
                    const contentWrap = document.createElement('div');
                    contentWrap.className = 'accordion-content';
                    
                    // JSON format snippet for data
                    const pre = document.createElement('pre');
                    pre.textContent = JSON.stringify(data, null, 2);
                    contentWrap.appendChild(pre);

                    item.appendChild(header);
                    item.appendChild(contentWrap);

                    // Accordion toggle logic
                    header.addEventListener('click', () => {
                        item.classList.toggle('open');
                    });

                    container.appendChild(item);
                });

                document.getElementById('p3-results-panel').classList.remove('hidden');
            }
        } catch(err) {
            UI.notify(err.message, 'error');
        } finally {
            UI.setButtonLoading(btn, false);
        }
    });

    // -----------------------------------------------------
    // Controller: Scan History
    // -----------------------------------------------------
    document.getElementById('btn-refresh-history').addEventListener('click', loadHistory);

    async function loadHistory() {
        try {
            const data = await Api.getScanHistory();
            const tbody = document.querySelector('#history-table tbody');
            tbody.innerHTML = '';

            data.forEach(scan => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td>#${scan.id}</td>
                    <td><span style="color:var(--text-main);font-weight:600;">${scan.target}</span></td>
                    <td>${scan.phase}</td>
                    <td>${UI.timeAgo(scan.timestamp)} (${UI.formatDate(scan.timestamp)})</td>
                    <td>${UI.getStatusBadge(scan.status)}</td>
                `;
                
                // Clicking row opens modal
                tr.addEventListener('click', async () => {
                    UI.notify(`Loading DB Object for scan #${scan.id}...`);
                    const details = await Api.getScanDetails(scan.id);
                    
                    const html = `
                        <div style="margin-bottom: 16px;">
                            <strong>Raw Database Data Extract for ID ${scan.id}</strong>
                        </div>
                        <pre>${details.rawJson}</pre>
                    `;
                    UI.showModal(`Scan Report - ID ${scan.id}`, html);
                });

                tbody.appendChild(tr);
            });
        } catch (err) {
            UI.notify('Failed to load scan history', 'error');
        }
    }

});
