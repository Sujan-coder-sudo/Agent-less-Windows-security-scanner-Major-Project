/**
 * ui.js
 * Handles DOM manipulation, state rendering, and reusable UI components.
 */

const UI = {
    // Show notification banners
    notify(msg, type = 'info') {
        const container = document.getElementById('notification-container');
        if (!container) return;
        const notif = document.createElement('div');
        notif.className = `notification ${type}`;

        let icon = 'ℹ️';
        if (type === 'error')   icon = '🚨';
        if (type === 'success') icon = '✅';

        notif.innerHTML = `
            <span>${icon} ${msg}</span>
            <button class="close-btn">&times;</button>
        `;

        container.appendChild(notif);

        notif.querySelector('.close-btn').addEventListener('click', () => notif.remove());

        setTimeout(() => {
            if (document.body.contains(notif)) notif.remove();
        }, 5000);
    },

    // Navigation orchestration
    switchSection(targetId) {
        document.querySelectorAll('.nav-item').forEach(el => {
            el.classList.remove('active');
            if (el.getAttribute('data-target') === targetId) el.classList.add('active');
        });
        document.querySelectorAll('.section').forEach(el => {
            el.classList.remove('active');
            if (el.id === targetId) el.classList.add('active');
        });
    },

    // Loading button state
    setButtonLoading(btnEl, isLoading) {
        if (!btnEl) return;
        const textSpan = btnEl.querySelector('.btn-text');
        const spinner  = btnEl.querySelector('.spinner');
        if (isLoading) {
            btnEl.disabled = true;
            if (spinner)  spinner.classList.remove('hidden');
        } else {
            btnEl.disabled = false;
            if (spinner)  spinner.classList.add('hidden');
        }
    },

    // Render bar chart for overview
    renderVulnChart(data) {
        const chartContainer = document.getElementById('vuln-chart');
        if (!chartContainer) return;
        chartContainer.innerHTML = '';

        if (!data || !data.length) return;

        const maxVal = Math.max(...data.map(d => d.value), 1);

        data.forEach(item => {
            const heightPercent = (item.value / maxVal) * 100;

            const col = document.createElement('div');
            col.className = 'bar-col';

            const bar = document.createElement('div');
            bar.className = 'bar';
            bar.style.height = '0%';
            if (item.color) {
                bar.style.background  = `linear-gradient(0deg, rgba(0,0,0,0) 0%, ${item.color} 100%)`;
                bar.style.boxShadow   = `inset 0 0 10px ${item.color}`;
            }

            const val = document.createElement('div');
            val.className   = 'bar-val';
            val.textContent = item.value;

            const label = document.createElement('div');
            label.className   = 'bar-label';
            label.textContent = item.label;

            bar.appendChild(val);
            col.appendChild(bar);
            col.appendChild(label);
            chartContainer.appendChild(col);

            requestAnimationFrame(() => {
                setTimeout(() => {
                    bar.style.height = `${Math.max(heightPercent, 5)}%`;
                }, 100);
            });
        });
    },

    // Risk badge
    getRiskBadge(riskStr = 'LOW') {
        const r = riskStr.toUpperCase();
        let type = 'info';
        if (r === 'CRITICAL') type = 'danger';
        else if (r === 'HIGH')   type = 'danger';
        else if (r === 'MEDIUM') type = 'warning';
        else if (r === 'LOW')    type = 'success';
        return `<span class="status-badge ${type}">${riskStr}</span>`;
    },

    // Status badge
    getStatusBadge(statusStr = '') {
        let type = 'info';
        const s = statusStr.toLowerCase();
        if (s.includes('success') || s.includes('completed') || s.includes('up')) type = 'success';
        if (s.includes('fail') || s.includes('error')) type = 'danger';
        return `<span class="status-badge ${type}">${statusStr}</span>`;
    },

    // Scan type label helper
    getScanTypeLabel(scanType) {
        if (scanType === 'port_scan')      return '🔍 Port Scanner';
        if (scanType === 'os_inspection')  return '🔐 OS Inspection';
        return scanType || 'Unknown';
    },

    // Modal
    showModal(title, contentHtml) {
        const modal = document.getElementById('details-modal');
        if (!modal) return;
        document.getElementById('modal-title').textContent  = title;
        document.getElementById('modal-body').innerHTML     = contentHtml;
        modal.classList.remove('hidden');
    },

    closeModal() {
        const modal = document.getElementById('details-modal');
        if (modal) modal.classList.add('hidden');
    },

    // Relative time
    timeAgo(ts) {
        if (ts === undefined || ts === null || ts === '') return 'N/A';
        const timestamp = Number(ts);
        if (!Number.isFinite(timestamp)) return 'N/A';

        const diffMs = timestamp - Date.now();
        if (!Number.isFinite(diffMs)) return 'N/A';

        try {
            const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
            const days    = Math.round(diffMs / 86400000);
            const hours   = Math.round(diffMs / 3600000);
            const minutes = Math.round(diffMs / 60000);

            if (Math.abs(days)  > 0)  return rtf.format(days,    'day');
            if (Math.abs(hours) > 0)  return rtf.format(hours,   'hour');
            return rtf.format(minutes, 'minute');
        } catch (e) {
            return 'N/A';
        }
    },

    // Format date string
    formatDate(dateStr) {
        if (!dateStr || dateStr === 'null' || dateStr === 'undefined') return 'N/A';
        try {
            const date = new Date(dateStr);
            if (isNaN(date.getTime())) return 'Invalid date';
            return date.toLocaleString();
        } catch {
            return 'Invalid date';
        }
    }
};
