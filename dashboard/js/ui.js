/**
 * ui.js
 * Handles DOM manipulation, state rendering, and reusable UI components.
 */

const UI = {
    // Show notification banners
    notify(msg, type = 'info') {
        const container = document.getElementById('notification-container');
        const notif = document.createElement('div');
        notif.className = `notification ${type}`;
        
        let icon = 'ℹ️';
        if(type==='error') icon = '🚨';
        if(type==='success') icon = '✅';

        notif.innerHTML = `
            <span>${icon} ${msg}</span>
            <button class="close-btn">&times;</button>
        `;

        container.appendChild(notif);

        notif.querySelector('.close-btn').addEventListener('click', () => {
            notif.remove();
        });

        // Auto remove after 5s
        setTimeout(() => {
            if (document.body.contains(notif)) {
                notif.remove();
            }
        }, 5000);
    },

    // Navigation orchestration
    switchSection(targetId) {
        // Update nav links
        document.querySelectorAll('.nav-item').forEach(el => {
            el.classList.remove('active');
            if(el.getAttribute('data-target') === targetId) {
                el.classList.add('active');
            }
        });

        // Update sections
        document.querySelectorAll('.section').forEach(el => {
            el.classList.remove('active');
            if(el.id === targetId) {
                el.classList.add('active');
            }
        });
    },

    // Loading button state
    setButtonLoading(btnEl, isLoading) {
        const textSpan = btnEl.querySelector('.btn-text');
        const spinner = btnEl.querySelector('.spinner');
        if (isLoading) {
            btnEl.disabled = true;
            spinner.classList.remove('hidden');
        } else {
            btnEl.disabled = false;
            spinner.classList.add('hidden');
        }
    },

    // Render bar chart
    renderVulnChart(data) {
        const chartContainer = document.getElementById('vuln-chart');
        chartContainer.innerHTML = ''; // reset

        const maxVal = Math.max(...data.map(d => d.value), 1); // Avoid div by 0

        data.forEach(item => {
            const heightPercent = (item.value / maxVal) * 100;
            
            const col = document.createElement('div');
            col.className = 'bar-col';

            const bar = document.createElement('div');
            bar.className = 'bar';
            bar.style.height = '0%'; // Start at 0 for animation
            if (item.color) {
                bar.style.background = `linear-gradient(0deg, rgba(0,0,0,0) 0%, ${item.color} 100%)`;
                bar.style.boxShadow = `inset 0 0 10px ${item.color}`;
            }

            const val = document.createElement('div');
            val.className = 'bar-val';
            val.textContent = item.value;

            const label = document.createElement('div');
            label.className = 'bar-label';
            label.textContent = item.label;

            bar.appendChild(val);
            col.appendChild(bar);
            col.appendChild(label);
            chartContainer.appendChild(col);

            // Trigger animation on next frame
            requestAnimationFrame(() => {
                setTimeout(() => {
                    bar.style.height = `${Math.max(heightPercent, 5)}%`; // Min 5% height
                }, 100);
            });
        });
    },

    // Badges UI
    getRiskBadge(riskStr) {
        let type = 'info';
        if(riskStr.toLowerCase().includes('high')) type = 'danger';
        else if(riskStr.toLowerCase().includes('medium')) type = 'warning';
        else if(riskStr.toLowerCase().includes('low')) type = 'success';
        
        return `<span class="status-badge ${type}">${riskStr}</span>`;
    },

    getStatusBadge(statusStr) {
        let type = 'info';
        const s = statusStr.toLowerCase();
        if(s.includes('success') || s.includes('up')) type = 'success';
        if(s.includes('fail') || s.includes('error')) type = 'danger';
        
        return `<span class="status-badge ${type}">${statusStr}</span>`;
    },

    // Modal UI
    showModal(title, contentHtml) {
        const modal = document.getElementById('details-modal');
        document.getElementById('modal-title').textContent = title;
        document.getElementById('modal-body').innerHTML = contentHtml;
        modal.classList.remove('hidden');
    },

    closeModal() {
        document.getElementById('details-modal').classList.add('hidden');
    },

    // Format Relative Time
    timeAgo(ts) {
        const rtf = new Intl.RelativeTimeFormat('en', { numeric: 'auto' });
        const daysDifference = Math.round((ts - Date.now()) / 86400000);
        const hoursDifference = Math.round((ts - Date.now()) / 3600000);
        
        if (Math.abs(daysDifference) > 0) return rtf.format(daysDifference, 'day');
        return rtf.format(hoursDifference, 'hour');
    },

    // Format Date
    formatDate(dateStr) {
        return new Date(dateStr).toLocaleString();
    }
};
