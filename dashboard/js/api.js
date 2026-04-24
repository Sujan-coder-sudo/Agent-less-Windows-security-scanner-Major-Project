/**
 * api.js
 * Clean API layer — no auth gate, unified /api/scan endpoint.
 */

const API_BASE = 'http://localhost:5000/api';

// ── State ──────────────────────────────────────────────────────────────────────
const scanState = {
    portScanRunning: false,
    osInspectionRunning: false,
};

// ── Internal helpers ───────────────────────────────────────────────────────────
async function _handleResponse(response) {
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
        throw new Error(data.message || `HTTP ${response.status}`);
    }
    return data;
}

// ── Public API object ──────────────────────────────────────────────────────────
const Api = {

    /** GET /api/ping — backend health check */
    async ping() {
        const r = await fetch(`${API_BASE}/ping`);
        return _handleResponse(r);
    },

    /** GET /api/health */
    async healthCheck() {
        const r = await fetch(`${API_BASE}/health`);
        return _handleResponse(r);
    },

    /**
     * POST /api/scan
     * @param {string} target   — IPv4 or 'localhost'
     * @param {string} scanType — 'port_scan' | 'os_inspection'
     */
    async startScan(target, scanType) {
        if (scanType === 'port_scan' && scanState.portScanRunning) {
            throw new Error('Port Scanner is already running. Please wait.');
        }
        if (scanType === 'os_inspection' && scanState.osInspectionRunning) {
            throw new Error('OS Inspection is already running. Please wait.');
        }

        if (scanType === 'port_scan') scanState.portScanRunning = true;
        else scanState.osInspectionRunning = true;

        try {
            const r = await fetch(`${API_BASE}/scan`, {
                method:  'POST',
                headers: { 'Content-Type': 'application/json' },
                body:    JSON.stringify({ target, scan_type: scanType }),
            });
            return _handleResponse(r);
        } finally {
            if (scanType === 'port_scan') scanState.portScanRunning = false;
            else scanState.osInspectionRunning = false;
        }
    },

    /**
     * Wait for a scan to finish by polling its status endpoint.
     * @param {string} scanId 
     * @param {number} intervalMs 
     * @param {number} maxRetries 
     */
    async pollScanCompletion(scanId, intervalMs = 2000, maxRetries = 150) {
        for (let i = 0; i < maxRetries; i++) {
            const r = await fetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}/status`);
            const response = await _handleResponse(r);
            const status = response.data?.status;
            
            if (status === 'completed') {
                return await this.getScanDetails(scanId);
            }
            if (status === 'failed') {
                throw new Error(response.data?.error_message || 'Scan failed during execution');
            }
            
            // Wait before next poll
            await new Promise(resolve => setTimeout(resolve, intervalMs));
        }
        throw new Error('Scan timed out waiting for completion');
    },

    /** GET /api/scans — full history index */
    async getScanHistory() {
        try {
            const r = await fetch(`${API_BASE}/scans`);
            const data = await _handleResponse(r);
            return Array.isArray(data.data) ? data.data : [];
        } catch (err) {
            console.error('[API] getScanHistory failed:', err);
            return [];
        }
    },

    /** GET /api/scans/<id> — full result for one scan */
    async getScanDetails(scanId) {
        const r = await fetch(`${API_BASE}/scans/${encodeURIComponent(scanId)}`);
        const data = await _handleResponse(r);
        return data.data || null;
    },

    /** GET /api/scans/latest */
    async getLatestScan() {
        try {
            const r = await fetch(`${API_BASE}/scans/latest`);
            const data = await _handleResponse(r);
            return data.data || null;
        } catch {
            return null;
        }
    },

    /** Overview — derived from latest scan */
    async getOverview() {
        try {
            const latest = await Api.getLatestScan();
            if (!latest) {
                return { totalHosts: 0, openPorts: 0, highRiskServices: 0, missingHotfixes: 0, lastScan: null, vulnData: [], recentHosts: [] };
            }

            // Unified shape: latest.result = { summary: {...}, data: [...] }
            const result  = latest.result  || {};
            const summary = result.summary || {};
            const data    = result.data    || [];

            if (latest.scan_type === 'port_scan') {
                // risk_distribution uses title-case keys: Critical, High, Medium, Low
                const rd = summary.risk_distribution || {};
                return {
                    totalHosts:       summary.total_findings || data.length || 0,
                    openPorts:        summary.open_ports     || 0,
                    highRiskServices: (rd.High || 0) + (rd.Critical || 0),
                    missingHotfixes:  0,
                    lastScan:         latest.timestamp,
                    vulnData: [
                        { label: 'Critical', value: rd.Critical || 0, color: '#ff3366' },
                        { label: 'High',     value: rd.High     || 0, color: '#ff8800' },
                        { label: 'Medium',   value: rd.Medium   || 0, color: '#ffcc00' },
                        { label: 'Low',      value: rd.Low      || 0, color: '#00cc66' },
                    ],
                    // Show top 5 findings as "hosts" for overview table
                    recentHosts: data.slice(0, 5).map(f => ({
                        ip:       latest.target || '-',
                        hostname: f.issue       || f.service || '-',
                        risk:     (f.risk || 'Low').toUpperCase(),
                        lastSeen: latest.timestamp,
                    })),
                };
            }

            // os_inspection — summary has: total_checks, critical, high, medium, low
            return {
                totalHosts:       1,
                openPorts:        0,
                highRiskServices: (summary.high || 0) + (summary.critical || 0),
                missingHotfixes:  0,
                lastScan:         latest.timestamp,
                vulnData: [
                    { label: 'Critical', value: summary.critical || 0, color: '#ff3366' },
                    { label: 'High',     value: summary.high     || 0, color: '#ff8800' },
                    { label: 'Medium',   value: summary.medium   || 0, color: '#ffcc00' },
                    { label: 'Low',      value: summary.low      || 0, color: '#00cc66' },
                ],
                recentHosts: data.slice(0, 5).map(r => ({
                    ip:       latest.target || '-',
                    hostname: r.category    || '-',
                    risk:     (r.risk       || 'LOW').toUpperCase(),
                    lastSeen: latest.timestamp,
                })),
            };
        } catch (err) {
            console.error('[API] getOverview failed:', err);
            return { totalHosts: 0, openPorts: 0, highRiskServices: 0, missingHotfixes: 0, lastScan: null, vulnData: [], recentHosts: [] };
        }
    },

    /** GET /api/export/pdf/<id> — download PDF report */
    downloadPdf(scanId) {
        const url = `${API_BASE}/export/pdf/${encodeURIComponent(scanId)}`;
        window.open(url, '_blank');
    },

    isPortScanRunning()      { return scanState.portScanRunning; },
    isOsInspectionRunning()  { return scanState.osInspectionRunning; },
};
