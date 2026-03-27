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

            const result = latest.result || {};

            if (latest.scan_type === 'port_scan') {
                const summary = result.summary || {};
                const hosts   = result.hosts   || [];
                return {
                    totalHosts:       summary.total_hosts      || hosts.length || 0,
                    openPorts:        summary.total_open_ports || 0,
                    highRiskServices: summary.high_risk_count  || 0,
                    missingHotfixes:  0,
                    lastScan:         latest.timestamp,
                    vulnData: [
                        { label: 'Critical', value: summary.risk_distribution?.CRITICAL || 0, color: '#ff3366' },
                        { label: 'High',     value: summary.risk_distribution?.HIGH     || 0, color: '#ff8800' },
                        { label: 'Medium',   value: summary.risk_distribution?.MEDIUM   || 0, color: '#ffcc00' },
                        { label: 'Low',      value: summary.risk_distribution?.LOW      || 0, color: '#00cc66' },
                    ],
                    recentHosts: hosts.slice(0, 5).map(h => ({
                        ip: h.ip || '-', hostname: h.hostname || '-',
                        risk: h.risk_level || 'LOW', lastSeen: latest.timestamp,
                    })),
                };
            }

            // os_inspection
            const summary = result.summary || {};
            return {
                totalHosts:       1,
                openPorts:        0,
                highRiskServices: summary.high || 0,
                missingHotfixes:  0,
                lastScan:         latest.timestamp,
                vulnData: [
                    { label: 'Critical', value: summary.critical  || 0, color: '#ff3366' },
                    { label: 'High',     value: summary.high      || 0, color: '#ff8800' },
                    { label: 'Medium',   value: summary.medium    || 0, color: '#ffcc00' },
                    { label: 'Low',      value: summary.low       || 0, color: '#00cc66' },
                ],
                recentHosts: [],
            };
        } catch (err) {
            console.error('[API] getOverview failed:', err);
            return { totalHosts: 0, openPorts: 0, highRiskServices: 0, missingHotfixes: 0, lastScan: null, vulnData: [], recentHosts: [] };
        }
    },

    isPortScanRunning()      { return scanState.portScanRunning; },
    isOsInspectionRunning()  { return scanState.osInspectionRunning; },
};
