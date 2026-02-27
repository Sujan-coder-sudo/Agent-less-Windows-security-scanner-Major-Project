/**
 * api.js
 * Production-grade API layer for Agentless Scanner Dashboard.
 * Handles all backend communication with proper error handling.
 */

const API_BASE = 'http://localhost:5000/api';

// Track scan state to prevent duplicate triggers
const scanState = {
    phase2Running: false,
    phase3Running: false,
    authenticated: false
};

/**
 * Handle API response and errors consistently
 */
async function handleResponse(response) {
    if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        // Check for auth required
        if (response.status === 401) {
            scanState.authenticated = false;
        }
        throw new Error(errorData.message || `HTTP Error: ${response.status}`);
    }
    return response.json();
}

/**
 * Show loading state on button
 */
function setButtonLoading(button, loading) {
    if (!button) return;
    const spinner = button.querySelector('.spinner');
    const btnText = button.querySelector('.btn-text');

    if (loading) {
        button.disabled = true;
        if (spinner) spinner.classList.remove('hidden');
        if (btnText) btnText.textContent = 'Scanning...';
    } else {
        button.disabled = false;
        if (spinner) spinner.classList.add('hidden');
        if (btnText) btnText.textContent = btnText.dataset.originalText || 'Start Scan';
    }
}

const Api = {
    /**
     * Check authentication status
     */
    async checkAuthStatus() {
        try {
            console.log('[API] Checking auth status...');
            const response = await fetch(`${API_BASE}/auth/status`, {
                method: 'GET',
                credentials: 'include'
            });
            console.log('[API] Auth status response:', response.status);
            const data = await handleResponse(response);
            console.log('[API] Auth status data:', data);
            scanState.authenticated = data.authenticated === true;
            return scanState.authenticated;
        } catch (error) {
            console.error('[API] Auth check failed:', error);
            scanState.authenticated = false;
            return false;
        }
    },

    /**
     * Verify authentication using Windows Hello
     */
    async verifyAuth() {
        try {
            console.log('[API] Verifying auth (Windows Hello)...');
            const response = await fetch(`${API_BASE}/auth/verify`, {
                method: 'POST',
                credentials: 'include'
            });
            console.log('[API] Auth verify response:', response.status);
            const data = await response.json().catch(() => ({}));
            console.log('[API] Auth verify data:', data);

            // Backend returns { status, authenticated, data, message }
            scanState.authenticated = data.authenticated === true;

            if (response.status === 401) {
                throw new Error(data.message || 'Authentication denied or cancelled');
            }
            if (!response.ok) {
                throw new Error(data.message || `HTTP Error: ${response.status}`);
            }
            return data;
        } catch (error) {
            console.error('[API] Auth verification failed:', error);
            scanState.authenticated = false;
            throw error;
        }
    },

    /**
     * Logout - clear authentication
     */
    async logout() {
        try {
            const response = await fetch(`${API_BASE}/auth/logout`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include'
            });
            scanState.authenticated = false;
            return handleResponse(response);
        } catch (error) {
            console.error('Logout failed:', error);
            throw error;
        }
    },

    /**
     * Check if user is authenticated
     */
    isAuthenticated() {
        return scanState.authenticated;
    },

    /**
     * Health check endpoint
     */
    async healthCheck() {
        try {
            const response = await fetch(`${API_BASE}/health`, {
                credentials: 'include'
            });
            return handleResponse(response);
        } catch (error) {
            console.error('Health check failed:', error);
            throw new Error('Backend API is not available. Please ensure the server is running.');
        }
    },

    /**
     * Fetch Dashboard Overview
     */
    async getOverview() {
        try {
            const response = await fetch(`${API_BASE}/overview`, {
                credentials: 'include'
            });
            const data = await handleResponse(response);

            if (data.status === 'success' && data.data) {
                const overview = data.data;
                return {
                    totalHosts: overview.totalHosts || 0,
                    openPorts: overview.openPorts || 0,
                    highRiskServices: overview.highRiskServices || 0,
                    missingHotfixes: overview.missingHotfixes || 0,
                    lastScan: overview.lastScan,
                    vulnData: overview.vulnData || [],
                    recentHosts: overview.recentHosts || []
                };
            }
            throw new Error(data.message || 'Failed to load overview');
        } catch (error) {
            console.error('Failed to load overview:', error);
            UI.notify(error.message, 'error');
            // Return default data
            return {
                totalHosts: 0,
                openPorts: 0,
                highRiskServices: 0,
                missingHotfixes: 0,
                lastScan: null,
                vulnData: [],
                recentHosts: []
            };
        }
    },

    /**
     * Start Phase 2 Network Exposure Scan (requires auth)
     */
    async startPhase2Scan(target, scanType) {
        if (scanState.phase2Running) {
            throw new Error('Phase 2 scan is already running. Please wait for it to complete.');
        }

        // Check authentication first
        if (!scanState.authenticated) {
            throw new Error('Authentication required. Please verify authentication before running scans.');
        }

        // Validate IP address format
        const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(\/(\d|[12]\d|3[01]))?$/;
        if (!ipRegex.test(target)) {
            throw new Error('Invalid IP address or CIDR range format.');
        }

        scanState.phase2Running = true;

        try {
            const response = await fetch(`${API_BASE}/phase2/run`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include',
                body: JSON.stringify({ target, scanType })
            });

            const data = await handleResponse(response);

            if (data.status === 'success') {
                return {
                    status: 'completed',
                    data: data.data,
                    message: data.message
                };
            } else {
                throw new Error(data.message || 'Scan failed');
            }
        } catch (error) {
            console.error('Phase 2 scan failed:', error);
            throw error;
        } finally {
            scanState.phase2Running = false;
        }
    },

    /**
     * Start Phase 3 System Vulnerability Scan (requires auth)
     */
    async startPhase3Scan() {
        if (scanState.phase3Running) {
            throw new Error('Phase 3 scan is already running. Please wait for it to complete.');
        }

        // Check authentication first
        if (!scanState.authenticated) {
            throw new Error('Authentication required. Please verify authentication before running scans.');
        }

        scanState.phase3Running = true;

        try {
            const response = await fetch(`${API_BASE}/phase3/run`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                credentials: 'include',
                body: JSON.stringify({})
            });

            const data = await handleResponse(response);

            if (data.status === 'success') {
                return {
                    status: 'completed',
                    data: data.data,
                    message: data.message
                };
            } else {
                throw new Error(data.message || 'Scan failed');
            }
        } catch (error) {
            console.error('Phase 3 scan failed:', error);
            throw error;
        } finally {
            scanState.phase3Running = false;
        }
    },

    /**
     * Get scan history
     */
    async getScanHistory() {
        try {
            const response = await fetch(`${API_BASE}/scans`, {
                credentials: 'include'
            });
            const data = await handleResponse(response);

            if (data.status === 'success' && Array.isArray(data.data)) {
                return data.data.map(scan => ({
                    id: scan.id,
                    target: scan.target,
                    phase: scan.phase,
                    timestamp: scan.timestamp ? new Date(scan.timestamp).getTime() : Date.now(),
                    status: scan.status || 'Unknown',
                    dataSummary: scan.data_summary || null
                }));
            }
            return [];
        } catch (error) {
            console.error('Failed to load scan history:', error);
            return [];
        }
    },

    /**
     * Clear scan history
     */
    async clearScanHistory() {
        try {
            const response = await fetch(`${API_BASE}/scans/clear`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include'
            });
            return handleResponse(response);
        } catch (error) {
            console.error('Failed to clear history:', error);
            throw error;
        }
    },

    /**
     * Export scan to file
     */
    async exportScan(scanId, format) {
        try {
            const response = await fetch(`${API_BASE}/export/${format}/${scanId}`, {
                credentials: 'include'
            });
            if (!response.ok) {
                throw new Error(`Export failed: ${response.status}`);
            }

            // Get filename from Content-Disposition header or generate one
            const contentDisposition = response.headers.get('content-disposition');
            let filename = `scan_${scanId}.${format}`;
            if (contentDisposition) {
                const match = contentDisposition.match(/filename="(.+)"/);
                if (match) filename = match[1];
            }

            // Download the file
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);

            return { success: true, filename };
        } catch (error) {
            console.error('Export failed:', error);
            throw error;
        }
    },

    /**
     * Export all scans
     */
    async exportAllScans(format) {
        try {
            const response = await fetch(`${API_BASE}/export/all/${format}`, {
                credentials: 'include'
            });
            if (!response.ok) {
                throw new Error(`Export failed: ${response.status}`);
            }

            const contentDisposition = response.headers.get('content-disposition');
            let filename = `all_scans.${format}`;
            if (contentDisposition) {
                const match = contentDisposition.match(/filename="(.+)"/);
                if (match) filename = match[1];
            }

            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            window.URL.revokeObjectURL(url);

            return { success: true, filename };
        } catch (error) {
            console.error('Bulk export failed:', error);
            throw error;
        }
    },

    /**
     * Check if Phase 2 scan is running
     */
    isPhase2Running() {
        return scanState.phase2Running;
    },

    /**
     * Check if Phase 3 scan is running
     */
    isPhase3Running() {
        return scanState.phase3Running;
    },

    // ─────────────────────────────────────────────────────────
    // NEW SPEC METHODS
    // ─────────────────────────────────────────────────────────

    /**
     * GET /api/history/<scan_id>
     * Returns full scan record for modal / detail view.
     */
    async getScanDetails(scanId) {
        try {
            const response = await fetch(`${API_BASE}/history/${scanId}`, {
                credentials: 'include'
            });
            const data = await handleResponse(response);
            if (data.status === 'success') return data.data;
            return null;
        } catch (error) {
            console.error(`[API] getScanDetails(${scanId}) failed:`, error);
            return null;
        }
    },

    /**
     * POST /api/scan/phase2  { target }
     * Direct endpoint — auth is validated server-side.
     */
    async startPhase2Direct(target) {
        if (scanState.phase2Running) {
            throw new Error('Phase 2 scan is already running.');
        }
        scanState.phase2Running = true;
        try {
            const response = await fetch(`${API_BASE}/scan/phase2`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ target })
            });
            const data = await handleResponse(response);
            if (data.status === 'success') return { status: 'completed', data: data.data };
            throw new Error(data.message || 'Scan failed');
        } catch (error) {
            console.error('[API] startPhase2Direct failed:', error);
            throw error;
        } finally {
            scanState.phase2Running = false;
        }
    },

    /**
     * POST /api/scan/phase3
     * Direct endpoint — auth is validated server-side.
     */
    async startPhase3Direct() {
        if (scanState.phase3Running) {
            throw new Error('Phase 3 scan is already running.');
        }
        scanState.phase3Running = true;
        try {
            const response = await fetch(`${API_BASE}/scan/phase3`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({})
            });
            const data = await handleResponse(response);
            if (data.status === 'success') return { status: 'completed', data: data.data };
            throw new Error(data.message || 'Scan failed');
        } catch (error) {
            console.error('[API] startPhase3Direct failed:', error);
            throw error;
        } finally {
            scanState.phase3Running = false;
        }
    }
};
