/**
 * api.js
 * Handles all API networking. 
 * Mock implementation to fulfill the frontend-only requirement while showing backend structure.
 */

const API_BASE = '/api';

// Utilities to fake delays for nice UX flows
const delay = ms => new Promise(res => setTimeout(res, ms));

const Api = {
    /**
     * Fetch Dashboard Overview
     * Returns: high level metrics
     */
    async getOverview() {
        await delay(500);
        return {
            totalHosts: 42,
            openPorts: 312,
            highRiskServices: 5,
            missingHotfixes: 18,
            lastScan: new Date().toISOString(),
            // Mock chart data for vuln distribution
            vulnData: [
                { label: 'Critical', value: 2, color: 'var(--accent-red)' },
                { label: 'High', value: 8, color: 'var(--accent-red)' },
                { label: 'Med', value: 15, color: 'var(--accent-yellow)' },
                { label: 'Low', value: 24, color: 'var(--accent-cyan)' },
                { label: 'Info', value: 45, color: 'var(--text-muted)' }
            ],
            recentHosts: [
                { ip: '192.168.1.10', hostname: 'DC-01', risk: 'High', lastSeen: Date.now() - 3600000 },
                { ip: '192.168.1.50', hostname: 'WIN10-DEV', risk: 'Medium', lastSeen: Date.now() - 7200000 },
                { ip: '192.168.1.105', hostname: 'SRV-FILE', risk: 'Low', lastSeen: Date.now() - 86400000 },
            ]
        };
    },

    /**
     * POST /api/phase2/run
     * Start Phase 2 Network Exposure Scan
     */
    async startPhase2Scan(target, scanType) {
        console.log(`Sending Phase 2 Scan request: Target=${target}, Type=${scanType}`);
        await delay(800);
        
        // Simulating API success
        return {
            jobId: `p2_${Date.now()}`,
            status: 'running',
            message: 'Exposure scan initiated successfully'
        };
    },

    /**
     * GET /api/phase2/status?jobId={id}
     * Poll Phase 2 results
     */
    async pollPhase2Status(jobId) {
        await delay(2000); // Simulate processing time
        // Simulate returning result
        return {
            jobId,
            status: 'completed',
            results: [
                { ip: '10.0.0.50', hostname: 'LAB-PC-1', status: 'Up', openPorts: 12 },
                { ip: '10.0.0.51', hostname: 'LAB-PC-2', status: 'Up', openPorts: 3 },
                { ip: '10.0.0.254', hostname: 'GATEWAY', status: 'Up', openPorts: 1 }
            ]
        };
    },

    /**
     * POST /api/phase3/run
     * Start Phase 3 Authenticated Inspection
     */
    async startPhase3Scan(target, user, pass, domain) {
        console.log(`Sending Phase 3 Auth request. Target=${target}, User=${user}, Domain=${domain}`);
        await delay(1000);

        if (pass === 'wrong') {
            throw new Error("Authentication Failed. LogonUserW rejected credentials.");
        }

        return {
            jobId: `p3_${Date.now()}`,
            status: 'running',
            message: 'Authenticated inspection initiated successfully'
        };
    },

    /**
     * GET /api/phase3/status?jobId={id}
     * Poll Phase 3 results
     */
    async pollPhase3Status(jobId) {
        await delay(3000); // Simulate slower WMI interrogation

        // 13 categories mock
        return {
            jobId,
            status: 'completed',
            categories: {
                "OS Profiling": { os: "Windows 10 Pro", build: "19045", arch: "x64" },
                "Hotfix Audit": ["KB5031356", "KB5029244 missing"],
                "Software Inventory": ["Google Chrome 118", "Python 3.10", "Wireshark"],
                "Service Status": { "WinRM": "Running", "Spooler": "Stopped" },
                "EDR / AV Health": { "Windows Defender": "Active", "Signatures": "Up to date" },
                "Audit Policy": { "Logon": "Success/Failure", "Object Access": "No Auditing" },
                "Firewall Rules": ["Rule 1: Allow TCP 5985", "Rule 2: Block ICMP"],
                "Neighbor Discovery": ["10.0.0.1 (Gateway)", "10.0.0.5 (DC)"],
                "Interface Statistics": { "Ethernet0": { "Rx": "1.2GB", "Tx": "850MB" } },
                "Infrastructure Link": "Domain Joined: LAB.LOCAL",
                "Persistence Mechanisms": ["Run Keys: OneDrive", "Scheduled Task: Updater"],
                "User / Group Audit": ["Administrators: Admin, IT-Support", "Guests: Disabled"],
                "Active Connections": ["[TCP] 10.0.0.50:5985 -> 10.0.0.10:49211 (ESTABLISHED)"]
            }
        };
    },

    /**
     * GET /api/scans
     * Fetch scan history
     */
    async getScanHistory() {
        await delay(600);
        return [
            { id: 1042, target: '10.0.0.50', phase: 'Phase 3', timestamp: Date.now() - 100000, status: 'Success' },
            { id: 1041, target: '10.0.0.0/24', phase: 'Phase 2', timestamp: Date.now() - 86400000, status: 'Success' },
            { id: 1040, target: '192.168.1.10', phase: 'Phase 3', timestamp: Date.now() - 172800000, status: 'Failed (Auth)' },
            { id: 1039, target: '10.0.0.51', phase: 'Phase 3', timestamp: Date.now() - 250000000, status: 'Success' },
        ];
    },
    
    /**
     * GET /api/scans/{id}
     * Fetch details for a specific scan
     */
    async getScanDetails(id) {
        await delay(500);
        return {
            id,
            rawJson: JSON.stringify({
                _metadata: {
                    version: "1.0",
                    timestamp: new Date().toISOString(),
                    scanner_ip: "10.0.0.100"
                },
                results: "Mocked database JSON representation"
            }, null, 2)
        };
    }
};
