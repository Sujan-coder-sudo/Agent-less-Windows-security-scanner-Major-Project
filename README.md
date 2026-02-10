# Agentless Windows Security Scanner

A blue-team oriented, agent-less Windows vulnerability assessment platform that performs network exposure analysis, OS inspection, and authenticated security scanning without requiring client-side agents.

## 🎯 Overview

This tool provides enterprise-grade security assessment capabilities for Windows environments using:
- **Network Discovery**: Safe TCP port scanning (Nessus-style, not aggressive Nmap)
- **OS Inspection**: Authenticated WinRM/WMI-based system profiling
- **Data Ingestion**: PostgreSQL-backed scan history and analytics
- **Zero Client Footprint**: Completely agent-less architecture

## 🏗️ Architecture

The scanner operates in distinct phases:

### Phase 2: Network Exposure Scanning
- Performs safe TCP SYN scans using Nmap
- Identifies open ports and running services
- Captures local network context (ARP neighbors)
- Outputs structured JSON for ingestion

### Phase 3: OS Inspection (Authenticated)
- Windows credential validation via `LogonUserW` API
- WinRM-based system interrogation
- Collects OS details, patch levels, and security configurations
- Requires valid Windows credentials (local or domain)

### Phase 4: Data Ingestion & Storage
- **Phase 2 Ingestion**: Network exposure data (ports, services, hosts)
- **Phase 3 Ingestion**: OS inspection data (13 security categories)
- Standalone PostgreSQL ingestion pipelines
- Atomic transaction handling
- Replay protection via SHA-256 source file hashing
- Secure file disposal after successful ingestion

## 📋 Prerequisites

### System Requirements
- **OS**: Windows 10/11 or Windows Server 2016+
- **Python**: 3.9+
- **Database**: PostgreSQL 13+
- **Network Tools**: Nmap 7.80+

### Python Environment
```powershell
# Create virtual environment
python -m venv .venv

# Activate
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install psycopg[binary] pywinrm requests
```

### Database Setup
```sql
-- Create database
CREATE DATABASE agentless_scanner;

-- Connect and create user
CREATE USER scanner_user WITH PASSWORD 'changeme';
GRANT ALL PRIVILEGES ON DATABASE agentless_scanner TO scanner_user;
```

## 🚀 Quick Start

### 1. Configure Database Connection

Edit `phase4/phase2_ingest_standalone.py`:
```python
DB_CONFIG = {
    "dbname": "agentless_scanner",
    "user": "postgres",
    "password": "changeme",  # ⚠️ Change this!
    "host": "localhost",
    "port": 5432,
}
```

### 2. Run Network Scan (Phase 2)
```powershell
cd agentless-scanner/phase2
python runner.py
```

**Output**: `phase2/output/phase2_exposure.json`

### 3. Ingest Phase 2 Scan Data
```powershell
cd agentless-scanner
python phase4/phase2_ingest_standalone.py
```

**Expected Output**:
```
🔥 Phase-2 ingestion started
📋 File hash: a8e4c563...
DEBUG - Top-level keys: ['scanner', 'history']
DEBUG - Extracted 1 host(s)
🔐 Starting transaction...
DEBUG - scan_id created: 1
✅ Phase-2 ingestion committed
DEBUG - hosts inserted: 1
DEBUG - ports inserted: 19
DEBUG - services inserted: 19
🧨 Phase-2 file securely deleted
```

### 4. Run OS Inspection (Phase 3)
```powershell
cd agentless-scanner/phase3
python main.py
```

**Requires**: Valid Windows credentials (domain or local account)
**Output**: `phase3/output/scan_report.json`

### 5. Ingest Phase 3 Security Data
```powershell
cd agentless-scanner
python phase4/phase3_ingest_standalone.py
```

**Expected Output**:
```
[INFO] Starting Phase 3 ingestion...
[DEBUG] Resolved Phase 3 report path: C:\agentless-scanner\phase3\output\scan_report.json
[DEBUG] Detected top-level JSON type: list (array)
[DEBUG] Found category: OS Profiling
[DEBUG] Found category: Hotfix Audit
[DEBUG] Found category: Software Inventory
...
[DEBUG] All 13 required categories present
[DEBUG] New scan run created with ID: 1
[DEBUG] Inserting category: OS Profiling
...
[INFO] All categories inserted successfully
[DEBUG] Secure disposal completed
[+] Phase 3 scan_report.json ingested and securely disposed
```

## 🗂️ Database Schema

### Phase 2 Network Exposure Tables

#### `scans`
- Tracks individual scan executions
- Links to all discovered hosts

#### `hosts`
- Discovered network hosts
- IP address, hostname, up/down status

#### `ports`
- Open/closed/filtered ports per host
- Protocol (TCP/UDP), state, reason

#### `services`
- Service identification per port
- Product, version, confidence level

#### `os_profile`
- Operating system fingerprints
- OS family, name, accuracy score

#### `network_exposure`
- Aggregated exposure metrics per host
- Open port counts, exposure type

### Phase 3 Security Assessment Tables

#### `scan_runs`
- Tracks Phase 3 scan executions
- SHA-256 hash for duplicate prevention
- Ingestion timestamp

#### `scan_data`
- Stores security category data as JSONB
- 13 security categories:
  - OS Profiling
  - Hotfix Audit
  - Software Inventory
  - Service Status
  - EDR / AV Health
  - Audit Policy
  - Firewall Rules
  - Neighbor Discovery
  - Interface Statistics
  - Infrastructure Link
  - Persistence Mechanisms
  - User / Group Audit
  - Active Connections

## 🔒 Security Considerations

### Authentication
- **Phase 2**: No credentials required (passive scanning)
- **Phase 3**: Requires authenticated Windows user
  - Local accounts: `WORKSTATION\username`
  - Domain accounts: `DOMAIN\username`
  - ⚠️ **NOT** compatible with Microsoft Account PINs

### Network Safety
- Uses `-sS` (SYN scan) to minimize network noise
- Avoids service version detection (`-sV`) to prevent alerts
- No aggressive OS fingerprinting
- Blue-team oriented, SOC-friendly approach

### Data Protection
- Secure file deletion after ingestion (overwrites with zeros)
- Replay protection via SHA-256 hash tracking
- No plaintext credential storage

## ⚙️ Configuration

### Scan Targets
Edit `phase2/runner.py`:
```python
TARGET = "192.168.1.0/24"  # Scan entire subnet
# or
TARGET = "10.0.0.50"       # Single host
```

### Port Ranges
Default scans common Windows ports:
```
21, 23, 80, 88, 135, 139, 389, 443, 445, 636, 
3306, 3389, 5432, 5985, 5986, 8080, 8443
```

Customize in Nmap command flags.

## 🐛 Troubleshooting

### Error: "Access denied for user"
**Cause**: Incorrect database credentials  
**Fix**: Update `DB_CONFIG` in `phase4/phase2_ingest_standalone.py`

### Error: "column does not exist"
**Cause**: Schema mismatch between code and database  
**Fix**: Tables are auto-created. Drop existing tables if schema changed:
```sql
DROP TABLE IF EXISTS services, ports, hosts, scans CASCADE;
```

### Error: "LogonUser failed" (Phase 3)
**Cause**: Invalid Windows credentials or Microsoft Account PIN used  
**Fix**: Use actual password (not PIN) for local/domain accounts

### Error: "Phase-2 normalization produced ZERO hosts"
**Cause**: No hosts found in scan results  
**Fix**: Verify target is reachable and Nmap completed successfully

## 📊 Example Workflows

### Complete Security Assessment
```powershell
# 1. Activate environment
.\.venv\Scripts\Activate.ps1

# 2. Run network discovery scan (Phase 2)
cd agentless-scanner\phase2
python runner.py  # Creates phase2_exposure.json

# 3. Ingest network exposure data
cd ..
python phase4\phase2_ingest_standalone.py

# 4. Run authenticated OS inspection (Phase 3)
cd phase3
python main.py  # Requires Windows credentials

# 5. Ingest security assessment data
cd ..
python phase4\phase3_ingest_standalone.py
```

### Network Exposure Only
```powershell
cd agentless-scanner\phase2
python runner.py
cd ..
python phase4\phase2_ingest_standalone.py
```

### OS Inspection Only
```powershell
cd agentless-scanner\phase3
python main.py
cd ..
python phase4\phase3_ingest_standalone.py
```

## 📁 Project Structure

```
agentless-scanner/
├── phase2/                           # Network exposure scanning
│   ├── runner.py                     # Main scan orchestrator
│   ├── core1.py                      # Nmap wrapper
│   └── output/                       # JSON scan results
│       └── phase2_exposure.json      # Network exposure data
├── phase3/                           # OS inspection (WinRM)
│   ├── main.py                       # Authenticated scanner
│   ├── auth.py                       # Windows credential validation
│   ├── core1.py                      # WinRM session management
│   └── output/                       # Security assessment results
│       └── scan_report.json          # 13 security categories
└── phase4/                           # Data ingestion pipelines
    ├── phase2_ingest_standalone.py   # Network exposure loader
    └── phase3_ingest_standalone.py   # Security assessment loader
```

## 🔐 Production Deployment

1. **Never commit credentials**: Use environment variables
   ```powershell
   $env:DB_PASSWORD = "secure_password"
   ```

2. **Restrict database access**: Use least-privilege accounts

3. **Enable audit logging**: Track all scan executions

4. **Secure scan outputs**: Encrypt JSON files at rest

5. **Network segmentation**: Run scanner from trusted management VLAN

## 📝 License

Enterprise security assessment tool. Ensure compliance with organizational policies before deployment.

## 🤝 Contributing

This is a specialized enterprise security tool. Modifications should be reviewed by InfoSec team.

## ⚠️ Legal Disclaimer

**AUTHORIZED USE ONLY**  
This tool performs network scanning and system interrogation. Only use on systems you own or have explicit written permission to assess. Unauthorized scanning may violate laws including:
- Computer Fraud and Abuse Act (CFAA)
- Network intrusion regulations
- Corporate security policies

**The authors assume no liability for misuse.**
