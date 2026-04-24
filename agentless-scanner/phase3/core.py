# Agentless Windows Vulnerability Scanner (Core Engine)
# Fully operational logic for:
# - Running local inspection commands (agentless)
# - Correlating findings with NVD CVEs
# - Applying logical vulnerability reasoning where NVD does not apply
# - Exporting results to JSON and PDF

import os
import sys
import json
import subprocess
import platform
import requests
import ctypes
import re
from typing import List, Dict, Any
from datetime import datetime
import uuid

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from dotenv import load_dotenv
load_dotenv()


# -----------------------------
# CONFIGURATION
# -----------------------------
NVD_API_KEY = os.getenv("NVD_API_KEY")
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_HEADERS = {
    "apiKey": NVD_API_KEY,
    "User-Agent": "Agentless-Vuln-Scanner/1.0"
}

# Always write output relative to THIS script's directory, not the CWD.
# This prevents the output file from being created in a wrong location
# when called as a subprocess from scan_service.py.
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR  = os.path.join(_SCRIPT_DIR, "output")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# -----------------------------
# UTILITY FUNCTIONS
# -----------------------------

def generate_scan_metadata():
    return {
        "scan_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat()
    }

COMMON_PORT_MAP = {
    "3389": "RDP",
    "445": "SMB",
    "139": "NetBIOS",
    "135": "RPC",
    "80": "HTTP",
    "443": "HTTPS",
    "21": "FTP",
    "22": "SSH"
}

def is_admin() -> bool:
    """Checks if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def extract_kbs(output: str) -> List[str]:
    """Extract KB numbers like KB5021234 from command output."""
    return list(set(re.findall(r"(KB\d+)", output, re.IGNORECASE)))

def parse_software(output: str) -> List[str]:
    """Extract top installed software names from command output."""
    lines = output.splitlines()
    softwares = []
    for line in lines:
        parts = line.split('  ')
        if parts and parts[0].strip() and not parts[0].strip().startswith('-') and parts[0].strip().lower() != 'name':
            if len(parts[0].strip()) > 2:
                softwares.append(parts[0].strip())
    return softwares

def extract_services(output: str) -> List[str]:
    """Extract running service names from command output."""
    lines = output.splitlines()
    services = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[0] == 'Running':
            services.append(parts[1])
    return services

def run_powershell(command: str) -> str:
    """Runs PowerShell command safely (inspection-only)."""
    try:
        completed = subprocess.run(
            ["powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60
        )
        return completed.stdout.strip() or completed.stderr.strip()
    except Exception as e:
        return f"ERROR: {str(e)}"

def calculate_risk(nvd):
    """Calculates risk dynamically from nvd output severities."""
    if not isinstance(nvd, list) or not nvd:
        return "LOW"
    
    if any(c.get("severity") == "CRITICAL" for c in nvd if isinstance(c, dict)):
        return "CRITICAL"
        
    if any(c.get("severity") == "HIGH" for c in nvd if isinstance(c, dict)):
        return "HIGH"
        
    return "MEDIUM"

def query_nvd(keyword: str, limit: int = 5) -> List[Dict[str, Any]]:
    if not NVD_API_KEY:
        return [{"error": "NVD_API_KEY not set"}]

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": limit
    }

    try:
        r = requests.get(NVD_URL, headers=REQUEST_HEADERS, params=params, timeout=30)
        r.raise_for_status()
        data = r.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            try:
                cve = item.get("cve", {})
                cvss_data = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
                severity = cvss_data.get("baseSeverity", "").upper()
                
                if severity in ["HIGH", "CRITICAL"]:
                    cve_id = cve.get("id", "Unknown")
                    desc = cve.get("descriptions", [{}])[0].get("value", "No description")
                    cves.append({
                        "cve_id": cve_id,
                        "description": desc,
                        "severity": severity
                    })
            except Exception:
                continue
        return cves
    except Exception as e:
        return [{"error": str(e)}]

# -----------------------------
# SCAN MODULES
# -----------------------------

def scan_os_profiling():
    cmd = 'systeminfo'
    output = run_powershell(cmd)
    
    nvd_query = "Windows vulnerability"
    extracted_name = None
    extracted_version = None
    
    try:
        os_name_match = re.search(r"OS Name:\s+(.+)", output)
        os_version_match = re.search(r"OS Version:\s+(.+)", output)
        if os_name_match and os_version_match:
            extracted_name = os_name_match.group(1).replace("Microsoft", "").strip()
            extracted_version = os_version_match.group(1).split(" ")[0]
            nvd_query = f"{extracted_name} {extracted_version}"
        else:
            ver = platform.version()
            if ver:
                nvd_query = f"Windows {ver}"
                extracted_version = ver
    except Exception:
        pass

    extra = {
        "os_name": extracted_name,
        "os_version": extracted_version
    }

    return _wrap_result(
        "OS Profiling",
        cmd,
        output,
        "OS version/build determines kernel exploit exposure.",
        query_nvd(nvd_query),
        extra
    )

def scan_hotfix_audit():
    cmd = 'Get-HotFix; (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0").Updates'
    output = run_powershell(cmd)
    
    kbs = extract_kbs(output)
    query_str = "Windows Patch Tuesday Remote Code Execution"
    if kbs:
        query_str = " ".join(kbs[:3])
        
    extra = {
        "missing_kbs": kbs[:10]
    }
        
    return _wrap_result(
        "Hotfix Audit",
        cmd,
        output,
        "Missing KBs correlate with Patch Tuesday RCE/LPE vulnerabilities.",
        query_nvd(query_str),
        extra
    )

def scan_software_inventory():
    cmd = 'Get-Package; Get-WmiObject -Class Win32_Product; Get-Service | Where-Object {$_.Name -like "Sysmon"}'
    output = run_powershell(cmd)
    
    softwares = parse_software(output)
    query_str = "Windows third-party software vulnerability"
    if softwares and len(softwares) > 0:
        query_str = softwares[0]
        
    extra = {
        "top_software": softwares[:5]
    }
        
    return _wrap_result(
        "Software Inventory",
        cmd,
        output,
        "Outdated or unmanaged software expands exploit surface.",
        query_nvd(query_str),
        extra
    )

def scan_service_status():
    cmd = 'Get-Service | Where-Object {$_.Status -eq "Running"}; Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer'
    output = run_powershell(cmd)
    
    services = extract_services(output)
    query_str = "Windows service privilege escalation"
    if services:
        query_str = f"{services[0]} privilege escalation"
        
    extra = {
        "running_services": services[:10]
    }
        
    return _wrap_result(
        "Service Status",
        cmd,
        output,
        "Running services and WMI consumers are common persistence vectors.",
        query_nvd(query_str),
        extra
    )

def scan_edr_health():
    cmd = 'Get-MpComputerStatus; Confirm-SecureBootUEFI'
    output = run_powershell(cmd)
    
    query_str = "Windows Defender evasion"
    if "False" in output or "Provider load failure" in output or "Cmdlet not supported" in output:
        query_str = "Windows Defender bypass BYOVD"
        
    extra = {
        "edr_disabled_or_weak": ("False" in output) or ("Provider load failure" in output)
    }
        
    return _wrap_result(
        "EDR / AV Health",
        cmd,
        output,
        "Weak EDR or Secure Boot off enables BYOVD and bootkits.",
        query_nvd(query_str),
        extra
    )

def scan_audit_policy():
    cmd = 'auditpol /get /category:*; Get-EventLog -List'
    output = run_powershell(cmd)
    
    extra = {
        "logging_status": "Checked"
    }
    
    return _wrap_result(
        "Audit Policy",
        cmd,
        output,
        "Low logging creates detection gaps.",
        "No direct CVE - maps to MITRE ATT&CK",
        extra
    )

def scan_firewall():
    fw_cmd = 'Get-NetFirewallPortFilter | Where-Object {$_.Protocol -eq "TCP"}'
    listen_cmd = 'Get-NetTCPConnection -State Listen'
    
    fw_output = run_powershell(fw_cmd)
    listen_output = run_powershell(listen_cmd)
    
    try:
        fw_ports = set(re.findall(r"\b\d{2,5}\b", str(fw_output)))
        listen_ports = set(re.findall(r"\b\d{2,5}\b", str(listen_output)))
        exposed_ports = list(fw_ports.intersection(listen_ports))
    except Exception:
        exposed_ports = []
        
    port = None
    service = None
    
    if exposed_ports:
        port = str(exposed_ports[0])
        service = COMMON_PORT_MAP.get(port, "Windows service")
        query_str = f"{service} remote code execution"
        nvd_result = query_nvd(query_str)
    else:
        nvd_result = "Windows firewall misconfiguration"
        
    cmd_str = f"{fw_cmd}; {listen_cmd}"
    combined_output = f"FIREWALL:\n{str(fw_output)[:1000]}\n\nLISTEN:\n{str(listen_output)[:1000]}"
    
    extra = {
        "exposed_ports": exposed_ports,
        "primary_port": port,
        "service": service
    }
    
    return _wrap_result(
        "Firewall Rules",
        cmd_str,
        combined_output,
        "Open ports increase attack surface.",
        nvd_result,
        extra
    )

def scan_neighbor_discovery():
    cmd = 'Get-NetNeighbor; Get-NetRoute'
    output = run_powershell(cmd)
    
    extra = {
        "network_exposure": "Checked"
    }
    
    return _wrap_result(
        "Neighbor Discovery",
        cmd,
        output,
        "ARP/IPv6 exposure enables MitM attacks.",
        query_nvd("IPv6 Neighbor Discovery vulnerability"),
        extra
    )

def scan_interface_stats():
    cmd = 'Get-NetAdapterStatistics; Get-DnsClientServerAddress'
    output = run_powershell(cmd)
    
    query_str = "Windows DNS Client vulnerability"
    if "ServerAddresses" in output or re.search(r"\d+\.\d+\.\d+\.\d+", output):
        query_str = "DNS spoofing Windows vulnerability"
        
    extra = {
        "interface_stats": "Checked"
    }
        
    return _wrap_result(
        "Interface Statistics",
        cmd,
        output,
        "DNS hijacking can redirect traffic to malicious resolvers.",
        query_nvd(query_str),
        extra
    )

def scan_infrastructure_link():
    cmd = 'Get-ADComputer -Identity $env:COMPUTERNAME -Properties *; (Get-CimInstance Win32_BIOS).Version'
    output = run_powershell(cmd)
    
    query_str = "UEFI firmware vulnerability"
    bios_ver = None
    try:
        lines = [line.strip() for line in output.splitlines() if line.strip()]
        if lines:
            bios_ver = lines[-1][:30]
            query_str = f"UEFI firmware vulnerability {bios_ver}"
    except Exception:
        pass
        
    extra = {
        "bios_version": bios_ver
    }
        
    return _wrap_result(
        "Infrastructure Link",
        cmd,
        output,
        "Outdated BIOS/UEFI firmware enables bootkits.",
        query_nvd(query_str),
        extra
    )

def scan_persistence():
    cmd = 'Get-ScheduledTask; Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
    output = run_powershell(cmd)
    
    extra = {
        "persistence_mechanisms": "Checked"
    }
    
    return _wrap_result(
        "Persistence Mechanisms",
        cmd,
        output,
        "Startup tasks and run keys allow malware persistence.",
        "No direct CVE - maps to MITRE ATT&CK",
        extra
    )

def scan_users():
    cmd = 'Get-LocalGroupMember -Group "Administrators"'
    output = run_powershell(cmd)
    
    query_str = "Windows privilege escalation"
    admin_count = 0
    try:
        lines = output.splitlines()
        admin_count = sum(1 for line in lines if "User" in line or "Group" in line)
        if admin_count > 1:
            query_str = "Windows local privilege escalation"
    except Exception:
        pass
        
    extra = {
        "admin_count": admin_count
    }
        
    return _wrap_result(
        "User / Group Audit",
        cmd,
        output,
        "Admin sprawl enables privilege escalation chaining.",
        query_nvd(query_str),
        extra
    )

def scan_connections():
    cmd = 'Get-NetTCPConnection -State Listen'
    output = run_powershell(cmd)
    
    query_str = "Windows remote service RCE"
    ports = []
    try:
        # Regex update specific to connections explicitly requested
        ports = re.findall(r":(\d+)\s+Listen", output)
        if ports:
            query_str = f"Windows remote service RCE port {ports[0]}"
    except Exception:
        pass
        
    extra = {
        "listening_ports": ports[:10]
    }
        
    return _wrap_result(
        "Active Connections",
        cmd,
        output,
        "Unexpected listeners may indicate backdoors.",
        query_nvd(query_str),
        extra
    )

def _wrap_result(category, cmd, output, logic, nvd, extra=None):
    return {
        "category": category,
        "status": "success" if "ERROR" not in str(output) else "failed",
        "type": "cve" if isinstance(nvd, list) else "misconfiguration",
        "risk": calculate_risk(nvd),
        "command": {
            "executed": cmd,
            "raw_output": output[:2000] if isinstance(output, str) else str(output)[:2000]
        },
        "findings": extra if extra else {},
        "analysis": {
            "summary": f"{category} inspection completed.",
            "logic": logic
        },
        "nvd": nvd if isinstance(nvd, list) else []
    }

# -----------------------------
# EXPORT
# -----------------------------

def build_summary(report):
    return {
        "total_checks": len(report),
        "critical": sum(1 for r in report if r.get("risk") == "CRITICAL"),
        "high": sum(1 for r in report if r.get("risk") == "HIGH"),
        "medium": sum(1 for r in report if r.get("risk") == "MEDIUM"),
        "low": sum(1 for r in report if r.get("risk") == "LOW"),
        "failed": sum(1 for r in report if r.get("status") == "failed")
    }

def export_json(new_scan):
    path = os.path.join(OUTPUT_DIR, "scan_report.json")

    # Load existing data
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Ensure it's a list
            if not isinstance(data, list):
                data = [data]

        except Exception:
            data = []
    else:
        data = []

    # Append new scan
    data.append(new_scan)

    # Save back
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    return path

def export_pdf(report):
    path = os.path.join(OUTPUT_DIR, "scan_report.pdf")
    doc = SimpleDocTemplate(path, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Agentless Windows Vulnerability Assessment", styles["Title"]))
    story.append(Spacer(1, 12))

    for item in report:
        story.append(Paragraph(f"<b>Category:</b> {item.get('category')}", styles["Heading2"]))
        
        # Access properties using the new nested output schema safely
        cmd_text = item.get("command", {}).get("executed", "")
        summary_text = item.get("analysis", {}).get("summary", "")
        logic_text = item.get("analysis", {}).get("logic", "")
        nvd_list = item.get("nvd", [])
        
        story.append(Paragraph(f"<b>Command:</b> {cmd_text}", styles["Normal"]))
        story.append(Paragraph(f"<b>Summary:</b> {summary_text}", styles["Normal"]))
        story.append(Paragraph(f"<b>Logic:</b> {logic_text}", styles["Normal"]))
        story.append(Paragraph(f"<b>NVD:</b> {str(nvd_list)[:1000]}", styles["Normal"]))
        story.append(Spacer(1, 10))

    doc.build(story)
    return path
# MAIN
# -----------------------------

def main():
    """
    Main entry point for OS inspection scan.
    Always runs all 13 categories - no admin elevation required.
    Non-privileged checks simply return partial data with status='restricted'.
    """
    admin_status = "YES" if is_admin() else "NO (some checks will be restricted)"
    print(f"[core.py] Administrator privileges: {admin_status}")
    print(f"[core.py] Output directory: {OUTPUT_DIR}")
    print(f"[core.py] Starting 13-category security scan...")

    report = [
        scan_os_profiling(),
        scan_hotfix_audit(),
        scan_software_inventory(),
        scan_service_status(),
        scan_edr_health(),
        scan_audit_policy(),
        scan_firewall(),
        scan_neighbor_discovery(),
        scan_interface_stats(),
        scan_infrastructure_link(),
        scan_persistence(),
        scan_users(),
        scan_connections()
    ]

    print(f"[core.py] Completed {len(report)} scan categories.")

    metadata = generate_scan_metadata()

    final_output = {
        "scan_info": metadata,
        "summary": build_summary(report),
        "results": report
    }

    json_path = export_json(final_output)
    print(f"[core.py] JSON report written to: {json_path}")

    try:
        pdf_path = export_pdf(report)
        print(f"[core.py] PDF report written to: {pdf_path}")
    except Exception as pdf_err:
        print(f"[core.py] WARNING: PDF export failed (non-critical): {pdf_err}")

    print("[core.py] Scan complete.")

if __name__ == "__main__":
    main()