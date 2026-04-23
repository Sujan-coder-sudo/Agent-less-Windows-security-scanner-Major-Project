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
import asyncio
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

OUTPUT_DIR = "output"
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
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def relaunch_as_admin():
    executable = sys.executable
    args = " ".join([f'"{arg}"' for arg in sys.argv])
    ctypes.windll.shell32.ShellExecuteW(None, "runas", executable, args, None, 1)
    sys.exit(0)

def extract_kbs(output: str) -> List[str]:
    return list(set(re.findall(r"(KB\d+)", output, re.IGNORECASE)))

def parse_software(output: str) -> List[str]:
    lines = output.splitlines()
    softwares = []
    for line in lines:
        parts = line.split('  ')
        if parts and parts[0].strip() and not parts[0].strip().startswith('-') and parts[0].strip().lower() != 'name':
            if len(parts[0].strip()) > 2:
                softwares.append(parts[0].strip())
    return softwares

def extract_services(output: str) -> List[str]:
    lines = output.splitlines()
    services = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[0] == 'Running':
            services.append(parts[1])
    return services

async def run_powershell(command: str) -> str:
    """Runs PowerShell command safely (inspection-only) - ASYNC."""
    try:
        process = await asyncio.create_subprocess_exec(
            "powershell", "-ExecutionPolicy", "Bypass", "-NoProfile", "-Command", command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=30)
        
        try:
            out_str = stdout.decode('utf-8', errors='replace').strip()
        except Exception:
            out_str = str(stdout)
            
        try:
            err_str = stderr.decode('utf-8', errors='replace').strip()
        except Exception:
            err_str = str(stderr)
            
        return out_str or err_str
    except asyncio.TimeoutError:
        try:
            process.kill()
        except Exception:
            pass
        return "ERROR: Command timed out after 30 seconds."
    except Exception as e:
        return f"ERROR: {str(e)}"

def calculate_risk(nvd):
    if not isinstance(nvd, list) or not nvd:
        return "LOW"
    
    if any(c.get("severity") == "CRITICAL" for c in nvd if isinstance(c, dict)):
        return "CRITICAL"
        
    if any(c.get("severity") == "HIGH" for c in nvd if isinstance(c, dict)):
        return "HIGH"
        
    return "MEDIUM"

async def query_nvd(keyword: str, limit: int = 5) -> List[Dict[str, Any]]:
    if not NVD_API_KEY:
        return []

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": limit
    }

    try:
        r = await asyncio.to_thread(requests.get, NVD_URL, headers=REQUEST_HEADERS, params=params, timeout=10)
        r.raise_for_status()
        data = r.json()
        cves = []
        for item in data.get("vulnerabilities", []):
            try:
                cve = item.get("cve", {})
                cvss_data = cve.get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {})
                severity = cvss_data.get("baseSeverity", "").upper()
                
                if severity in ["HIGH", "CRITICAL", "MEDIUM"]:
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
        return []

# -----------------------------
# SCAN MODULES
# -----------------------------

async def scan_os_profiling():
    cmd = 'systeminfo'
    output = await run_powershell(cmd)
    
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
    
    mitre = {"id": "T1082", "tactic": "Discovery", "technique": "System Information Discovery"}
    remediation = {
        "advice": "Ensure Windows is updated to the latest cumulative release.",
        "script": "Install-Module -Name PSWindowsUpdate -Force; Get-WindowsUpdate -Install -AcceptAll -IgnoreReboot"
    }

    return _wrap_result(
        "OS Profiling", cmd, output,
        "OS version/build determines kernel exploit exposure.",
        await query_nvd(nvd_query), mitre=mitre, remediation=remediation, extra=extra
    )

async def scan_hotfix_audit():
    cmd = 'Get-HotFix; (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0").Updates'
    output = await run_powershell(cmd)
    
    kbs = extract_kbs(output)
    query_str = "Windows Patch Tuesday Remote Code Execution"
    if kbs:
        query_str = " ".join(kbs[:3])
        
    extra = {
        "missing_kbs": kbs[:10]
    }
        
    mitre = {"id": "T1203", "tactic": "Execution", "technique": "Exploitation for Client Execution"}
    remediation = {
        "advice": "Apply missing Patch Tuesday KBs to mitigate RCE vulnerabilities.",
        "script": "Install-Module -Name PSWindowsUpdate -Force; Get-WindowsUpdate -Install -AcceptAll"
    }

    return _wrap_result(
        "Hotfix Audit", cmd, output,
        "Missing KBs correlate with Patch Tuesday RCE/LPE vulnerabilities.",
        await query_nvd(query_str), mitre=mitre, remediation=remediation, extra=extra
    )

async def scan_software_inventory():
    cmd = 'Get-Package; Get-WmiObject -Class Win32_Product; Get-Service | Where-Object {$_.Name -like "Sysmon"}'
    output = await run_powershell(cmd)
    
    softwares = parse_software(output)
    query_str = "Windows third-party software vulnerability"
    if softwares and len(softwares) > 0:
        query_str = softwares[0]
        
    extra = {
        "top_software": softwares[:5]
    }
        
    mitre = {"id": "T1518", "tactic": "Discovery", "technique": "Software Discovery"}
    remediation = {
        "advice": "Update or uninstall outdated third-party applications running on the system.",
        "script": "winget upgrade --all -h"
    }

    return _wrap_result(
        "Software Inventory", cmd, output,
        "Outdated or unmanaged software expands exploit surface.",
        await query_nvd(query_str), mitre=mitre, remediation=remediation, extra=extra
    )

async def scan_service_status():
    cmd = 'Get-Service | Where-Object {$_.Status -eq "Running"}; Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer'
    output = await run_powershell(cmd)
    
    services = extract_services(output)
    query_str = "Windows service privilege escalation"
    if services:
        query_str = f"{services[0]} privilege escalation"
        
    extra = {
        "running_services": services[:10]
    }
        
    mitre = {"id": "T1543.003", "tactic": "Privilege Escalation", "technique": "Create or Modify System Process: Windows Service"}
    remediation = {
        "advice": "Disable unnecessary high-privilege services and review WMI subscriptions.",
        "script": "Stop-Service -Name <SuspiciousService> -Force; Set-Service -Name <SuspiciousService> -StartupType Disabled"
    }

    return _wrap_result(
        "Service Status", cmd, output,
        "Running services and WMI consumers are common persistence vectors.",
        await query_nvd(query_str), mitre=mitre, remediation=remediation, extra=extra
    )

async def scan_edr_health():
    cmd = 'Get-MpComputerStatus; Confirm-SecureBootUEFI'
    output = await run_powershell(cmd)
    
    query_str = "Windows Defender evasion"
    if "False" in output or "Provider load failure" in output or "Cmdlet not supported" in output:
        query_str = "Windows Defender bypass BYOVD"
        
    extra = {
        "edr_disabled_or_weak": ("False" in output) or ("Provider load failure" in output)
    }
        
    mitre = {"id": "T1562.001", "tactic": "Defense Evasion", "technique": "Impair Defenses: Disable or Modify Tools"}
    remediation = {
        "advice": "Re-enable Windows Defender Real-Time Protection and Signature Updates.",
        "script": "Set-MpPreference -DisableRealtimeMonitoring $false; Update-MpSignature"
    }

    return _wrap_result(
        "EDR / AV Health", cmd, output,
        "Weak EDR or Secure Boot off enables BYOVD and bootkits.",
        await query_nvd(query_str), mitre=mitre, remediation=remediation, extra=extra
    )

async def scan_audit_policy():
    cmd = 'auditpol /get /category:*; Get-EventLog -List'
    output = await run_powershell(cmd)
    
    extra = {
        "logging_status": "Checked"
    }
    
    mitre = {"id": "T1562.002", "tactic": "Defense Evasion", "technique": "Impair Defenses: Disable Windows Event Logging"}
    remediation = {
        "advice": "Increase audit logging for Process Creation, Logons, and Object Access.",
        "script": "auditpol /set /category:'Logon/Logoff' /success:enable /failure:enable; auditpol /set /category:'Detailed Tracking' /success:enable"
    }

    return _wrap_result(
        "Audit Policy", cmd, output,
        "Low logging creates detection gaps.",
        "No direct CVE - maps to MITRE ATT&CK", mitre=mitre, remediation=remediation, extra=extra
    )

async def scan_firewall():
    fw_cmd = 'Get-NetFirewallPortFilter | Where-Object {$_.Protocol -eq "TCP"}'
    listen_cmd = 'Get-NetTCPConnection -State Listen'
    
    fw_output = await run_powershell(fw_cmd)
    listen_output = await run_powershell(listen_cmd)
    
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
        nvd_result = await query_nvd(query_str)
    else:
        nvd_result = "Windows firewall misconfiguration"
        
    cmd_str = f"{fw_cmd}; {listen_cmd}"
    combined_output = f"FIREWALL:\n{str(fw_output)[:1000]}\n\nLISTEN:\n{str(listen_output)[:1000]}"
    
    extra = {
        "exposed_ports": exposed_ports,
        "primary_port": port,
        "service": service
    }
    
    mitre = {"id": "T1562.004", "tactic": "Defense Evasion", "technique": "Impair Defenses: Disable or Modify System Firewall"}
    remediation = {
        "advice": "Restrict inbound firewall traffic only to necessary management ports.",
        "script": "Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block"
    }

    return _wrap_result(
        "Firewall Rules", cmd_str, combined_output,
        "Open ports increase attack surface.",
        nvd_result, mitre=mitre, remediation=remediation, extra=extra
    )

async def scan_neighbor_discovery():
    cmd = 'Get-NetNeighbor; Get-NetRoute'
    output = await run_powershell(cmd)
    
    extra = {
        "network_exposure": "Checked"
    }
    
    mitre = {"id": "T1557", "tactic": "Credential Access", "technique": "Adversary-in-the-Middle"}
    remediation = {
        "advice": "Disable IPv6 routing if not actively utilized in the corporate environment to avoid MitM spoofing.",
        "script": "Disable-NetAdapterBinding -Name * -ComponentID ms_tcpip6"
    }

    return _wrap_result(
        "Neighbor Discovery", cmd, output,
        "ARP/IPv6 exposure enables MitM attacks.",
        await query_nvd("IPv6 Neighbor Discovery vulnerability"), mitre=mitre, remediation=remediation, extra=extra
    )

async def scan_interface_stats():
    cmd = 'Get-NetAdapterStatistics; Get-DnsClientServerAddress'
    output = await run_powershell(cmd)
    
    query_str = "Windows DNS Client vulnerability"
    if "ServerAddresses" in output or re.search(r"\d+\.\d+\.\d+\.\d+", output):
        query_str = "DNS spoofing Windows vulnerability"
        
    extra = {
        "interface_stats": "Checked"
    }
        
    mitre = {"id": "T1557.001", "tactic": "Credential Access", "technique": "LLMNR/NBT-NS Poisoning and SMB Relay"}
    remediation = {
        "advice": "Set hardcoded static DNS resolvers to prevent DNS hijacking.",
        "script": 'Set-DnsClientServerAddress -InterfaceAlias * -ServerAddresses "1.1.1.1","8.8.8.8"'
    }

    return _wrap_result(
        "Interface Statistics", cmd, output,
        "DNS hijacking can redirect traffic to malicious resolvers.",
        await query_nvd(query_str), mitre=mitre, remediation=remediation, extra=extra
    )

async def scan_infrastructure_link():
    cmd = 'Get-ADComputer -Identity $env:COMPUTERNAME -Properties *; (Get-CimInstance Win32_BIOS).Version'
    output = await run_powershell(cmd)
    
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
        
    mitre = {"id": "T1542.001", "tactic": "Persistence", "technique": "Boot or Logon Autostart Execution: System Firmware"}
    remediation = {
        "advice": "Enforce Secure Boot in UEFI firmware to block unauthorized bootkits.",
        "script": "Confirm-SecureBootUEFI # Must be enabled manually in physical BIOS menu"
    }

    return _wrap_result(
        "Infrastructure Link", cmd, output,
        "Outdated BIOS/UEFI firmware enables bootkits.",
        await query_nvd(query_str), mitre=mitre, remediation=remediation, extra=extra
    )

async def scan_persistence():
    cmd = 'Get-ScheduledTask; Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
    output = await run_powershell(cmd)
    
    extra = {
        "persistence_mechanisms": "Checked"
    }
    
    mitre = {"id": "T1547.001", "tactic": "Persistence", "technique": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder"}
    remediation = {
        "advice": "Remove unrecognized entries from user and system Run keys.",
        "script": "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name '<SuspiciousEntry>'"
    }

    return _wrap_result(
        "Persistence Mechanisms", cmd, output,
        "Startup tasks and run keys allow malware persistence.",
        "No direct CVE - maps to MITRE ATT&CK", mitre=mitre, remediation=remediation, extra=extra
    )

async def scan_users():
    cmd = 'Get-LocalGroupMember -Group "Administrators"'
    output = await run_powershell(cmd)
    
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
        
    mitre = {"id": "T1078.003", "tactic": "Persistence", "technique": "Valid Accounts: Local Accounts"}
    remediation = {
        "advice": "Remove unauthorized accounts from the local Administrators group.",
        "script": "Remove-LocalGroupMember -Group 'Administrators' -Member '<UnauthorizedUser>'"
    }

    return _wrap_result(
        "User / Group Audit", cmd, output,
        "Admin sprawl enables privilege escalation chaining.",
        await query_nvd(query_str), mitre=mitre, remediation=remediation, extra=extra
    )

async def scan_connections():
    cmd = 'Get-NetTCPConnection -State Listen'
    output = await run_powershell(cmd)
    
    query_str = "Windows remote service RCE"
    ports = []
    try:
        ports = re.findall(r":(\d+)\s+Listen", output)
        if ports:
            query_str = f"Windows remote service RCE port {ports[0]}"
    except Exception:
        pass
        
    extra = {
        "listening_ports": ports[:10]
    }
        
    mitre = {"id": "T1049", "tactic": "Discovery", "technique": "System Network Connections Discovery"}
    remediation = {
        "advice": "Terminate unexpected TCP listeners using PowerShell.",
        "script": "Get-Process -Id (Get-NetTCPConnection -LocalPort <PortNumber>).OwningProcess | Stop-Process -Force"
    }

    return _wrap_result(
        "Active Connections", cmd, output,
        "Unexpected listeners may indicate backdoors.",
        await query_nvd(query_str), mitre=mitre, remediation=remediation, extra=extra
    )

def _wrap_result(category, cmd, output, logic, nvd, mitre=None, remediation=None, extra=None):
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
        "mitre": mitre or {},
        "remediation": remediation or {},
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
        
        # Access properties using nested output schema safely
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

# -----------------------------
# MAIN
# -----------------------------

async def main_async():
    if not is_admin():
        print("Not running as administrator. Relaunching...")
        relaunch_as_admin()

    start_time = datetime.now()

    # Run all 13 modules concurrently
    report = await asyncio.gather(
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
    )

    end_time = datetime.now()
    duration = (end_time - start_time).total_seconds()

    metadata = generate_scan_metadata()

    final_output = {
        "scan_info": metadata,
        "summary": build_summary(report),
        "results": list(report)
    }

    json_path = export_json(final_output)
    pdf_path = export_pdf(list(report))

    print(f"Report generated in {duration:.2f} seconds")
    print(f"JSON: {json_path}")
    print(f"PDF: {pdf_path}")

def main():
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    asyncio.run(main_async())

if __name__ == "__main__":
    main()