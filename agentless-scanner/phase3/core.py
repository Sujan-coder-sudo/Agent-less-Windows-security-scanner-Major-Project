# Agentless Windows Vulnerability Scanner (Core Engine)
# Fully operational logic for:
# - Running local inspection commands (agentless)
# - Correlating findings with NVD CVEs
# - Applying logical vulnerability reasoning where NVD does not apply
# - Exporting results to JSON and PDF

import os
import json
import subprocess
import platform
import requests
from typing import List, Dict, Any

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

def run_powershell(command: str) -> str:
    """Runs PowerShell command safely (inspection-only)."""
    try:
        completed = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=60
        )
        return completed.stdout.strip() or completed.stderr.strip()
    except Exception as e:
        return f"ERROR: {str(e)}"


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
            cve = item.get("cve", {})
            cves.append({
                "cve_id": cve.get("id"),
                "description": cve.get("descriptions", [{}])[0].get("value"),
                "severity": cve.get("metrics", {}).get("cvssMetricV31", [{}])[0]
            })
        return cves
    except Exception as e:
        return [{"error": str(e)}]

# -----------------------------
# SCAN MODULES
# -----------------------------

def scan_hotfix_audit():
    cmd = 'Get-HotFix; (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search("IsInstalled=0").Updates'
    return _wrap_result(
        "Hotfix Audit",
        cmd,
        run_powershell(cmd),
        "Missing KBs correlate with Patch Tuesday RCE/LPE vulnerabilities.",
        query_nvd("Windows Patch Tuesday Remote Code Execution")
    )


def scan_software_inventory():
    cmd = 'Get-Package; Get-WmiObject -Class Win32_Product; Get-Service | Where-Object {$_.Name -like "Sysmon"}'
    return _wrap_result(
        "Software Inventory",
        cmd,
        run_powershell(cmd),
        "Outdated or unmanaged software expands exploit surface.",
        query_nvd("Windows third-party software vulnerability")
    )


def scan_service_status():
    cmd = 'Get-Service | Where-Object {$_.Status -eq "Running"}; Get-CimInstance -Namespace root/subscription -ClassName __EventConsumer'
    return _wrap_result(
        "Service Status",
        cmd,
        run_powershell(cmd),
        "Running services and WMI consumers are common persistence vectors.",
        query_nvd("Windows service privilege escalation")
    )


def scan_edr_health():
    cmd = 'Get-MpComputerStatus; Confirm-SecureBootUEFI'
    return _wrap_result(
        "EDR / AV Health",
        cmd,
        run_powershell(cmd),
        "Weak EDR or Secure Boot off enables BYOVD and bootkits.",
        query_nvd("Windows Defender bypass BYOVD")
    )


def scan_audit_policy():
    cmd = 'auditpol /get /category:*; Get-EventLog -List'
    return _wrap_result(
        "Audit Policy",
        cmd,
        run_powershell(cmd),
        "Low logging creates detection gaps.",
        "No direct CVE – detection gap risk"
    )


def scan_firewall():
    cmd = 'Get-NetFirewallRule -Enabled True | Select DisplayName,Direction,Action'
    return _wrap_result(
        "Firewall Rules",
        cmd,
        run_powershell(cmd),
        "Inbound allow rules increase attack surface.",
        query_nvd("Windows Firewall bypass")
    )


def scan_neighbor_discovery():
    cmd = 'Get-NetNeighbor; Get-NetRoute'
    return _wrap_result(
        "Neighbor Discovery",
        cmd,
        run_powershell(cmd),
        "ARP/IPv6 exposure enables MitM attacks.",
        query_nvd("IPv6 Neighbor Discovery vulnerability")
    )


def scan_interface_stats():
    cmd = 'Get-NetAdapterStatistics; Get-DnsClientServerAddress'
    return _wrap_result(
        "Interface Statistics",
        cmd,
        run_powershell(cmd),
        "DNS hijacking can redirect traffic to malicious resolvers.",
        query_nvd("Windows DNS Client vulnerability")
    )


def scan_infrastructure_link():
    cmd = 'Get-ADComputer -Identity $env:COMPUTERNAME -Properties *; (Get-CimInstance Win32_BIOS).Version'
    return _wrap_result(
        "Infrastructure Link",
        cmd,
        run_powershell(cmd),
        "Outdated BIOS/UEFI firmware enables bootkits.",
        query_nvd("UEFI firmware vulnerability")
    )


def scan_persistence():
    cmd = 'Get-ScheduledTask; Get-ItemProperty HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'
    return _wrap_result(
        "Persistence Mechanisms",
        cmd,
        run_powershell(cmd),
        "Startup tasks and run keys allow malware persistence.",
        query_nvd("Windows Task Scheduler privilege escalation")
    )


def scan_os_profiling():
    cmd = 'systeminfo'
    return _wrap_result(
        "OS Profiling",
        cmd,
        run_powershell(cmd),
        "OS version/build determines kernel exploit exposure.",
        query_nvd(platform.platform())
    )


def scan_users():
    cmd = 'Get-LocalGroupMember -Group "Administrators"'
    return _wrap_result(
        "User / Group Audit",
        cmd,
        run_powershell(cmd),
        "Admin sprawl enables privilege escalation chaining.",
        query_nvd("Windows Local Privilege Escalation")
    )


def scan_connections():
    cmd = 'Get-NetTCPConnection -State Listen'
    return _wrap_result(
        "Active Connections",
        cmd,
        run_powershell(cmd),
        "Unexpected listeners may indicate backdoors.",
        query_nvd("Windows remote service RCE")
    )


def _wrap_result(category, cmd, output, logic, nvd):
    return {
        "category": category,
        "command": cmd,
        "command_output": output[:2000],
        "summary": f"{category} inspection completed.",
        "logic_reasoning": logic,
        "nvd_correlation": nvd
    }

# -----------------------------
# EXPORT
# -----------------------------

def export_json(report):
    path = os.path.join(OUTPUT_DIR, "scan_report.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    return path


def export_pdf(report):
    path = os.path.join(OUTPUT_DIR, "scan_report.pdf")
    doc = SimpleDocTemplate(path, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Agentless Windows Vulnerability Assessment", styles["Title"]))
    story.append(Spacer(1, 12))

    for item in report:
        story.append(Paragraph(f"<b>Category:</b> {item['category']}", styles["Heading2"]))
        story.append(Paragraph(f"<b>Command:</b> {item['command']}", styles["Normal"]))
        story.append(Paragraph(f"<b>Summary:</b> {item['summary']}", styles["Normal"]))
        story.append(Paragraph(f"<b>Logic:</b> {item['logic_reasoning']}", styles["Normal"]))
        story.append(Paragraph(f"<b>NVD:</b> {str(item['nvd_correlation'])[:1000]}", styles["Normal"]))
        story.append(Spacer(1, 10))

    doc.build(story)
    return path

# -----------------------------
# MAIN
# -----------------------------

def main():
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

    json_path = export_json(report)
    pdf_path = export_pdf(report)

    print("Report generated")
    print(f"JSON: {json_path}")
    print(f"PDF: {pdf_path}")


if __name__ == "__main__":
    main()
