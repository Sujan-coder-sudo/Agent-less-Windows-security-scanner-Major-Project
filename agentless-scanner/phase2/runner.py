import subprocess
import json
from pathlib import Path
from datetime import datetime

from parsers.host_discovery_parser import extract_ips_from_xml
from parsers.nmap_xml_parser import parse_nmap_xml
from nmap.host_discovery import discover_hosts
from nmap.port_scan import scan_host

OUTPUT_FILE = Path("output/phase2_exposure.json")


# ---------------------------
# PowerShell Execution Layer
# ---------------------------

def run_powershell(script_path):
    result = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script_path],
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout) if result.stdout else []


def phase2_local_discovery():
    return {
        "neighbors": run_powershell("powershell/neighbor_discovery.ps1"),
        "routes": run_powershell("powershell/route_context.ps1"),
        "local_listeners": run_powershell("powershell/local_listeners.ps1")
    }


# ---------------------------
# Phase 2 Core Execution
# ---------------------------

def phase2_execute(target_cidr):
    scan_time = datetime.utcnow().isoformat() + "Z"

    phase2_data = {
        "scan_id": scan_time,
        "target": target_cidr,
        "phase": 2,
        "local_context": phase2_local_discovery(),
        "network_exposure": []
    }

    live_hosts_xml = discover_hosts(target_cidr)
    live_ips = extract_ips_from_xml(live_hosts_xml)

    for ip in live_ips:
        try:
            xml = scan_host(ip)
            parsed = parse_nmap_xml(xml)
            print(f"[DEBUG] Parsed ports for {ip}: {parsed}")

            phase2_data["network_exposure"].extend(parsed)
        except Exception as e:
            # Do NOT fail entire scan for one host
            phase2_data["network_exposure"].append({
                "host": ip,
                "error": str(e)
            })

    return phase2_data


# ---------------------------
# History Append Logic
# ---------------------------

def append_scan_result(scan_result):
    data = None

    if OUTPUT_FILE.exists():
        try:
            with open(OUTPUT_FILE, "r") as f:
                content = f.read().strip()

                if not content:
                    raise ValueError("Empty JSON file")

                data = json.loads(content)

        except (json.JSONDecodeError, ValueError):
            # Corrupt or empty file → recover safely
            data = {
                "scanner": "Agentless Windows Scanner",
                "history": []
            }
    else:
        data = {
            "scanner": "Agentless Windows Scanner",
            "history": []
        }

    # Backward compatibility
    if "history" not in data:
        data = {
            "scanner": "Agentless Windows Scanner",
            "history": [data]
        }

    data["history"].append(scan_result)

    with open(OUTPUT_FILE, "w") as f:
        json.dump(data, f, indent=2)
