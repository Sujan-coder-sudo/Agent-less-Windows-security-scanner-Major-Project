"""
test.py
-------
Full validation runner for Agentless Windows Vulnerability Scanner (Async Mode)
"""

import json
import os
import sys
import asyncio
from datetime import datetime

from core import (
    run_powershell,
    scan_os_profiling,
    scan_hotfix_audit,
    scan_software_inventory,
    scan_service_status,
    scan_edr_health,
    scan_audit_policy,
    scan_firewall,
    scan_neighbor_discovery,
    scan_interface_stats,
    scan_infrastructure_link,
    scan_persistence,
    scan_users,
    scan_connections
)

OUTPUT_DIR = "output"
TEST_OUTPUT = os.path.join(OUTPUT_DIR, "test_report.json")

# -----------------------------
# SAFETY RULES
# -----------------------------

FORBIDDEN_KEYWORDS = [
    "Set-",
    "Enable-",
    "Disable-",
    "Remove-",
    "Add-",
    "Start-",
    "Stop-",
    "Invoke-Expression",
    "Invoke-WebRequest",
]


def check_command_safety(command: dict):
    violations = []
    cmd_str = command.get("executed", "")
    for keyword in FORBIDDEN_KEYWORDS:
        if keyword.lower() in cmd_str.lower():
            violations.append(keyword)
    return violations


# -----------------------------
# TEST EXECUTION
# -----------------------------

async def test_powershell_wrapper():
    output = await run_powershell("$PSVersionTable.PSVersion.Major")
    status = "PASS" if output.isdigit() else "FAIL"

    return {
        "test": "PowerShell Wrapper",
        "status": status,
        "output": output
    }


async def test_scan(scan_fn):
    result = {
        "module": scan_fn.__name__,
        "status": "PASS",
        "violations": [],
        "errors": None
    }

    try:
        scan_output = await scan_fn()

        # Structural validation (updated to match _wrap_result format)
        required_fields = {
            "category",
            "status",
            "type",
            "risk",
            "command",
            "findings",
            "analysis",
            "mitre",
            "remediation",
            "nvd"
        }

        missing = required_fields - scan_output.keys()
        if missing:
            result["status"] = "FAIL"
            result["errors"] = f"Missing fields: {list(missing)}"

        # Safety validation
        violations = check_command_safety(scan_output.get("command", {}))
        if violations:
            result["status"] = "WARN"
            result["violations"] = violations

    except Exception as e:
        result["status"] = "FAIL"
        result["errors"] = str(e)

    return result


# -----------------------------
# MAIN TEST RUNNER
# -----------------------------

async def main_async():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    test_results = {
        "test_run_time_utc": datetime.utcnow().isoformat() + "Z",
        "scanner_phase": 3,
        "tests": []
    }

    print("[*] Running full Phase-3 test suite")

    # Wrapper test
    test_results["tests"].append(await test_powershell_wrapper())

    # ALL scan modules
    SCANS = [
        scan_os_profiling,
        scan_hotfix_audit,
        scan_software_inventory,
        scan_service_status,
        scan_edr_health,
        scan_audit_policy,
        scan_firewall,
        scan_neighbor_discovery,
        scan_interface_stats,
        scan_infrastructure_link,
        scan_persistence,
        scan_users,
        scan_connections
    ]
    
    tasks = [test_scan(scan) for scan in SCANS]
    results = await asyncio.gather(*tasks)
    
    test_results["tests"].extend(results)

    with open(TEST_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(test_results, f, indent=2)

    print("[+] Test run completed")
    print(f"[+] Test report written to {TEST_OUTPUT}")

def main():
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    asyncio.run(main_async())

if __name__ == "__main__":
    main()
