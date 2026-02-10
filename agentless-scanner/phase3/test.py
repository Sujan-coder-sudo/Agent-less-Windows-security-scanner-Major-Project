"""
test.py
-------
Full validation runner for Agentless Windows Vulnerability Scanner

- Executes ALL scan modules
- Validates read-only behavior
- Flags Phase-3 violations explicitly
- Produces structured test output
"""

import json
import os
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
    "Win32_Product",
    "__EventConsumer",
    "__EventFilter",
    "CommandLineEventConsumer"
]


def check_command_safety(command: str):
    violations = []
    for keyword in FORBIDDEN_KEYWORDS:
        if keyword.lower() in command.lower():
            violations.append(keyword)
    return violations


# -----------------------------
# TEST EXECUTION
# -----------------------------

def test_powershell_wrapper():
    output = run_powershell("$PSVersionTable.PSVersion.Major")
    status = "PASS" if output.isdigit() else "FAIL"

    return {
        "test": "PowerShell Wrapper",
        "status": status,
        "output": output
    }


def test_scan(scan_fn):
    result = {
        "module": scan_fn.__name__,
        "status": "PASS",
        "violations": [],
        "errors": None
    }

    try:
        scan_output = scan_fn()

        # Structural validation
        required_fields = {
            "category",
            "command",
            "command_output",
            "logic_reasoning"
        }

        missing = required_fields - scan_output.keys()
        if missing:
            result["status"] = "FAIL"
            result["errors"] = f"Missing fields: {list(missing)}"

        # Safety validation
        violations = check_command_safety(scan_output.get("command", ""))
        if violations:
            result["status"] = "WARN"
            result["violations"] = violations

        # Output sanity
        if not isinstance(scan_output.get("command_output"), str):
            result["status"] = "FAIL"
            result["errors"] = "command_output is not string"

    except Exception as e:
        result["status"] = "FAIL"
        result["errors"] = str(e)

    return result


# -----------------------------
# MAIN TEST RUNNER
# -----------------------------

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    test_results = {
        "test_run_time_utc": datetime.utcnow().isoformat() + "Z",
        "scanner_phase": 3,
        "tests": []
    }

    print("[*] Running full Phase-3 test suite")

    # Wrapper test
    test_results["tests"].append(test_powershell_wrapper())

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

    for scan in SCANS:
        test_results["tests"].append(test_scan(scan))

    with open(TEST_OUTPUT, "w", encoding="utf-8") as f:
        json.dump(test_results, f, indent=2)

    print("[+] Test run completed")
    print(f"[+] Test report written to {TEST_OUTPUT}")


if __name__ == "__main__":
    main()
