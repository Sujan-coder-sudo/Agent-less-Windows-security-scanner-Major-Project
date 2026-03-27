from scanner import run_nmap
from nmap_parser import parse_nmap_output
from correlator import correlate_services
from scorer import calculate_risk
import json

def run_scan(target: str) -> dict:
    """
    Execute vulnerability scan using pure python modules.
    Returns a normalized dict:
        {
            "scan_info": {"target": ...},
            "summary":   {"total_findings": int, "open_ports": int,
                          "risk_score": float, "risk_distribution": {...}},
            "data":      [list of finding dicts]
        }
    """
    print(f"\nStep 1: Running Nmap against {target}...")
    nmap_output = run_nmap(target)

    print("\nStep 2: Parsing results...")
    services = parse_nmap_output(nmap_output)
    print("Parsed Services:\n", services)

    print("\nStep 3: Running correlation...")
    raw_findings = correlate_services(services)  # always returns a list

    # Guard: ensure raw_findings is always a list
    if not isinstance(raw_findings, list):
        raw_findings = list(raw_findings) if raw_findings else []

    risk_score = calculate_risk(raw_findings)

    # Build per-severity counts (engine uses title-case: High, Medium, Low, Critical)
    risk_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for f in raw_findings:
        r = f.get("risk", "Low")
        risk_dist[r] = risk_dist.get(r, 0) + 1

    findings = {
        "scan_info": {
            "target": target,
        },
        "summary": {
            "total_findings": len(raw_findings),
            "open_ports":     sum(1 for f in raw_findings if f.get("state") == "open"),
            "risk_score":     risk_score,
            "risk_distribution": risk_dist,
        },
        "data": raw_findings,   # canonical key consumed by scan_service.py
    }

    print("\n=== SYSTEM RISK SCORE ===")
    print(f"Risk Score: {risk_score} / 10")

    return findings


def main():
    target = input("Enter target IP: ")
    findings = run_scan(target)

    # Optional local save if run manually
    with open("report.json", "w") as f:
        json.dump(findings, f, indent=4)

    print("\nReport saved to report.json")


if __name__ == "__main__":
    main()
