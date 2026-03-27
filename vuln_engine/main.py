from scanner import run_nmap
from nmap_parser import parse_nmap_output
from correlator import correlate_services
from scorer import calculate_risk
import json

def run_scan(target: str) -> dict:
    """
    Execute vulnerability scan using pure python modules.
    """
    print(f"\nStep 1: Running Nmap against {target}...")
    nmap_output = run_nmap(target)

    print("\nStep 2: Parsing results...")
    services = parse_nmap_output(nmap_output)
    print("Parsed Services:\n", services)

    print("\nStep 3: Running correlation...")
    findings = correlate_services(services)

    risk_score = calculate_risk(findings)
    findings["summary"] = findings.get("summary", {})
    findings["summary"]["risk_score"] = risk_score
    findings["scan_info"] = findings.get("scan_info", {})
    findings["scan_info"]["target"] = target
    
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
