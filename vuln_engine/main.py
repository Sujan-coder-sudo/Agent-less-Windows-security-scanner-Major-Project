from scanner import run_nmap
from nmap_parser import parse_nmap_output
from correlator import correlate_services
from scorer import calculate_risk
import json

def main():
    target = input("Enter target IP: ")

    print("\nStep 1: Running Nmap...")
    nmap_output = run_nmap(target)

    print("\nStep 2: Parsing results...")
    services = parse_nmap_output(nmap_output)
    print("Parsed Services:\n", services)

    print("\nStep 3: Running correlation...")
    findings = correlate_services(services)

    risk_score = calculate_risk(findings)

    print("\n=== Vulnerability Report ===\n")
    print(json.dumps(findings, indent=4))

    # ✅ Save JSON for dashboard
    with open("report.json", "w") as f:
        json.dump(findings, f, indent=4)

    print("\nReport saved to report.json")

    print("\n=== SYSTEM RISK SCORE ===")
    print(f"Risk Score: {risk_score} / 10")


if __name__ == "__main__":
    main()
