from scanner import run_nmap
from nmap_parser import parse_nmap_output
from correlator import correlate_services
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

    print("\n=== Vulnerability Report ===\n")
    print(json.dumps(findings, indent=4))


if __name__ == "__main__":
    main()