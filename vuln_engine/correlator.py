from rules import apply_rules

def correlate_services(services):
    all_findings = []
    seen_ports = set()

    for service in services:
        port = service["port"]

        if port in seen_ports:
            continue

        findings = apply_rules(service)

        if findings:
            seen_ports.add(port)
            all_findings.extend(findings)

    return all_findings
