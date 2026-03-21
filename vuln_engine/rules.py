from cve_lookup import search_cve

def apply_rules(service_data):
    findings = []

    port = service_data["port"]
    service = service_data["service"]
    version = service_data["version"]

    # 🔴 SMB
    if port == 445:
        cves = search_cve(
            primary_keyword="SMBv1 Windows exploit",
            fallback_keyword="EternalBlue SMB"
        )

        findings.append({
            "port": port,
            "issue": "SMB service exposed",
            "risk": "High",
            "cves": cves if cves else ["Possible SMB vulnerabilities (manual verification needed)"]
        })

    # 🔴 WinRM
    elif port == 5985:
        cves = search_cve(
            primary_keyword="WinRM remote execution vulnerability",
            fallback_keyword="Windows remote management vulnerability"
        )

        findings.append({
            "port": port,
            "issue": "WinRM over HTTP exposed",
            "risk": "High",
            "cves": cves if cves else ["Check WinRM configuration manually"]
        })

    # 🔴 HTTP services
    elif service == "http":
        cves = search_cve(
            primary_keyword=version,
            fallback_keyword="HTTP server vulnerability"
        )

        findings.append({
            "port": port,
            "issue": f"HTTP service on port {port}",
            "risk": "Medium",
            "cves": cves if cves else ["Generic web vulnerabilities possible"]
        })

    return findings