from cve_lookup import search_cve

def apply_rules(service_data):
    findings = []

    port = service_data["port"]
    state = service_data["state"]
    service = service_data["service"]
    version = service_data["version"]

    # 🔴 SMB
    if port == 445:
        if state == "open":
            risk = "High"
            note = "SMB exposed - high attack surface"
        else:
            risk = "Low"
            note = "SMB filtered by firewall"

        cves = search_cve(
            primary_keyword="SMBv1 Windows exploit",
            fallback_keyword="EternalBlue SMB"
        )

        findings.append({
            "port": port,
            "state": state,
            "issue": "SMB service detected",
            "risk": risk,
            "note": note,
            "cves": cves if cves else ["Manual verification required"]
        })

    # 🔴 WinRM
    elif port == 5985:
        if state == "open":
            risk = "High"
            note = "WinRM exposed - possible remote execution"
        else:
            risk = "Low"
            note = "WinRM filtered"

        cves = search_cve(
            primary_keyword="WinRM remote execution vulnerability",
            fallback_keyword="Windows remote management vulnerability"
        )

        findings.append({
            "port": port,
            "state": state,
            "issue": "WinRM service detected",
            "risk": risk,
            "note": note,
            "cves": cves if cves else ["Check configuration manually"]
        })

    # 🔴 HTTP
    elif service == "http":
        if state == "open":
            risk = "Medium"
            note = "Web service accessible"
        else:
            risk = "Low"
            note = "Web service filtered"

        cves = search_cve(
            primary_keyword=version if version else "HTTP service",
            fallback_keyword="HTTP server vulnerability"
        )

        findings.append({
            "port": port,
            "state": state,
            "issue": f"HTTP service on port {port}",
            "risk": risk,
            "note": note,
            "cves": cves if cves else ["Generic web vulnerabilities possible"]
        })

    return findings
