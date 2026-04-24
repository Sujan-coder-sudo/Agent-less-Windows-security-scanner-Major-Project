from cve_lookup import search_cve
from typing import List, Dict, Any

# Production-grade vulnerability intelligence database
# Maps common ports to their security risk profiles and CVE queries
PORT_RULES = {
    21: {
        "service": "FTP",
        "risk": "High",
        "query": "FTP anonymous authentication vulnerability",
        "note": "FTP often allows anonymous access and transmits credentials in plaintext"
    },
    22: {
        "service": "SSH",
        "risk": "Medium",
        "query": "SSH brute force vulnerability",
        "note": "SSH is secure but may be vulnerable to brute-force attacks if weak credentials are used"
    },
    23: {
        "service": "Telnet",
        "risk": "Critical",
        "query": "Telnet insecure protocol",
        "note": "Telnet transmits all data including passwords in plaintext - immediate remediation required"
    },
    25: {
        "service": "SMTP",
        "risk": "Medium",
        "query": "SMTP open relay vulnerability",
        "note": "Misconfigured SMTP servers can be abused for spam and phishing campaigns"
    },
    53: {
        "service": "DNS",
        "risk": "Medium",
        "query": "DNS amplification attack",
        "note": "Open DNS resolvers can be abused for DDoS amplification attacks"
    },
    80: {
        "service": "HTTP",
        "risk": "Medium",
        "query": "web server vulnerability",
        "note": "Unencrypted web traffic susceptible to interception and manipulation"
    },
    110: {
        "service": "POP3",
        "risk": "Medium",
        "query": "POP3 plaintext vulnerability",
        "note": "POP3 typically uses plaintext authentication - consider POP3S"
    },
    135: {
        "service": "RPC",
        "risk": "High",
        "query": "Windows RPC vulnerability",
        "note": "RPC is commonly used in lateral movement and ransomware propagation"
    },
    139: {
        "service": "NetBIOS",
        "risk": "Medium",
        "query": "NetBIOS information leakage",
        "note": "NetBIOS can expose system information and enable enumeration attacks"
    },
    143: {
        "service": "IMAP",
        "risk": "Medium",
        "query": "IMAP vulnerability",
        "note": "IMAP without TLS exposes credentials and email content"
    },
    443: {
        "service": "HTTPS",
        "risk": "Medium",
        "query": "SSL TLS vulnerability",
        "note": "Check for outdated SSL/TLS versions and weak cipher suites"
    },
    445: {
        "service": "SMB",
        "risk": "High",
        "query": "SMB EternalBlue exploit",
        "note": "SMB has been exploited by WannaCry, NotPetya, and numerous ransomware strains"
    },
    1433: {
        "service": "MSSQL",
        "risk": "High",
        "query": "Microsoft SQL Server vulnerability",
        "note": "Exposed MSSQL instances are frequently targeted for cryptocurrency mining"
    },
    1521: {
        "service": "Oracle",
        "risk": "High",
        "query": "Oracle Database vulnerability",
        "note": "Oracle databases have extensive attack surface with critical historical vulnerabilities"
    },
    3306: {
        "service": "MySQL",
        "risk": "High",
        "query": "MySQL authentication bypass",
        "note": "Exposed MySQL databases are prime targets for data exfiltration"
    },
    3389: {
        "service": "RDP",
        "risk": "High",
        "query": "RDP BlueKeep vulnerability",
        "note": "RDP is a primary attack vector - ensure NLA is enabled and access is restricted"
    },
    5432: {
        "service": "PostgreSQL",
        "risk": "High",
        "query": "PostgreSQL vulnerability",
        "note": "Exposed PostgreSQL instances often use default/weak credentials"
    },
    5985: {
        "service": "WinRM",
        "risk": "High",
        "query": "WinRM remote execution vulnerability",
        "note": "Windows Remote Management enables PowerShell remoting - restrict access"
    },
    6379: {
        "service": "Redis",
        "risk": "Critical",
        "query": "Redis unauthenticated access",
        "note": "Redis lacks authentication by default - immediate access control required"
    },
    8080: {
        "service": "HTTP-Alt",
        "risk": "Medium",
        "query": "web server misconfiguration",
        "note": "Alternative HTTP ports often host admin interfaces or proxy servers"
    },
    8443: {
        "service": "HTTPS-Alt",
        "risk": "Medium",
        "query": "SSL misconfiguration",
        "note": "Alternative HTTPS ports may use self-signed or expired certificates"
    },
    9200: {
        "service": "Elasticsearch",
        "risk": "Critical",
        "query": "Elasticsearch exposure",
        "note": "Elasticsearch frequently lacks authentication leading to data breaches"
    },
    11211: {
        "service": "Memcached",
        "risk": "Critical",
        "query": "Memcached amplification attack",
        "note": "Memcached DDoS amplification attacks have reached 1.7 Tbps - firewall immediately"
    },
    27017: {
        "service": "MongoDB",
        "risk": "Critical",
        "query": "MongoDB exposed database",
        "note": "MongoDB ransomware attacks target exposed instances without authentication"
    },
    5000: {
        "service": "UPnP",
        "risk": "High",
        "query": "UPnP vulnerability",
        "note": "UPnP can be exploited to bypass firewalls and expose internal services"
    },
    5900: {
        "service": "VNC",
        "risk": "High",
        "query": "VNC authentication bypass",
        "note": "VNC often uses weak passwords or no authentication - major security risk"
    }
}


def apply_rules(service_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Apply vulnerability intelligence rules to a detected service.
    
    Args:
        service_data: Dict with keys 'port', 'state', 'service', 'version'
    
    Returns:
        List of finding dictionaries with CVE information
    """
    findings = []
<<<<<<< HEAD
    
    port = service_data.get("port")
    state = service_data.get("state", "unknown")
    service = service_data.get("service", "unknown")
    version = service_data.get("version", "")
    
    # Skip if port not in our threat intelligence database
    if port not in PORT_RULES:
        # Generic rule for unknown ports
        if state == "open":
            findings.append({
                "port": port,
                "service": service,
                "state": state,
                "issue": f"Unknown service '{service}' on port {port}",
                "risk": "Medium",
                "note": "Unidentified service - manual verification recommended",
                "cves": []
            })
        return findings
    
    rule = PORT_RULES[port]
    
    # Build the finding based on state
    if state == "open":
        # Look up CVEs for this service
        cves = search_cve(rule["query"])
        
        findings.append({
            "port": port,
            "service": rule["service"],
            "state": state,
            "issue": f"{rule['service']} service exposed on port {port}",
            "risk": rule["risk"],
            "note": rule["note"],
            "cves": cves if cves else ["No recent CVEs found - verify manually"],
            "version": version
        })
    elif state == "filtered":
        # Service exists but is filtered - reduced risk
        findings.append({
            "port": port,
            "service": rule["service"],
            "state": state,
            "issue": f"{rule['service']} port {port} is filtered",
            "risk": "Low",
            "note": "Service detected but protected by firewall",
            "cves": [],
            "version": version
        })
    else:
        # Closed or other state
        findings.append({
            "port": port,
            "service": rule["service"],
            "state": state,
            "issue": f"{rule['service']} port {port} is {state}",
            "risk": "Low",
            "note": "Service not accessible from network",
            "cves": [],
            "version": version
        })
    
=======

    port = service_data["port"]
    state = service_data["state"]
    service = service_data["service"]
    version = service_data.get("version", "")
    protocol = service_data.get("protocol", "tcp")

    # Helper function for safe CVE lookup with fallback
    def safe_cve_lookup(primary, fallback, static_cves=None):
        """Safely lookup CVEs with fallback to static list if API fails."""
        try:
            cves = search_cve(primary_keyword=primary, fallback_keyword=fallback)
            if cves and len(cves) > 0:
                return cves
        except Exception as e:
            print(f"[WARNING] CVE lookup failed for {primary}: {e}")

        # Return static fallback CVEs if API fails
        if static_cves:
            return static_cves
        return ["Manual verification required - CVE lookup unavailable"]

    # 🔴 SMB (Port 445)
    if port == 445:
        if state in ["open", "open_filtered"]:
            risk = "High"
            note = "SMB (Server Message Block) exposed - high attack surface. Vulnerable to EternalBlue, SMBGhost, and lateral movement attacks."
        else:
            risk = "Medium"
            note = "SMB port detected but filtered. May still be accessible under certain conditions."

        cves = safe_cve_lookup(
            "SMBv1 Windows exploit",
            "EternalBlue SMB",
            static_cves=["CVE-2017-0144", "CVE-2020-0796", "MS17-010"]
        )

        findings.append({
            "port": port,
            "protocol": protocol,
            "state": state,
            "service": service,
            "issue": "SMB service detected",
            "risk": risk,
            "note": note,
            "cves": cves
        })

    # 🔴 RDP (Port 3389)
    elif port == 3389:
        if state in ["open", "open_filtered"]:
            risk = "High"
            note = "RDP (Remote Desktop Protocol) exposed - vulnerable to BlueKeep, brute force, and remote code execution attacks. Immediate hardening recommended."
        else:
            risk = "Medium"
            note = "RDP port detected but filtered. Review firewall rules and consider disabling RDP if not required."

        cves = safe_cve_lookup(
            "RDP remote code execution",
            "BlueKeep RDP vulnerability",
            static_cves=["CVE-2019-0708", "CVE-2019-1181", "CVE-2019-1182"]
        )

        findings.append({
            "port": port,
            "protocol": protocol,
            "state": state,
            "service": service,
            "issue": "RDP service detected",
            "risk": risk,
            "note": note,
            "cves": cves
        })

    # 🔴 RPC (Port 135)
    elif port == 135:
        if state in ["open", "open_filtered"]:
            risk = "High"
            note = "RPC (Remote Procedure Call) endpoint mapper exposed. Critical for lateral movement techniques (T1021.003). Disable or restrict access."
        else:
            risk = "Medium"
            note = "RPC port detected but filtered. Review if RPC is required for business operations."

        findings.append({
            "port": port,
            "protocol": protocol,
            "state": state,
            "service": service,
            "issue": "RPC endpoint mapper exposed",
            "risk": risk,
            "note": note,
            "cves": ["MS08-067", "CVE-2008-4250", "Lateral Movement Vector (T1021.003)"]
        })

    # 🔴 NetBIOS (Port 139)
    elif port == 139:
        if state in ["open", "open_filtered"]:
            risk = "High"
            note = "NetBIOS over TCP/IP exposed. Enables SMB enumeration, password brute-forcing, and information disclosure attacks."
        else:
            risk = "Medium"
            note = "NetBIOS port detected but filtered. Legacy protocol that should be disabled on modern networks."

        findings.append({
            "port": port,
            "protocol": protocol,
            "state": state,
            "service": service,
            "issue": "NetBIOS service detected",
            "risk": risk,
            "note": note,
            "cves": ["Enumeration Risk (T1018)", "Information Disclosure (T1087)"]
        })

    # 🔴 WinRM (Port 5985)
    elif port == 5985 or port == 5986:
        if state in ["open", "open_filtered"]:
            risk = "High"
            note = f"WinRM (Windows Remote Management) exposed on port {port}. Enables remote PowerShell execution. Restrict to authorized management hosts only."
        else:
            risk = "Medium"
            note = f"WinRM port {port} detected but filtered. Verify if WinRM is required for system management."

        cves = safe_cve_lookup(
            "WinRM remote execution vulnerability",
            "Windows remote management vulnerability",
            static_cves=["Remote Execution Vector (T1021.006)"]
        )

        findings.append({
            "port": port,
            "protocol": protocol,
            "state": state,
            "service": service,
            "issue": "WinRM service detected",
            "risk": risk,
            "note": note,
            "cves": cves
        })

    # 🔴 HTTP/HTTPS (Ports 80, 443, 8080, 8443)
    elif service in ["http", "https"] or port in [80, 443, 8080, 8443]:
        if state in ["open", "open_filtered"]:
            # Higher risk for HTTP vs HTTPS
            if service == "http" or port == 80 or port == 8080:
                risk = "Medium"
                note = f"HTTP service on port {port}. Unencrypted traffic. Check for outdated web server versions and misconfigurations."
            else:
                risk = "Low"
                note = f"HTTPS service on port {port}. Verify TLS configuration and certificate validity."
        else:
            risk = "Low"
            note = f"Web service on port {port} is filtered."

        search_term = version if version else f"{service} {port}"
        cves = safe_cve_lookup(
            search_term,
            "HTTP server vulnerability",
            static_cves=["Review server version for known CVEs"]
        )

        findings.append({
            "port": port,
            "protocol": protocol,
            "state": state,
            "service": service,
            "issue": f"{service.upper() if service else 'Web'} service on port {port}",
            "risk": risk,
            "note": note,
            "cves": cves
        })

>>>>>>> a542a4e (Working stage)
    return findings

