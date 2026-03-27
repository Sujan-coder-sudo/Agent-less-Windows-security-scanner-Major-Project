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
    
    return findings

