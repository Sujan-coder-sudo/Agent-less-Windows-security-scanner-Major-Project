import re

def parse_nmap_output(nmap_output):
    """
    Parse Nmap output to extract port, state, service, and version information.
    Handles multiple Nmap output formats including:
    - Standard format: 80/tcp open http Apache httpd 2.4.41
    - Filtered ports: 443/tcp filtered https
    - No version: 22/tcp open ssh
    - Unknown service: 8080/tcp open unknown
    """
    results = []

    if not nmap_output or not isinstance(nmap_output, str):
        print("[WARNING] Empty or invalid Nmap output provided to parser")
        return results

    lines = nmap_output.split("\n")

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Skip header lines and comments
        if line.startswith('#') or line.startswith('Nmap') or line.startswith('Host') or line.startswith('PORT'):
            continue

        # Primary regex: captures port, state, service, and optional version
        # Pattern: port/protocol state service version-info
        # Examples:
        #   80/tcp  open   http    Apache httpd 2.4.41
        #   443/tcp filtered https
        #   22/tcp  open   ssh     OpenSSH 8.2p1
        match = re.search(
            r"(\d+)/(tcp|udp)\s+(open|open\|filtered|filtered|closed|unfiltered)\s+(\S+)(?:\s+(.*))?",
            line,
            re.IGNORECASE
        )

        if match:
            port = int(match.group(1))
            protocol = match.group(2).lower()
            state = match.group(3).lower().replace('|', '_')  # Normalize open|filtered to open_filtered
            service = match.group(4).replace("?", "").strip()
            version = (match.group(5) or "").strip()

            # Skip if service is unknown and version is empty - might be noise
            if service == "unknown" and not version:
                continue

            results.append({
                "port": port,
                "protocol": protocol,
                "state": state,
                "service": service,
                "version": version
            })

    print(f"[+] Parsed {len(results)} services from Nmap output")

    # Log summary of findings
    if results:
        open_count = sum(1 for r in results if "open" in r["state"])
        filtered_count = sum(1 for r in results if "filtered" in r["state"])
        print(f"[+] Open ports: {open_count}, Filtered ports: {filtered_count}")
    else:
        print("[INFO] No parseable services found in Nmap output")
        # Debug: show first few lines of output
        sample_lines = [l for l in lines if l.strip() and not l.startswith('#')][:5]
        if sample_lines:
            print(f"[DEBUG] Sample output lines: {sample_lines}")

    return results
