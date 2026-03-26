import re

def parse_nmap_output(nmap_output):
    results = []

    lines = nmap_output.split("\n")

    for line in lines:
        match = re.search(r"(\d+)/tcp\s+(open|filtered)\s+([\w\-/\?]+)\s*(.*)", line)

        if match:
            port = int(match.group(1))
            state = match.group(2)
            service = match.group(3).replace("?", "")
            version = match.group(4).strip()

            results.append({
                "port": port,
                "state": state,
                "service": service,
                "version": version
            })

    return results
