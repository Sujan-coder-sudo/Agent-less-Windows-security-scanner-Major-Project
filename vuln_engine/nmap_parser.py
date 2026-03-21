import re

def parse_nmap_output(nmap_output):
    results = []

    lines = nmap_output.split("\n")

    for line in lines:
        match = re.search(r"(\d+)/tcp\s+open\s+([\w\-/\?]+)\s*(.*)", line)

        if match:
            port = int(match.group(1))
            service = match.group(2).replace("?", "")
            version = match.group(3).strip()

            results.append({
                "port": port,
                "service": service,
                "version": version
            })

    return results