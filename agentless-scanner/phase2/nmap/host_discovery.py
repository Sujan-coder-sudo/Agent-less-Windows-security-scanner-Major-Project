import subprocess
from pathlib import Path

def discover_hosts(target_cidr):
    output = Path("output/host_discovery.xml")

    cmd = [
        "nmap",
        "-sn",
        "-n",
        "-oX", str(output),
        target_cidr
    ]

    subprocess.run(cmd, check=True)
    return output
