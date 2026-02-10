import subprocess
from pathlib import Path

WINDOWS_PORTS = [
    21, 23, 80, 88, 135, 139, 389, 443, 445,
    636, 1433, 3268, 3306, 3389, 5432,
    5985, 5986, 8080, 8443
]

def scan_host(ip):
    output = Path(f"output/scan_{ip}.xml")
    ports = ",".join(map(str, WINDOWS_PORTS))

    cmd = [
        "nmap",
        "-sS",
        "-Pn",
        "-n",
        "--version-light",
        "-p", ports,
        "-oX", str(output),
        ip
    ]

    subprocess.run(cmd, check=True)
    return output
