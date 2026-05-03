import subprocess
from pathlib import Path

WINDOWS_PORTS = [
    21, 23, 80, 88, 135, 139, 389, 443, 445,
    636, 1433, 3268, 3306, 3389, 5432,
    5985, 5986, 8080, 8443
]

def scan_host(ip):
    output = Path(f"output/scan_{ip}.xml")
    output.parent.mkdir(parents=True, exist_ok=True)
    ports = ",".join(map(str, WINDOWS_PORTS))

    import shutil
    import os
    
    nmap_exec = shutil.which("nmap")
    if not nmap_exec:
        default_win_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
        if os.path.exists(default_win_path):
            nmap_exec = default_win_path
        else:
            nmap_exec = "nmap"  # fallback

    cmd = [
        nmap_exec,
        "-sT",
        "-Pn",
        "-n",
        "--version-light",
        "-p", ports,
        "-oX", str(output),
        ip
    ]

    subprocess.run(cmd, check=True)
    return output
