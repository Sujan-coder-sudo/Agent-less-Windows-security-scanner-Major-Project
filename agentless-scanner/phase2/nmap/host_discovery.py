import subprocess
from pathlib import Path

def discover_hosts(target_cidr):
    output = Path("output/host_discovery.xml")
    output.parent.mkdir(parents=True, exist_ok=True)

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
        "-sn",
        "-n",
        "-oX", str(output),
        target_cidr
    ]

    subprocess.run(cmd, check=True)
    return output
