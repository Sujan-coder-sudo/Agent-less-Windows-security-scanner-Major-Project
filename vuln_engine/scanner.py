import subprocess

def run_nmap(target):
    print(f"\n[+] Running Nmap scan on {target}...\n")

    command = [
        "nmap",
        "-sV",
        "-Pn",
        target
    ]

    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout
