import subprocess
import shutil
import sys
import logging

logger = logging.getLogger(__name__)

def run_nmap(target):
    print(f"\n[+] Running Nmap scan on {target}...\n")
    logger.info(f"[NMAP] Starting scan against target: {target}")

    # Check if nmap is installed
    nmap_path = shutil.which("nmap")
    logger.info(f"[NMAP] Nmap executable path: {nmap_path}")

    if not nmap_path:
        error_msg = "Nmap not installed or not in PATH"
        logger.error(f"[NMAP] {error_msg}")
        print("[ERROR] Nmap is not installed or not in PATH")
        print("[INFO] Please install Nmap from https://nmap.org/download.html")
        print("[INFO] Windows: winget install Insecure.Nmap")
        raise RuntimeError(f"{error_msg}. Please install Nmap and ensure it's in your system PATH.")

    command = [
        "nmap",
        "-sV",           # Version detection
        "-Pn",           # Treat all hosts as online (skip host discovery)
        "-T4",           # Faster timing template
        "--open",        # Only show open ports
        "--max-retries", "2",  # Reduce retries for speed
        target
    ]

    logger.info(f"[NMAP] Executing command: {' '.join(command)}")

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
            encoding="utf-8",
            errors="replace"
        )

        logger.info(f"[NMAP] Exit code: {result.returncode}")

        if result.stdout:
            logger.info(f"[NMAP] stdout length: {len(result.stdout)} chars")
            logger.debug(f"[NMAP] stdout preview: {result.stdout[:500]}")
        if result.stderr:
            logger.warning(f"[NMAP] stderr: {result.stderr[:500]}")

        if result.returncode != 0:
            stderr = result.stderr.strip()
            error_msg = f"Nmap failed with exit code {result.returncode}: {stderr}"
            logger.error(f"[NMAP] {error_msg}")
            print(f"[ERROR] Nmap failed with exit code {result.returncode}")
            print(f"[ERROR] {stderr}")
            raise RuntimeError(f"Nmap scan failed: {stderr}")

        if not result.stdout.strip():
            logger.warning("[NMAP] Nmap returned empty output - no open ports found")
            print("[WARNING] Nmap returned empty output")
            return f"# Nmap scan completed but no open ports found on {target}\n"

        logger.info(f"[NMAP] Scan completed successfully. Output length: {len(result.stdout)} chars")
        print(f"[+] Nmap scan completed. Output length: {len(result.stdout)} chars")
        return result.stdout

    except subprocess.TimeoutExpired as e:
        logger.error(f"[NMAP] Scan timed out after 5 minutes: {e}")
        print("[ERROR] Nmap scan timed out after 5 minutes")
        raise RuntimeError("Nmap scan timed out. Try scanning a smaller port range or check network connectivity.")
    except FileNotFoundError as e:
        logger.error(f"[NMAP] Executable not found: {e}")
        print("[ERROR] Nmap executable not found")
        raise RuntimeError("Nmap not found. Please install Nmap and ensure it's in your system PATH.")
    except Exception as e:
        logger.error(f"[NMAP] Unexpected error: {type(e).__name__}: {e}")
        print(f"[ERROR] Unexpected error running Nmap: {e}")
        raise RuntimeError(f"Failed to run Nmap: {e}")
