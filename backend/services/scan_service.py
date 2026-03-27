"""
scan_service.py
Core dual-engine scanning service.

Engines:
  - port_scan     → vuln_engine/main.py  → vuln_engine/report.json
  - os_inspection → agentless-scanner/phase3/core.py → phase3/output/scan_report.json
"""

import os
import sys
import json
import subprocess
from datetime import datetime, timezone

# ── Paths (relative to project root) ──────────────────────────────────────────
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

VULN_ENGINE_DIR   = os.path.join(BASE_DIR, "vuln_engine")
VULN_ENGINE_MAIN  = os.path.join(VULN_ENGINE_DIR, "main.py")
VULN_REPORT_PATH  = os.path.join(VULN_ENGINE_DIR, "report.json")

PHASE3_DIR        = os.path.join(BASE_DIR, "agentless-scanner", "phase3")
PHASE3_CORE       = os.path.join(PHASE3_DIR, "core.py")
PHASE3_REPORT_DIR = os.path.join(PHASE3_DIR, "output")
PHASE3_REPORT     = os.path.join(PHASE3_REPORT_DIR, "scan_report.json")

# ── Storage paths ──────────────────────────────────────────────────────────────
DATA_DIR       = os.path.join(os.path.dirname(__file__), "..", "data")
SCANS_DIR      = os.path.join(DATA_DIR, "scans")
INDEX_FILE     = os.path.join(DATA_DIR, "scan_index.json")

os.makedirs(SCANS_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)


# ── Helpers ────────────────────────────────────────────────────────────────────

def _generate_scan_id() -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S_%f")
    return f"scan_{ts}"


def _load_index() -> list:
    if not os.path.exists(INDEX_FILE):
        return []
    try:
        with open(INDEX_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_index(index: list) -> None:
    with open(INDEX_FILE, "w", encoding="utf-8") as f:
        json.dump(index, f, indent=2)


def _save_scan(scan_id: str, payload: dict) -> str:
    path = os.path.join(SCANS_DIR, f"{scan_id}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return path


def _append_index(scan_id: str, scan_type: str, target: str, file_path: str) -> None:
    index = _load_index()
    entry = {
        "id":        scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_type": scan_type,
        "target":    target,
        "file_path": file_path,
    }
    index.insert(0, entry)          # newest first
    _save_index(index)


# ── Engine 1: Port Scan ────────────────────────────────────────────────────────

def run_port_scan(target: str) -> dict:
    """
    Execute vuln_engine/main.py with the supplied target and return the parsed
    report.json contents.  The script reads its target from stdin.
    """
    if not os.path.isfile(VULN_ENGINE_MAIN):
        raise FileNotFoundError(f"vuln_engine main.py not found at: {VULN_ENGINE_MAIN}")

    result = subprocess.run(
        [sys.executable, VULN_ENGINE_MAIN],
        input=target,
        capture_output=True,
        text=True,
        cwd=VULN_ENGINE_DIR,
        timeout=300,
    )

    if result.returncode != 0:
        stderr = result.stderr.strip() or "Unknown error"
        raise RuntimeError(f"vuln_engine failed (exit {result.returncode}): {stderr}")

    if not os.path.isfile(VULN_REPORT_PATH):
        raise FileNotFoundError(f"report.json not found after scan at: {VULN_REPORT_PATH}")

    with open(VULN_REPORT_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


# ── Engine 2: OS Inspection ────────────────────────────────────────────────────

def run_os_inspection(target: str) -> dict:
    """
    Execute phase3/core.py (agentless Windows inspection) and return the latest
    scan entry from phase3/output/scan_report.json.

    The phase3 core appends each run to scan_report.json as a list; we return
    only the most-recent entry so the caller gets a single-scan dict.
    """
    if not os.path.isfile(PHASE3_CORE):
        raise FileNotFoundError(f"phase3/core.py not found at: {PHASE3_CORE}")

    os.makedirs(PHASE3_REPORT_DIR, exist_ok=True)

    result = subprocess.run(
        [sys.executable, PHASE3_CORE],
        capture_output=True,
        text=True,
        cwd=PHASE3_DIR,
        timeout=600,
    )

    if result.returncode != 0:
        stderr = result.stderr.strip() or "Unknown error"
        raise RuntimeError(f"phase3/core.py failed (exit {result.returncode}): {stderr}")

    if not os.path.isfile(PHASE3_REPORT):
        raise FileNotFoundError(f"scan_report.json not found after inspection at: {PHASE3_REPORT}")

    with open(PHASE3_REPORT, "r", encoding="utf-8") as f:
        data = json.load(f)

    # core.py appends; return only the latest entry
    if isinstance(data, list):
        return data[-1] if data else {}
    return data


# ── Unified Runner ─────────────────────────────────────────────────────────────

def run_scan(target: str, scan_type: str) -> dict:
    """
    Run the appropriate engine, store the result, update scan_index.json,
    and return:
        { scan_id, scan_type, target, timestamp, result }
    """
    scan_id   = _generate_scan_id()
    timestamp = datetime.now(timezone.utc).isoformat()

    if scan_type == "port_scan":
        result = run_port_scan(target)
    elif scan_type == "os_inspection":
        result = run_os_inspection(target)
    else:
        raise ValueError(f"Unknown scan_type: '{scan_type}'. Must be 'port_scan' or 'os_inspection'.")

    payload = {
        "scan_id":   scan_id,
        "scan_type": scan_type,
        "target":    target,
        "timestamp": timestamp,
        "result":    result,
    }

    file_path = _save_scan(scan_id, payload)
    _append_index(scan_id, scan_type, target, file_path)

    return payload


# ── History Queries ────────────────────────────────────────────────────────────

def get_scan_history() -> list:
    """Return the full scan index (metadata only, no result blobs)."""
    return _load_index()


def get_scan_by_id(scan_id: str) -> dict | None:
    """Load and return a full scan result by ID."""
    path = os.path.join(SCANS_DIR, f"{scan_id}.json")
    if not os.path.isfile(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def get_latest_scan() -> dict | None:
    """Return the most recent full scan result, or None."""
    index = _load_index()
    if not index:
        return None
    return get_scan_by_id(index[0]["id"])
