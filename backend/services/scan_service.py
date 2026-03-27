"""
scan_service.py
Core dual-engine scanning service.

Engines:
  - port_scan     → vuln_engine/main.py   → writes vuln_engine/report.json
  - os_inspection → agentless-scanner/phase3/core.py → phase3/output/scan_report.json

Unified API result shape (stored per-scan and returned by /api/scan):
    {
        "scan_id":   str,
        "scan_type": "port_scan" | "os_inspection",
        "target":    str,
        "timestamp": ISO-8601 str,
        "result": {
            "summary": {
                "total_findings": int,
                "open_ports":     int,          # port_scan only
                "risk_score":     float,        # port_scan only
                "risk_distribution": {...},     # port_scan only
                "total_checks":  int,           # os_inspection only
                "critical": int,                # os_inspection only
                "high":     int,                # os_inspection only
                "medium":   int,                # os_inspection only
                "low":      int,                # os_inspection only
            },
            "data": [list of finding dicts]
        }
    }
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
DATA_DIR   = os.path.join(os.path.dirname(__file__), "..", "data")
SCANS_DIR  = os.path.join(DATA_DIR, "scans")
INDEX_FILE = os.path.join(DATA_DIR, "scan_index.json")

os.makedirs(SCANS_DIR, exist_ok=True)
os.makedirs(DATA_DIR,  exist_ok=True)


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
    index.insert(0, entry)   # newest first
    _save_index(index)


# ── Normalisers ────────────────────────────────────────────────────────────────

def _normalize_port_scan(raw) -> dict:
    """
    Convert vuln_engine output into the unified result shape.

    vuln_engine/main.py now returns:
        {"scan_info": {...}, "summary": {...}, "data": [...]}

    Older report.json files on disk may be a bare list or dict; we handle all.
    """
    # --- handle None or non-container types ---
    if raw is None:
        raw = []

    # --- handle legacy or unexpected shapes ---
    if isinstance(raw, list):
        # bare list of findings (pre-fix format)
        findings = raw
        risk_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in findings:
            if not isinstance(f, dict):
                continue
            r = f.get("risk", "Low")
            risk_dist[r] = risk_dist.get(r, 0) + 1
        total_score = sum(
            {"Critical": 10, "High": 7, "Medium": 4, "Low": 2}.get(
                (f.get("risk", "Low") if isinstance(f, dict) else "Low"), 1
            )
            for f in findings
        )
        risk_score = round(total_score / len(findings), 2) if findings else 0.0
        return {
            "summary": {
                "total_findings":   len(findings),
                "open_ports":       sum(1 for f in findings if isinstance(f, dict) and f.get("state") == "open"),
                "risk_score":       risk_score,
                "risk_distribution": risk_dist,
            },
            "data": findings,
        }

    # --- handle non-dict types (convert to empty structure) ---
    if not isinstance(raw, dict):
        raw = {}

    # --- new canonical shape from fixed main.py ---
    summary = raw.get("summary") if isinstance(raw, dict) else {}
    if not isinstance(summary, dict):
        summary = {}

    data = raw.get("data", [])
    if not isinstance(data, list):
        data = []

    return {
        "summary": {
            "total_findings":    summary.get("total_findings",    len(data)),
            "open_ports":        summary.get("open_ports",        sum(1 for f in data if isinstance(f, dict) and f.get("state") == "open")),
            "risk_score":        summary.get("risk_score",        0.0),
            "risk_distribution": summary.get("risk_distribution", {}),
        },
        "data": data,
    }


def _normalize_os_inspection(raw) -> dict:
    """
    Convert phase3/core.py output into the unified result shape.

    core.py writes each run as:
        {"scan_info": {...}, "summary": {...}, "results": [...]}
    appended into a list inside scan_report.json.

    scan_service.run_os_inspection() already extracts the last element.
    """
    # --- handle None or non-container types ---
    if raw is None:
        raw = {}

    # --- handle list type (shouldn't happen but be defensive) ---
    if isinstance(raw, list):
        # If raw is a list, treat it as the results directly
        return {
            "summary": {
                "total_checks": len(raw),
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "failed": 0,
            },
            "data": raw,
        }

    # --- handle non-dict types ---
    if not isinstance(raw, dict):
        raw = {}

    summary = raw.get("summary", {})
    if not isinstance(summary, dict):
        summary = {}

    results = raw.get("results", [])
    if not isinstance(results, list):
        results = []

    return {
        "summary": {
            "total_checks": summary.get("total_checks", len(results)),
            "critical":     summary.get("critical", 0),
            "high":         summary.get("high",      0),
            "medium":       summary.get("medium",    0),
            "low":          summary.get("low",       0),
            "failed":       summary.get("failed",    0),
        },
        "data": results,
    }


# ── Engine 1: Port Scan ────────────────────────────────────────────────────────

def run_port_scan(target: str) -> dict:
    """
    Execute vuln_engine/main.py, read report.json, return normalised result dict.
    The script reads its target from stdin.
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

    # Handle empty or invalid JSON files gracefully
    try:
        with open(VULN_REPORT_PATH, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                raise ValueError("report.json is empty")
            raw = json.loads(content)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON in report.json: {e}")
    except Exception as e:
        raise RuntimeError(f"Failed to read report.json: {e}")

    return _normalize_port_scan(raw)


# ── Engine 2: OS Inspection ────────────────────────────────────────────────────

def run_os_inspection(target: str) -> dict:
    """
    Execute phase3/core.py and return the normalised latest scan entry.
    core.py appends each run to scan_report.json as a list.
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

    # Handle empty or invalid JSON files gracefully
    try:
        with open(PHASE3_REPORT, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                raise ValueError("scan_report.json is empty")
            data = json.loads(content)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON in scan_report.json: {e}")
    except Exception as e:
        raise RuntimeError(f"Failed to read scan_report.json: {e}")

    # core.py appends into a list — grab the latest entry
    latest = data[-1] if isinstance(data, list) and data else data if isinstance(data, dict) else {}
    return _normalize_os_inspection(latest)


# ── Unified Runner ─────────────────────────────────────────────────────────────

def run_scan(target: str, scan_type: str) -> dict:
    """
    Run the appropriate engine, store the result, update scan_index.json,
    and return the canonical payload:
        { scan_id, scan_type, target, timestamp, result: {summary, data} }
    """
    scan_id   = _generate_scan_id()
    timestamp = datetime.now(timezone.utc).isoformat()

    if scan_type == "port_scan":
        result = run_port_scan(target)
    elif scan_type == "os_inspection":
        result = run_os_inspection(target)
    else:
        raise ValueError(f"Unknown scan_type: '{scan_type}'.")

    payload = {
        "scan_id":   scan_id,
        "scan_type": scan_type,
        "target":    target,
        "timestamp": timestamp,
        "result":    result,   # always {"summary": {...}, "data": [...]}
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
