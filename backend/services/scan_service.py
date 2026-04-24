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
import logging
import subprocess
import threading
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

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

    vuln_engine/main.py returns:
        {"scan_info": {...}, "summary": {...}, "data": [...]}

    Older report.json files on disk may be a bare list or dict; we handle all.
    """
    if raw is None:
        raw = []

    if isinstance(raw, list):
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

    if not isinstance(raw, dict):
        raw = {}

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
    if raw is None:
        raw = {}

    if isinstance(raw, list):
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
    logger.info(f"[PORT SCAN] Starting nmap-based port scan against: {target}")
    logger.info(f"[PORT SCAN] Engine script: {VULN_ENGINE_MAIN}")
    logger.info(f"[PORT SCAN] Engine exists: {os.path.isfile(VULN_ENGINE_MAIN)}")

    if not os.path.isfile(VULN_ENGINE_MAIN):
        raise FileNotFoundError(f"vuln_engine main.py not found at: {VULN_ENGINE_MAIN}")

    cmd = [sys.executable, VULN_ENGINE_MAIN]
    logger.info(f"[PORT SCAN] Subprocess command: {cmd}")
    logger.info(f"[PORT SCAN] Working directory: {VULN_ENGINE_DIR}")
    logger.info(f"[PORT SCAN] Sending stdin: {repr(target)}")

    result = subprocess.run(
        cmd,
        input=target,
        capture_output=True,
        text=True,
        cwd=VULN_ENGINE_DIR,
        timeout=300,
        encoding="utf-8",
        errors="replace",
    )

    logger.info(f"[PORT SCAN] Exit code: {result.returncode}")
    if result.stdout:
        logger.info(f"[PORT SCAN] stdout (first 1000 chars):\n{result.stdout[:1000]}")
    if result.stderr:
        logger.warning(f"[PORT SCAN] stderr (first 1000 chars):\n{result.stderr[:1000]}")

    if result.returncode != 0:
        stderr = result.stderr.strip() or "Unknown error"
        raise RuntimeError(f"vuln_engine failed (exit {result.returncode}): {stderr}")

    logger.info(f"[PORT SCAN] report.json path: {VULN_REPORT_PATH}")
    logger.info(f"[PORT SCAN] report.json exists: {os.path.isfile(VULN_REPORT_PATH)}")

    if not os.path.isfile(VULN_REPORT_PATH):
        raise FileNotFoundError(f"report.json not found after scan at: {VULN_REPORT_PATH}")

    with open(VULN_REPORT_PATH, "r", encoding="utf-8") as f:
        content = f.read().strip()

    logger.info(f"[PORT SCAN] report.json content length: {len(content)} bytes")

    if not content:
        raise ValueError("report.json is empty")

    try:
        raw = json.loads(content)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON in report.json: {e}")

    normalized = _normalize_port_scan(raw)
    logger.info(f"[PORT SCAN] Normalized: {normalized['summary']}")
    logger.info(f"[PORT SCAN] Finding count after normalize: {len(normalized['data'])}")
    logger.info(f"[PORT SCAN] ===== EXECUTION COMPLETE =====")
    logger.info(f"[PORT SCAN] Report path: {VULN_REPORT_PATH}")
    logger.info(f"[PORT SCAN] Total findings: {len(normalized['data'])}")

    return normalized


# ── Engine 2: OS Inspection ────────────────────────────────────────────────────

def run_os_inspection(target: str, username: str = None, password: str = None) -> dict:
    """
    Execute OS inspection.
    For localhost: uses local subprocess execution via phase3/core.py logic.
    For remote targets: uses WinRM with provided credentials.
    Returns the normalised scan entry.
    """
    is_local = target.lower() in ('localhost', '127.0.0.1', '::1')
    logger.info(f"[OS INSPECT] target={target}  is_local={is_local}  has_credentials={bool(username)}")

    if is_local or not username:
        results = _run_local_os_inspection()
    else:
        results = _run_remote_os_inspection(target, username, password)

    logger.info(f"[OS INSPECT] Raw results count: {len(results)}")

    critical = sum(1 for r in results if r.get("risk", "").upper() == "CRITICAL")
    high     = sum(1 for r in results if r.get("risk", "").upper() == "HIGH")
    medium   = sum(1 for r in results if r.get("risk", "").upper() == "MEDIUM")
    low      = sum(1 for r in results if r.get("risk", "").upper() == "LOW")

    summary = {
        "total_checks": len(results),
        "critical": critical,
        "high":     high,
        "medium":   medium,
        "low":      low,
        "failed":   sum(1 for r in results if r.get("status") == "failed"),
    }
    logger.info(f"[OS INSPECT] Summary: {summary}")

    return {
        "summary": summary,
        "data": results,
    }


def _run_local_os_inspection() -> list:
    """
    Run OS inspection by executing phase3/core.py directly.
    This ensures all 13 security categories are executed:
    1. OS Profiling, 2. Hotfix Audit, 3. Software Inventory, 4. Service Status,
    5. EDR Health, 6. Audit Policy, 7. Firewall Rules, 8. Neighbor Discovery,
    9. Interface Stats, 10. Infrastructure Link, 11. Persistence,
    12. User Audit, 13. Active Connections
    """
    _phase3_dir  = os.path.join(BASE_DIR, "agentless-scanner", "phase3")
    _phase3_core = os.path.join(_phase3_dir, "core.py")
    _output_file = os.path.join(_phase3_dir, "output", "scan_report.json")

    logger.info(f"[OS INSPECT] Core script: {_phase3_core}")
    logger.info(f"[OS INSPECT] Core exists: {os.path.isfile(_phase3_core)}")

    os.makedirs(os.path.dirname(_output_file), exist_ok=True)

    cmd = [sys.executable, _phase3_core]
    logger.info(f"[OS INSPECT] Subprocess command: {cmd}")
    logger.info(f"[OS INSPECT] Working directory: {_phase3_dir}")

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=_phase3_dir,
            timeout=300,
            encoding="utf-8",
            errors="replace",
        )

        logger.info(f"[OS INSPECT] Exit code: {result.returncode}")
        if result.stdout:
            logger.info(f"[OS INSPECT] stdout (first 2000 chars):\n{result.stdout[:2000]}")
        if result.stderr:
            logger.warning(f"[OS INSPECT] stderr (first 2000 chars):\n{result.stderr[:2000]}")

        if not os.path.isfile(_output_file):
            logger.error(f"[OS INSPECT] Output file NOT found at: {_output_file}")
            logger.error("[OS INSPECT] This means core.py did not write the report. Check stderr above.")
            return []

        with open(_output_file, "r", encoding="utf-8") as f:
            content = f.read().strip()

        logger.info(f"[OS INSPECT] Output file size: {len(content)} bytes")

        if not content:
            logger.error("[OS INSPECT] Output file is EMPTY")
            return []

        data = json.loads(content)

        # phase3/core.py appends each run to a list — get the most recent
        if isinstance(data, list) and len(data) > 0:
            latest_scan = data[-1]
            logger.info(f"[OS INSPECT] scan_report.json has {len(data)} entries — using latest (index {len(data)-1})")
        elif isinstance(data, dict):
            latest_scan = data
            logger.info("[OS INSPECT] scan_report.json is a single dict entry")
        else:
            logger.error(f"[OS INSPECT] Unexpected data type from JSON: {type(data)}")
            return []

        results = latest_scan.get("results", [])
        logger.info(f"[OS INSPECT] Results from latest scan entry: {len(results)} items")

        if not results:
            logger.warning("[OS INSPECT] 'results' key is empty in scan entry")
            logger.warning(f"[OS INSPECT] Keys in scan entry: {list(latest_scan.keys())}")
            return []

        # Validate + patch missing fields
        validated = []
        for idx, item in enumerate(results):
            if not isinstance(item, dict):
                logger.warning(f"[OS INSPECT] Item {idx} is not a dict ({type(item)}) — skipping")
                continue

            if "category" not in item:
                item["category"] = f"Category_{idx}"

            if "risk" not in item:
                item["risk"] = "LOW"

            if "analysis" not in item:
                item["analysis"] = {
                    "summary": f"{item.get('category', 'Unknown')} inspection completed.",
                    "logic":   "",
                }

            if "nvd" not in item:
                item["nvd"] = []

            validated.append(item)

        logger.info(f"[OS INSPECT] Validated findings: {len(validated)}")
        logger.info(f"[OS INSPECT] ===== EXECUTION COMPLETE =====")
        logger.info(f"[OS INSPECT] JSON file path: {_output_file}")
        logger.info(f"[OS INSPECT] JSON file exists: {os.path.isfile(_output_file)}")
        logger.info(f"[OS INSPECT] Total findings to return: {len(validated)}")
        return validated

    except subprocess.TimeoutExpired:
        logger.error("[OS INSPECT] Subprocess TIMED OUT after 5 minutes")
        return []
    except json.JSONDecodeError as e:
        logger.error(f"[OS INSPECT] JSON parse error in output file: {e}")
        return []
    except Exception as e:
        logger.error(f"[OS INSPECT] Unexpected error: {type(e).__name__}: {e}")
        logger.error(traceback_str())
        return []


def traceback_str() -> str:
    import traceback
    return traceback.format_exc()


def _run_remote_os_inspection(target: str, username: str, password: str) -> list:
    """
    Run OS inspection remotely using WinRM.
    """
    from services.winrm_executor import WinRMExecutor

    executor = WinRMExecutor(target, username, password)
    results = []

    # 1. Password Policy Check
    pw_result = executor.check_password_policy()
    if pw_result["status_code"] == 0:
        results.append({
            "category": "Password Policy",
            "status": "success",
            "risk": "Medium" if "Lockout" not in pw_result["stdout"] else "Low",
            "analysis": {"summary": "Retrieved Password Policy", "logic": pw_result["stdout"][:500]},
            "nvd": []
        })
    else:
        results.append({
            "category": "Password Policy",
            "status": "failed",
            "risk": "High",
            "analysis": {"summary": "Failed to retrieve Password Policy", "logic": pw_result.get("stderr", "Unknown error")},
            "nvd": []
        })

    # 2. SMB Signing Check
    smb_result = executor.check_smb_signing()
    if smb_result["status_code"] == 0:
        val = smb_result["stdout"].strip()
        is_enabled = val == "1"
        results.append({
            "category": "SMB Signing",
            "status": "success",
            "risk": "Low" if is_enabled else "High",
            "analysis": {"summary": "SMB Signing Status", "logic": f"RequireSecuritySignature = {val}"},
            "nvd": [{"cve_id": "CVE-2020-0796", "severity": "HIGH", "description": "SMBGhost vulnerability"}] if not is_enabled else []
        })

    # 3. Defender Check
    def_result = executor.check_windows_defender()
    if def_result["status_code"] == 0:
        try:
            def_data = json.loads(def_result["stdout"])
            is_active = def_data.get("AntivirusEnabled", False)
            results.append({
                "category": "Windows Defender",
                "status": "success",
                "risk": "Low" if is_active else "Critical",
                "analysis": {"summary": "Windows Defender Status", "logic": f"Enabled: {is_active}"},
                "nvd": []
            })
        except Exception:
            results.append({
                "category": "Windows Defender",
                "status": "failed",
                "risk": "High",
                "analysis": {"summary": "Failed to parse Defender status", "logic": def_result["stdout"][:200]},
                "nvd": []
            })
    else:
        results.append({
            "category": "Windows Defender",
            "status": "failed",
            "risk": "High",
            "analysis": {"summary": "Failed to retrieve Defender status", "logic": def_result.get("stderr", "Unknown error")},
            "nvd": []
        })

    return results


# ── Unified Runner (Threading-based) ─────────────────────────────────────────

def run_scan(target: str, scan_type: str, username: str = None, password: str = None) -> dict:
    """
    Create a pending DB record and execute the scan in a daemon background thread.

    IMPORTANT: This replaces the old Celery apply_async approach.
    No separate worker process is required — the thread runs inside the Flask
    process and uses its application context.

    Returns an immediate 'queued' status response to the caller.
    """
    from extensions import db
    from models.scan import Scan
    from tasks.scan_tasks import execute_scan_sync
    from flask import current_app

    scan_id = _generate_scan_id()
    logger.info(f"[RUN SCAN] Creating scan record: {scan_id}")

    # Create pending DB record
    scan_record = Scan(
        id        = scan_id,
        target    = target,
        scan_type = scan_type,
        status    = "pending",
    )
    db.session.add(scan_record)
    db.session.commit()
    logger.info(f"[RUN SCAN] Scan record persisted with status='pending'")

    # Capture current Flask app to pass into the thread
    app = current_app._get_current_object()

    def _worker():
        logger.info(f"[THREAD] Background scan thread started for {scan_id}")
        execute_scan_sync(app, scan_id, target, scan_type, username, password)
        logger.info(f"[THREAD] Background scan thread finished for {scan_id}")

    thread = threading.Thread(target=_worker, name=f"scan-{scan_id}", daemon=True)
    thread.start()
    logger.info(f"[RUN SCAN] Background thread launched: {thread.name}")

    return {
        "scan_id":   scan_id,
        "thread_id": str(thread.ident),
        "status":    "running",
        "scan_type": scan_type,
        "target":    target,
    }


# ── History Queries (SQLAlchemy) ───────────────────────────────────────────────

def get_scan_history() -> list:
    """Return all scans ordered newest-first."""
    from models.scan import Scan
    from sqlalchemy import func

    scans = (
        Scan.query
        .order_by(
            func.coalesce(Scan.created_at, Scan.timestamp).desc()
        )
        .all()
    )
    return [
        {
            "id":             s.id,
            "scan_type":      s.scan_type,
            "target":         s.target,
            "status":         s.status,
            "created_at":     s.effective_timestamp().isoformat() + "Z" if s.effective_timestamp() else None,
            "timestamp":      s.effective_timestamp().isoformat() + "Z" if s.effective_timestamp() else None,
            "risk_score":     s.risk_score,
            "total_findings": s.total_findings,
        }
        for s in scans
    ]


def get_scan_by_id(scan_id: str) -> dict | None:
    """Load and return a full scan result by ID from the database."""
    from extensions import db
    from models.scan import Scan

    scan = db.session.get(Scan, scan_id)
    if not scan:
        path = os.path.join(SCANS_DIR, f"{scan_id}.json")
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        return None

    ts = scan.effective_timestamp()
    return {
        "scan_id":       scan.id,
        "scan_type":     scan.scan_type,
        "target":        scan.target,
        "status":        scan.status,
        "created_at":    ts.isoformat() + "Z" if ts else None,
        "timestamp":     ts.isoformat() + "Z" if ts else None,
        "completed_at":  scan.completed_at.isoformat() + "Z" if scan.completed_at else None,
        "error_message": scan.error_message,
        "result": {
            "summary": json.loads(scan.summary_json) if scan.summary_json else {},
            "data": [
                json.loads(finding.raw_data_json) if finding.raw_data_json else {}
                for finding in scan.findings.all()
            ],
        },
    }


def get_latest_scan() -> dict | None:
    """Return the most recent full scan result, or None."""
    from models.scan import Scan
    from sqlalchemy import func

    latest = (
        Scan.query
        .order_by(
            func.coalesce(Scan.created_at, Scan.timestamp).desc()
        )
        .first()
    )
    if not latest:
        return None
    return get_scan_by_id(latest.id)


def clear_scan_history() -> dict:
    """
    Clear all scan history with cascade delete for findings.
    Returns summary of deleted records.
    """
    from extensions import db
    from models.scan import Scan
    from models.finding import Finding

    scan_count    = Scan.query.count()
    finding_count = Finding.query.count()

    Finding.query.delete()
    Scan.query.delete()
    db.session.commit()

    # Clear legacy JSON files
    try:
        if os.path.exists(INDEX_FILE):
            os.remove(INDEX_FILE)
        if os.path.exists(SCANS_DIR):
            for f in os.listdir(SCANS_DIR):
                if f.endswith('.json'):
                    os.remove(os.path.join(SCANS_DIR, f))
    except Exception:
        pass

    return {
        "scans_deleted":   scan_count,
        "findings_deleted": finding_count,
    }
