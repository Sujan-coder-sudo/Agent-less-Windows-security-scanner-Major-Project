"""
scan_tasks.py
Core scan execution logic.

Uses direct synchronous execution in a background threading.Thread.
No Celery, no Redis, no separate worker process required.

The function execute_scan_sync() is the single entry point called from
scan_service.run_scan() inside a daemon thread.
"""

import json
import traceback
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def execute_scan_sync(app, scan_id: str, target: str, scan_type: str,
                      username: str = None, password: str = None):
    """
    Execute a security scan synchronously inside an application context.
    Intended to be called from a daemon threading.Thread — NOT from a
    Celery worker (Celery dependency removed).

    Flow:
        1. Mark scan as 'running'
        2. Call the appropriate engine (port_scan | os_inspection)
        3. Persist every finding to the DB
        4. Mark scan as 'completed'
        5. On any exception → mark scan as 'failed' + log full traceback
    """
    from services.scan_service import run_port_scan, run_os_inspection
    from utils.mitre_mapper import MitreMapper

    logger.info("=" * 60)
    logger.info(f"[SCAN START] scan_id={scan_id}")
    logger.info(f"[SCAN START] type={scan_type} target={target}")
    logger.info("=" * 60)

    with app.app_context():
        from extensions import db
        from models.scan import Scan
        from models.finding import Finding

        # ── Step 1: Mark running ───────────────────────────────────────────
        scan_record = db.session.get(Scan, scan_id)
        if not scan_record:
            logger.error(f"[SCAN] Scan record {scan_id} not found in DB — aborting.")
            return

        scan_record.status = "running"
        db.session.commit()
        logger.info(f"[SCAN] Status set to 'running'")

        try:
            # ── Step 2: Execute engine ─────────────────────────────────────
            logger.info(f"[SCAN] Dispatching to engine: {scan_type}")

            if scan_type == "port_scan":
                result = run_port_scan(target)
            elif scan_type == "os_inspection":
                result = run_os_inspection(target, username, password)
            else:
                raise ValueError(f"Unknown scan_type: {scan_type!r}")

            # ── Step 3: Extract summary + data ────────────────────────────
            summary = result.get("summary", {})
            data    = result.get("data", [])

            logger.info(f"[SCAN] Engine returned: summary={summary}")
            logger.info(f"[SCAN] Engine returned: data items={len(data)}")

            if not data:
                logger.warning("[SCAN] WARNING: engine returned 0 data items — check engine logs above")

            # ── Step 4: Update Scan record metrics ────────────────────────
            if scan_type == "port_scan":
                scan_record.total_findings = summary.get("total_findings", len(data))
                scan_record.risk_score     = float(summary.get("risk_score", 0.0))
            else:
                scan_record.total_findings = summary.get("total_checks", len(data))
                scan_record.risk_score     = 0.0

            scan_record.summary_json = json.dumps(summary)
            logger.info(f"[SCAN] total_findings={scan_record.total_findings}  risk_score={scan_record.risk_score}")

            # ── Step 5: Persist findings ───────────────────────────────────
            inserted = 0
            for idx, item in enumerate(data):
                if not isinstance(item, dict):
                    logger.warning(f"[SCAN] Skipping non-dict item at index {idx}: {type(item)}")
                    continue

                # Enrich with MITRE ATT&CK mapping
                enriched = MitreMapper.enrich_finding(dict(item))  # copy to avoid mutating source

                # Normalise risk level → uppercase
                raw_risk  = enriched.get("risk", "LOW") or "LOW"
                risk_norm = raw_risk.upper() if isinstance(raw_risk, str) else "LOW"

                logger.debug(f"[SCAN] Saving finding #{idx}: category={enriched.get('category')} "
                             f"port={enriched.get('port')} risk={risk_norm}")

                if scan_type == "port_scan":
                    finding = Finding(
                        scan_id      = scan_id,
                        port         = enriched.get("port"),
                        service      = enriched.get("service"),
                        state        = enriched.get("state"),
                        issue        = enriched.get("issue"),
                        risk_level   = risk_norm,
                        note         = enriched.get("note"),
                        cves_json    = json.dumps(enriched.get("cves", [])),
                        raw_data_json= json.dumps(enriched),
                    )
                else:  # os_inspection
                    # analysis block structure from phase3/core.py _wrap_result()
                    analysis = enriched.get("analysis", {})
                    if not isinstance(analysis, dict):
                        analysis = {}

                    issue_text = analysis.get("summary") or enriched.get("category", "")
                    note_text  = analysis.get("logic") or ""

                    finding = Finding(
                        scan_id      = scan_id,
                        category     = enriched.get("category"),
                        issue        = issue_text,
                        risk_level   = risk_norm,
                        note         = note_text,
                        cves_json    = json.dumps(enriched.get("nvd", [])),
                        raw_data_json= json.dumps(enriched),
                    )

                db.session.add(finding)
                inserted += 1

            db.session.flush()  # write findings before committing scan status
            logger.info(f"[SCAN] Inserted {inserted} findings into DB")

            # ── Step 6: Mark completed ─────────────────────────────────────
            scan_record.status       = "completed"
            scan_record.completed_at = datetime.now(timezone.utc)
            db.session.commit()

            logger.info(f"[SCAN] ✓ Scan {scan_id} completed successfully — {inserted} findings saved.")

        except Exception as exc:
            db.session.rollback()
            logger.error(f"[SCAN] ✗ Scan {scan_id} FAILED: {exc}")
            logger.error(traceback.format_exc())

            try:
                scan_record = db.session.get(Scan, scan_id)
                if scan_record:
                    scan_record.status        = "failed"
                    scan_record.error_message = str(exc)
                    scan_record.completed_at  = datetime.now(timezone.utc)
                    db.session.commit()
            except Exception as inner:
                logger.error(f"[SCAN] Could not even mark scan as failed: {inner}")
