from datetime import datetime, timezone
from extensions import db


class Scan(db.Model):
    """Persistent record of a single security scan run.

    Column notes
    ------------
    timestamp   – original creation column (kept for backward compatibility).
    created_at  – canonical creation timestamp added in Phase-2 migration.
                  New rows populate both; existing rows are backfilled by the
                  migrate_add_created_at.py script.  All ordering queries
                  (order_by, get_latest) use *this* column.
    """
    __tablename__ = "scans"

    # ── Identity ────────────────────────────────────────────────────────────────
    id        = db.Column(db.String(50),  primary_key=True)   # e.g. scan_20240424_...
    scan_type = db.Column(db.String(50),  nullable=False, index=True)  # port_scan | os_inspection
    target    = db.Column(db.String(255), nullable=False, index=True)
    status    = db.Column(db.String(20),  nullable=False, default="pending")  # pending|running|completed|failed

    # ── Timestamps ──────────────────────────────────────────────────────────────
    # timestamp   : kept for backward-compatibility with old rows / JSON exports
    timestamp  = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
    # created_at  : canonical column used by all ordering / history queries
    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=True,   # nullable so ALTER TABLE on existing DB succeeds without a default
        index=True,
    )
    completed_at = db.Column(db.DateTime, nullable=True)

    # ── Summary metrics ─────────────────────────────────────────────────────────
    total_findings = db.Column(db.Integer, default=0)
    risk_score     = db.Column(db.Float,   default=0.0)

    # ── Blob storage ────────────────────────────────────────────────────────────
    summary_json  = db.Column(db.Text, nullable=True)
    error_message = db.Column(db.Text, nullable=True)

    # ── Relationships ───────────────────────────────────────────────────────────
    findings = db.relationship(
        "Finding",
        backref="scan",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    # ── Helpers ─────────────────────────────────────────────────────────────────

    def effective_timestamp(self) -> datetime | None:
        """Return created_at if set, fall back to legacy timestamp."""
        return self.created_at or self.timestamp

    def __repr__(self) -> str:
        return f"<Scan {self.id} ({self.scan_type} on {self.target} – {self.status})>"

    def to_dict(self) -> dict:
        ts = self.effective_timestamp()
        return {
            "id":             self.id,
            "scan_type":      self.scan_type,
            "target":         self.target,
            "status":         self.status,
            # canonical field (used by dashboard / analytics)
            "created_at":     ts.isoformat() + "Z" if ts else None,
            # legacy alias kept so old frontend code continues to work
            "timestamp":      ts.isoformat() + "Z" if ts else None,
            "completed_at":   self.completed_at.isoformat() + "Z" if self.completed_at else None,
            "total_findings": self.total_findings,
            "risk_score":     self.risk_score,
        }
