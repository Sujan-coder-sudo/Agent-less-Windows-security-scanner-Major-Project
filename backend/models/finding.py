from datetime import datetime, timezone
from extensions import db

class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    scan_id = db.Column(db.String(50), db.ForeignKey("scans.id"), nullable=False, index=True)
    
    # Port scan specific
    port = db.Column(db.Integer, nullable=True)
    service = db.Column(db.String(100), nullable=True)
    state = db.Column(db.String(20), nullable=True)
    
    # OS Inspection specific
    category = db.Column(db.String(100), nullable=True, index=True)
    issue = db.Column(db.Text, nullable=True)
    
    # Common fields
    risk_level = db.Column(db.String(20), nullable=False, index=True) # Critical, High, Medium, Low
    note = db.Column(db.Text, nullable=True)
    
    # JSON blobs for flexibility
    cves_json = db.Column(db.Text, nullable=True) # JSON serialized list of CVEs
    raw_data_json = db.Column(db.Text, nullable=True) # The complete raw finding data
    
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<Finding {self.id} for Scan {self.scan_id} (Risk: {self.risk_level})>"
