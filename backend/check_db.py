import sys
import os

# Setup path so we can import app
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app
from extensions import db
from models.scan import Scan

with app.app_context():
    scans = Scan.query.all()
    print(f"Total scans: {len(scans)}")
    for s in scans:
        print(f"Scan {s.id}: status={s.status}, findings={s.findings.count()}")
