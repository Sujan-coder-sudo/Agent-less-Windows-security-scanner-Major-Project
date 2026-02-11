#!/usr/bin/env python3
"""
Phase 4 - Standalone Ingestion for Phase 3 Output (scan_report.json)

This is production-grade ingestion, not some hacky script you rerun until it works.

This file:
- Lives in agentless-scanner/phase4/phase3_ingest_standalone.py
- Reads Phase 3 output: scan_report.json
- Creates schema (13 categories)
- Inserts normalized data
- Securely disposes sensitive artifacts

Assumptions (Read Carefully):
Your Phase 3 scan_report.json has 13 logical security categories.
If yours does not, fix Phase 3 instead of blaming ingestion.

Expected structure:
The JSON file is an array where the first 13 elements are category objects,
each with: category, command, command_output, summary, logic_reasoning, nvd_correlation

The 13 categories are:
- OS Profiling
- Hotfix Audit
- Software Inventory
- Service Status
- EDR / AV Health
- Audit Policy
- Firewall Rules
- Neighbor Discovery
- Interface Statistics
- Infrastructure Link
- Persistence Mechanisms
- User / Group Audit
- Active Connections

File Path Resolution (Same Discipline as Phase 2):
Hardcoding absolute paths is amateur hour. This is how adults do it.

Database Config:
Use env vars later. For now, focus on correctness.
"""

import json
import psycopg2
import hashlib
import os
from pathlib import Path
from datetime import datetime

# Path resolution using project root
PROJECT_ROOT = Path(__file__).resolve().parents[1]
PHASE3_REPORT = PROJECT_ROOT / "phase3" / "output" / "scan_report.json"

# Database configuration
DB_CONFIG = {
    "dbname": "agentless_scanner",
    "user": "postgres",
    "password": "SomSonR@2714",
    "host": "localhost",
    "port": 5432,
}

# Expected categories - exactly 13
EXPECTED_CATEGORIES = [
    "OS Profiling",
    "Hotfix Audit",
    "Software Inventory",
    "Service Status",
    "EDR / AV Health",
    "Audit Policy",
    "Firewall Rules",
    "Neighbor Discovery",
    "Interface Statistics",
    "Infrastructure Link",
    "Persistence Mechanisms",
    "User / Group Audit",
    "Active Connections",
]


def get_conn():
    """Get PostgreSQL database connection."""
    print(f"[DEBUG] Connecting to database: {DB_CONFIG['dbname']}@{DB_CONFIG['host']}:{DB_CONFIG['port']}")
    return psycopg2.connect(**DB_CONFIG)


def create_schema(cur):
    """
    Create required database schema if it does not exist.
    
    Creates two tables:
    - scan_runs: Tracks unique scan ingestion runs
    - scan_data: Stores categorized scan data as JSONB
    """
    print("[DEBUG] Creating schema if missing...")
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS scan_runs (
            id SERIAL PRIMARY KEY,
            scan_hash TEXT UNIQUE NOT NULL,
            ingested_at TIMESTAMP NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_data (
            id SERIAL PRIMARY KEY,
            scan_id INTEGER REFERENCES scan_runs(id) ON DELETE CASCADE,
            category TEXT NOT NULL,
            payload JSONB NOT NULL
        );
        """
    )
    print("[DEBUG] Schema creation completed")


def load_report():
    """
    Load Phase 3 scan report from JSON file and extract categories using recursive search.
    
    Returns:
        dict: Dictionary mapping category names to their data
        
    Raises:
        FileNotFoundError: If scan_report.json does not exist
        ValueError: If JSON structure is invalid or no categories are found
    """
    print(f"[DEBUG] Resolved Phase 3 report path: {PHASE3_REPORT}")
    print(f"[DEBUG] Phase 3 report exists: {PHASE3_REPORT.exists()}")
    
    if not PHASE3_REPORT.exists():
        raise FileNotFoundError(f"Missing Phase 3 report: {PHASE3_REPORT}")
    
    print(f"[DEBUG] Loading report from: {PHASE3_REPORT}")
    with open(PHASE3_REPORT, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    categories = {}

    def _extract_recursive(obj, depth=0):
        """
        Recursively traverse JSON to find objects with 'category' key.
        """
        indent = "  " * depth
        
        if isinstance(obj, dict):
            # Check if this dict IS a category object
            if "category" in obj:
                cat_name = obj["category"]
                # We only want valid categories from our known list
                if cat_name in EXPECTED_CATEGORIES:
                    categories[cat_name] = obj
                    print(f"[DEBUG] {indent}Found category: {cat_name}")
                return

            # Otherwise traverse values
            # print(f"[DEBUG] {indent}Dict keys: {list(obj.keys())}")
            for key, value in obj.items():
                if isinstance(value, (dict, list)):
                    _extract_recursive(value, depth + 1)
                    
        elif isinstance(obj, list):
            # print(f"[DEBUG] {indent}List length: {len(obj)}")
            for item in obj:
                if isinstance(item, (dict, list)):
                    _extract_recursive(item, depth + 1)

    print("[DEBUG] Starting recursive extraction...")
    _extract_recursive(data)
    
    print(f"[DEBUG] Total categories extracted: {len(categories)}")
    
    if not categories:
        raise ValueError("No categories found in scan_report.json")
        
    return categories


def hash_report(data):
    """
    Generate SHA256 hash of report for duplicate detection.
    
    Args:
        data (dict): Report data to hash
        
    Returns:
        str: Hexadecimal hash string
    """
    raw = json.dumps(data, sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()


def ingest():
    """
    Main ingestion function.
    
    Steps:
    1. Load and validate Phase 3 report
    2. Check for all required categories
    3. Generate hash for duplicate detection
    4. Create schema if needed
    5. Insert scan run record
    6. Insert categorized data
    7. Securely dispose of source file
    
    Raises:
        ValueError: If any required category is missing
        FileNotFoundError: If scan_report.json does not exist
    """
    print("[INFO] Starting Phase 3 ingestion...")
    
    # Load report and extract categories
    categories = load_report()
    
    # Validate all 13 categories are present - fail loudly if any missing
    missing = [c for c in EXPECTED_CATEGORIES if c not in categories]
    if missing:
        error_msg = f"Phase 3 output is incomplete. Missing categories: {missing}"
        print(f"[ERROR] {error_msg}")
        print(f"[ERROR] Found categories: {sorted(categories.keys())}")
        raise ValueError(error_msg)
    
    print("[DEBUG] All 13 required categories present")
    
    # Generate hash for idempotency
    scan_hash = hash_report(categories)
    print(f"[DEBUG] Generated scan hash: {scan_hash}")
    
    # Connect to database
    conn = get_conn()
    try:
        with conn:
            with conn.cursor() as cur:
                # Create schema if needed
                create_schema(cur)
                
                # Insert scan run (or skip if duplicate)
                print("[DEBUG] Inserting scan run record...")
                cur.execute(
                    """
                    INSERT INTO scan_runs (scan_hash, ingested_at)
                    VALUES (%s, %s)
                    ON CONFLICT (scan_hash) DO NOTHING
                    RETURNING id;
                    """,
                    (scan_hash, datetime.utcnow()),
                )
                
                # Get scan_id (either new or existing)
                row = cur.fetchone()
                if row:
                    scan_id = row[0]
                    print(f"[DEBUG] New scan run created with ID: {scan_id}")
                else:
                    cur.execute(
                        "SELECT id FROM scan_runs WHERE scan_hash = %s",
                        (scan_hash,),
                    )
                    scan_id = cur.fetchone()[0]
                    print(f"[DEBUG] Duplicate scan detected, using existing ID: {scan_id}")
                
                # Insert data for each category
                print("[DEBUG] Inserting categorized data...")
                for category_name in EXPECTED_CATEGORIES:
                    print(f"[DEBUG] Inserting category: {category_name}")
                    cur.execute(
                        """
                        INSERT INTO scan_data (scan_id, category, payload)
                        VALUES (%s, %s, %s::jsonb)
                        """,
                        (scan_id, category_name, json.dumps(categories[category_name])),
                    )
                
                print("[INFO] All categories inserted successfully")
        
        # Only dispose after successful commit
        print("[DEBUG] Transaction committed, proceeding with secure disposal...")
        secure_dispose()
        
    finally:
        conn.close()
        print("[DEBUG] Database connection closed")


def secure_dispose():
    """
    Securely wipe Phase 3 output after ingestion.
    Not DoD-grade, but sufficient for local threat models.
    
    Steps:
    1. Overwrite file with random bytes
    2. Delete file
    """
    if PHASE3_REPORT.exists():
        print(f"[DEBUG] Securely disposing: {PHASE3_REPORT}")
        size = PHASE3_REPORT.stat().st_size
        with open(PHASE3_REPORT, "ba+", buffering=0) as f:
            f.seek(0)
            f.write(os.urandom(size))
        PHASE3_REPORT.unlink()
        print("[DEBUG] Secure disposal completed")
    else:
        print("[DEBUG] Report file already removed, skipping disposal")


if __name__ == "__main__":
    try:
        ingest()
        print("[+] Phase 3 scan_report.json ingested and securely disposed")
    except Exception as e:
        print(f"[-] Ingestion failed: {e}")
        raise
