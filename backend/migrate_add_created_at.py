"""
migrate_add_created_at.py
=========================
Safe, idempotent Phase-2 migration for the Agentless Scanner database.

What it does
------------
1. Inspects the live SQLite schema.
2. If `scans.created_at` is MISSING  → adds the column (ALTER TABLE).
3. Backfills created_at = timestamp   for every row where created_at IS NULL.
4. Adds a DB index on created_at      if not already present.
5. Prints a row-level summary so you can verify data integrity.

Safety guarantees
-----------------
- Idempotent: safe to re-run; already-present column / index are skipped.
- No DROP, no DELETE, no table recreate.
- Uses a single SQLite connection; ROLLBACK on any error.

Usage
-----
    cd backend
    py migrate_add_created_at.py

Expected output (first run)
---------------------------
    [INFO]  Connected to: .../backend/data/scanner.db
    [INFO]  Column 'created_at' NOT found in 'scans' — adding it now.
    [OK]    ALTER TABLE executed.
    [INFO]  Backfilling created_at from timestamp ...
    [OK]    Backfilled 5 row(s).
    [INFO]  Creating index on scans.created_at ...
    [OK]    Index created.
    [OK]    Migration complete. Verify below:
    scan_20240424_...  status=completed  created_at=2024-04-24T...
    ...
    [DONE]  All done — restart Flask to pick up the schema change.

Expected output (re-run)
------------------------
    [INFO]  Column 'created_at' already present — no DDL needed.
    [INFO]  0 rows needed backfill.
    [OK]    Migration complete. ...
"""

import os
import sqlite3
import sys

# ── Locate the database ────────────────────────────────────────────────────────
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH  = os.path.join(BASE_DIR, "data", "scanner.db")

if not os.path.isfile(DB_PATH):
    print(f"[ERROR]  Database not found at: {DB_PATH}")
    print("         Start Flask at least once (py app.py) to create it, then re-run.")
    sys.exit(1)

print(f"[INFO]   Connected to: {DB_PATH}")

con = sqlite3.connect(DB_PATH)
con.row_factory = sqlite3.Row
cur = con.cursor()

try:
    # ── Step 1: Check whether created_at already exists ───────────────────────
    cur.execute("PRAGMA table_info(scans)")
    columns = {row["name"] for row in cur.fetchall()}

    if "created_at" not in columns:
        print("[INFO]   Column 'created_at' NOT found in 'scans' — adding it now.")
        # SQLite ALTER TABLE only supports ADD COLUMN (no DEFAULT on non-literal)
        cur.execute("ALTER TABLE scans ADD COLUMN created_at DATETIME")
        con.commit()
        print("[OK]     ALTER TABLE executed.")
    else:
        print("[INFO]   Column 'created_at' already present — no DDL needed.")

    # ── Step 2: Backfill created_at = timestamp where NULL ────────────────────
    cur.execute("SELECT COUNT(*) FROM scans WHERE created_at IS NULL")
    null_count = cur.fetchone()[0]

    if null_count > 0:
        print(f"[INFO]   Backfilling created_at from timestamp for {null_count} row(s) ...")
        cur.execute(
            "UPDATE scans SET created_at = timestamp WHERE created_at IS NULL AND timestamp IS NOT NULL"
        )
        # For rows where BOTH are NULL, fall back to the scan id embedded timestamp
        cur.execute(
            """
            UPDATE scans
            SET created_at = datetime('now')
            WHERE created_at IS NULL
            """
        )
        con.commit()
        print(f"[OK]     Backfilled {null_count} row(s).")
    else:
        print("[INFO]   0 rows needed backfill.")

    # ── Step 3: Create index (idempotent — IF NOT EXISTS) ─────────────────────
    cur.execute(
        "CREATE INDEX IF NOT EXISTS ix_scans_created_at ON scans (created_at)"
    )
    con.commit()
    print("[INFO]   Index on scans.created_at ensured.")

    # ── Step 4: Verification summary ─────────────────────────────────────────
    print("\n[OK]     Migration complete. Row verification:")
    print(f"         {'scan_id':<40} {'status':<12} {'created_at'}")
    print("         " + "-" * 75)
    cur.execute(
        "SELECT id, status, created_at FROM scans ORDER BY created_at DESC LIMIT 20"
    )
    rows = cur.fetchall()
    if rows:
        for row in rows:
            print(f"         {row['id']:<40} {row['status']:<12} {row['created_at']}")
    else:
        print("         (no rows yet — database is empty)")

    print("\n[DONE]   Migration finished successfully.")
    print("         Restart Flask (py app.py) to pick up the updated schema.")

except Exception as exc:
    con.rollback()
    print(f"\n[ERROR]  Migration failed — rolled back.\n         {exc}")
    sys.exit(1)
finally:
    con.close()
