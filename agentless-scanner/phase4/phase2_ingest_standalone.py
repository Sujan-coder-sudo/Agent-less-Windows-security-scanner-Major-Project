import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
import psycopg
from psycopg.rows import dict_row

# =====================
# CONFIG
# =====================

DB_CONFIG = {
    "dbname": "agentless_scanner",
    "user": "postgres",
    "password": "SomSonR@2714",
    "host": "localhost",
    "port": 5432,
}

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PHASE2_PATH = PROJECT_ROOT / "phase2" / "output" / "phase2_exposure.json"

AUTH_ID = "local-admin"

# =====================
# UTILS
# =====================

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def secure_delete(path: Path):
    if not path.exists():
        return
    with open(path, "wb") as f:
        f.write(b"\x00" * path.stat().st_size)
    path.unlink()

# =====================
# VALIDATION + NORMALIZATION
# =====================

def normalize_phase2(data):
    """
    Robust Phase-2 normalizer.
    Extracts hosts from history -> network_exposure structure.
    JSON structure:
    {
      "scanner": "...",
      "history": [
        {
          "scan_id": "...",
          "network_exposure": [
            {
              "host": "127.0.0.1",
              "ports": [
                {"port": 80, "protocol": "tcp", "state": "open", "service": {...}}
              ]
            }
          ]
        }
      ]
    }
    """
    hosts = []

    # Validate top-level structure
    if not isinstance(data, dict):
         raise ValueError(f"Phase-2 data must be a dict, got {type(data)}")

    if "scanner" not in data or "history" not in data:
        raise ValueError(f"Missing required top-level keys. Found: {list(data.keys())}")
    
    history = data["history"]
    if not isinstance(history, list):
         raise ValueError(f"History must be a list, got {type(history)}")

    # Iterate through history entries
    for entry in history:
        if not isinstance(entry, dict):
            continue
        
        # Extract network_exposure from each history entry
        net_exposure = entry.get("network_exposure", [])
        if not isinstance(net_exposure, list):
             continue

        # Process each host in network_exposure
        for host_record in net_exposure:
            if not isinstance(host_record, dict):
                continue
                
            # Extract host IP
            ip = host_record.get("host") or host_record.get("ip")
            if not ip:
                continue

            # Assume host is up if it appears in network_exposure
            is_up = True
            
            # Extract ports
            raw_ports = host_record.get("ports", [])
            if not isinstance(raw_ports, list):
                raw_ports = []
            
            normalized_ports = []
            
            for p in raw_ports:
                if not isinstance(p, dict):
                    continue
                    
                port_num = p.get("port")
                if port_num is None:
                    continue
                    
                svc_data = p.get("service", {})
                if not isinstance(svc_data, dict):
                    svc_data = {}
                
                normalized_ports.append({
                    "port": port_num,
                    "protocol": p.get("protocol", "tcp"),
                    "state": p.get("state", "unknown"),
                    "reason": p.get("reason", "syn-ack"),
                    "service": svc_data
                })

            hosts.append({
                "ip": ip,
                "hostname": host_record.get("hostname"),
                "is_up": is_up,
                "ports": normalized_ports,
                "latency_ms": None  # Not provided in this JSON
            })

    if not hosts:
        raise ValueError("Phase-2 normalization produced ZERO hosts. Check JSON structure.")

    return hosts

# =====================
# DB INIT
# =====================

def create_tables_if_not_exist(conn):
    """Create tables matching schema - DO NOT MODIFY SCHEMA"""
    with conn.cursor() as cur:
        # scans table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id SERIAL PRIMARY KEY,
                auth_id TEXT,
                scan_type TEXT,
                tool TEXT,
                started_at TIMESTAMPTZ,
                completed_at TIMESTAMPTZ,
                source_file_hash TEXT UNIQUE
            )
        """)
        
        # hosts table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS hosts (
                id SERIAL PRIMARY KEY,
                scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
                ip_address TEXT,
                hostname TEXT,
                is_up BOOLEAN
            )
        """)
        
        # ports table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ports (
                id SERIAL PRIMARY KEY,
                host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
                port_number INTEGER,
                protocol TEXT,
                state TEXT,
                reason TEXT
            )
        """)
        
        # services table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS services (
                id SERIAL PRIMARY KEY,
                port_id INTEGER REFERENCES ports(id) ON DELETE CASCADE,
                service_name TEXT,
                product TEXT,
                version TEXT,
                confidence TEXT
            )
        """)
        
        # os_profile table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS os_profile (
                id SERIAL PRIMARY KEY,
                host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
                os_family TEXT,
                os_name TEXT,
                os_accuracy INTEGER
            )
        """)
        
        # network_exposure table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS network_exposure (
                id SERIAL PRIMARY KEY,
                host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
                exposure_type TEXT,
                exposed_port_count INTEGER
            )
        """)
    conn.commit()

# =====================
# INGESTION
# =====================

def ingest_phase2():
    """
    Main ingestion function.
    Maintains FK ordering: scans -> hosts -> ports -> services / network_exposure
    Uses ONE transaction.
    """
    
    print("🔥 Phase-2 ingestion started")

    # 1. Validate file exists
    if not PHASE2_PATH.exists():
        raise FileNotFoundError(f"Phase-2 file not found: {PHASE2_PATH}")

    # 2. Compute hash
    file_hash = sha256_file(PHASE2_PATH)
    print(f"📋 File hash: {file_hash[:16]}...")

    # 3. Load and parse JSON
    with open(PHASE2_PATH, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    print(f"DEBUG - Top-level keys: {list(raw_data.keys())}")

    # 4. Normalize
    hosts = normalize_phase2(raw_data)
    print(f"DEBUG - Extracted {len(hosts)} host(s)")

    if not hosts:
        raise ValueError("CRITICAL: Phase-2 normalization produced ZERO hosts")

    # 5. Database ingestion in ONE transaction
    with psycopg.connect(**DB_CONFIG, row_factory=dict_row) as conn:
        create_tables_if_not_exist(conn)
        
        try:
            with conn.cursor() as cur:
                # Replay protection
                cur.execute(
                    "SELECT id FROM scans WHERE source_file_hash = %s",
                    (file_hash,)
                )
                if cur.fetchone():
                    raise RuntimeError("❌ Scan already ingested (duplicate hash)")

                # BEGIN transaction
                print("🔐 Starting transaction...")
                
                # Insert scan record
                now_utc = datetime.now(timezone.utc)
                cur.execute("""
                    INSERT INTO scans (
                        auth_id, scan_type, tool,
                        started_at, completed_at, source_file_hash
                    )
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING id
                """, (
                    AUTH_ID,
                    "network_exposure",
                    "nmap",
                    now_utc,
                    now_utc,
                    file_hash
                ))

                scan_id = cur.fetchone()["id"]
                print(f"DEBUG - scan_id created: {scan_id}")

                # Counters
                host_count = 0
                port_count = 0
                service_count = 0

                # Insert hosts and related data
                for host in hosts:
                    cur.execute("""
                        INSERT INTO hosts (
                            scan_id, ip_address, hostname, is_up
                        )
                        VALUES (%s, %s, %s, %s)
                        RETURNING id
                    """, (
                        scan_id,
                        host["ip"],
                        host.get("hostname"),
                        host["is_up"]
                    ))

                    host_id = cur.fetchone()["id"]
                    host_count += 1
                    
                    # Track open ports for exposure
                    open_port_count = 0

                    # Insert ports
                    for port_data in host["ports"]:
                        cur.execute("""
                            INSERT INTO ports (
                                host_id, port_number, protocol, state, reason
                            )
                            VALUES (%s, %s, %s, %s, %s)
                            RETURNING id
                        """, (
                            host_id,
                            port_data["port"],
                            port_data["protocol"],
                            port_data["state"],
                            port_data.get("reason")
                        ))

                        port_id = cur.fetchone()["id"]
                        port_count += 1

                        # Count open ports
                        if port_data["state"] == "open":
                            open_port_count += 1

                        # Insert service if present
                        svc = port_data.get("service", {})
                        if svc and svc.get("name"):
                            cur.execute("""
                                INSERT INTO services (
                                    port_id, service_name, product, version, confidence
                                )
                                VALUES (%s, %s, %s, %s, %s)
                            """, (
                                port_id,
                                svc.get("name"),
                                svc.get("product"),
                                svc.get("version"),
                                str(svc.get("confidence", ""))
                            ))
                            service_count += 1

                    # Insert network_exposure for this host
                    cur.execute("""
                        INSERT INTO network_exposure (
                            host_id, exposure_type, exposed_port_count
                        )
                        VALUES (%s, %s, %s)
                    """, (
                        host_id,
                        "port_exposure",
                        open_port_count
                    ))

                # Commit transaction
                conn.commit()
                print("✅ Phase-2 ingestion committed")
                print(f"DEBUG - hosts inserted: {host_count}")
                print(f"DEBUG - ports inserted: {port_count}")
                print(f"DEBUG - services inserted: {service_count}")

        except Exception as e:
            conn.rollback()
            print(f"❌ ROLLBACK: {e}")
            raise

    # 6. Secure delete
    secure_delete(PHASE2_PATH)
    print("🧨 Phase-2 file securely deleted")


# =====================
# ENTRY
# =====================

if __name__ == "__main__":
    ingest_phase2()
