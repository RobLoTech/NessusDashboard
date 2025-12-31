import csv
import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, text

CSV_PATH = os.environ.get("CSV_PATH")  # required
SOURCE = os.environ.get("INGEST_SOURCE", "nessus_pro")
NESSUS_SCAN_ID = os.environ.get("NESSUS_SCAN_ID")  # optional
SCAN_NAME = os.environ.get("SCAN_NAME", "unknown")
FOLDER_ID = os.environ.get("FOLDER_ID")  # optional

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def norm_int(v):
    try:
        return int(v)
    except Exception:
        return None

def main():
    if not CSV_PATH:
        raise SystemExit("CSV_PATH env var required")
    p = Path(CSV_PATH)
    if not p.exists():
        raise SystemExit(f"CSV not found: {p}")

    db_url = os.environ["DATABASE_URL"]
    engine = create_engine(db_url, future=True)

    file_sha = sha256_file(p)

    exported_at = datetime.now(timezone.utc)

    # Read CSV rows
    rows = []
    with p.open(newline="", encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f)
        for i, r in enumerate(reader, start=1):
            # pull common fields if present (best-effort; raw JSON still stores everything)
            sev = norm_int(r.get("Severity"))
            plugin_id = norm_int(r.get("Plugin ID") or r.get("PluginID") or r.get("plugin_id"))
            plugin_name = r.get("Name") or r.get("Plugin Name") or r.get("plugin_name")
            cve_text = r.get("CVE") or r.get("Cves") or r.get("cve")

            host_ip = r.get("Host") or r.get("IP Address") or r.get("IP") or r.get("host")
            host_fqdn = r.get("FQDN") or r.get("DNS Name") or r.get("Hostname") or r.get("host_name")

            port = norm_int(r.get("Port"))
            protocol = (r.get("Protocol") or "").strip() or None

            rows.append({
                "row_num": i,
                "row_json": r,  # exact row dict (near-source)
                "severity": sev,
                "plugin_id": plugin_id,
                "plugin_name": plugin_name,
                "cve_text": cve_text,
                "host_ip": host_ip,
                "host_fqdn": host_fqdn,
                "port": port,
                "protocol": protocol,
            })

    with engine.begin() as conn:
        # sha256 guard: never ingest same file twice
        existing = conn.execute(
            text("SELECT id FROM raw_ingests WHERE file_sha256 = :sha"),
            {"sha": file_sha},
        ).fetchone()
        if existing:
            print(f"SKIP: already ingested sha256={file_sha}")
            return

        ingest_id = conn.execute(
            text("""
                INSERT INTO raw_ingests
                (id, source, nessus_scan_id, scan_name, folder_id, exported_at, file_sha256, row_count, ingested_at)
                VALUES
                (gen_random_uuid(), :source, :scan_id, :scan_name, :folder_id, :exported_at, :sha, :row_count, :ingested_at)
                RETURNING id
            """),
            {
                "source": SOURCE,
                "scan_id": int(NESSUS_SCAN_ID) if NESSUS_SCAN_ID else None,
                "scan_name": SCAN_NAME,
                "folder_id": int(FOLDER_ID) if FOLDER_ID else None,
                "exported_at": exported_at,
                "sha": file_sha,
                "row_count": len(rows),
                "ingested_at": exported_at,
            },
        ).scalar_one()

        conn.execute(
            text("""
                INSERT INTO raw_nessus_rows
                (ingest_id, row_num, row_json, severity, plugin_id, plugin_name, cve_text, host_ip, host_fqdn, port, protocol)
                VALUES
                (:ingest_id, :row_num, CAST(:row_json AS jsonb), :severity, :plugin_id, :plugin_name, :cve_text,
                 CAST(NULLIF(:host_ip,'') AS inet), NULLIF(:host_fqdn,''), :port, NULLIF(:protocol,''))
            """),
            [
                {
                    "ingest_id": str(ingest_id),
                    "row_num": r["row_num"],
                    "row_json": json.dumps(r["row_json"]),
                    "severity": r["severity"],
                    "plugin_id": r["plugin_id"],
                    "plugin_name": r["plugin_name"],
                    "cve_text": r["cve_text"],
                    "host_ip": r["host_ip"] or "",
                    "host_fqdn": r["host_fqdn"] or "",
                    "port": r["port"],
                    "protocol": r["protocol"] or "",
                }
                for r in rows
            ],
        )

    print(f"OK: ingested sha256={file_sha} rows={len(rows)}")

if __name__ == "__main__":
    main()
