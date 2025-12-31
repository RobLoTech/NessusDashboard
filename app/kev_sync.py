import json
import os
from datetime import datetime, timezone
import requests

from sqlalchemy import create_engine, text

KEV_FILE = os.environ.get('KEV_FILE')

KEV_URL = os.environ.get(
    "KEV_URL",
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
)

def fetch_json_from_file(path: str) -> dict:
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def fetch_json(url: str) -> dict:
    headers = {
        "User-Agent": "Mozilla/5.0 (nessus-kev-dashboard)",
        "Accept": "application/json,text/plain,*/*",
    }
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    return r.json()

def main():
    db_url = os.environ["DATABASE_URL"]
    engine = create_engine(db_url, future=True)
    now = datetime.now(timezone.utc)

    data = fetch_json_from_file(KEV_FILE) if KEV_FILE else fetch_json(KEV_URL)
    vulns = data.get("vulnerabilities", [])
    if not vulns:
        raise SystemExit("No vulnerabilities found in KEV feed (unexpected)")

    with engine.begin() as conn:
        snap_id = conn.execute(
            text("""
                INSERT INTO kev_catalog (id, pulled_at, source_url, record_count)
                VALUES (gen_random_uuid(), :pulled_at, :url, :cnt)
                RETURNING id
            """),
            {"pulled_at": now, "url": KEV_URL, "cnt": len(vulns)},
        ).scalar_one()

        # store the cves for this snapshot
        for v in vulns:
            cve = (v.get("cveID") or "").strip().upper()
            if not cve:
                continue
            conn.execute(
                text("""
                    INSERT INTO kev_catalog_entries
                    (snapshot_id, cve, vendor_project, product, vulnerability_name, date_added, due_date, required_action, known_ransomware_campaign_use)
                    VALUES
                    (:sid, :cve, :vendor, :product, :name, :date_added, :due_date, :action, :ransom)
                    ON CONFLICT (snapshot_id, cve) DO NOTHING
                """),
                {
                    "sid": str(snap_id),
                    "cve": cve,
                    "vendor": v.get("vendorProject"),
                    "product": v.get("product"),
                    "name": v.get("vulnerabilityName"),
                    "date_added": v.get("dateAdded"),
                    "due_date": v.get("dueDate"),
                    "action": v.get("requiredAction"),
                    "ransom": v.get("knownRansomwareCampaignUse"),
                },
            )

        # match ALL our CVEs against this snapshot (strict CVE-level truth)
        conn.execute(
            text("""
                INSERT INTO kev_matches (snapshot_id, cve, matched_at)
                SELECT :sid, c.cve, :now
                FROM cves c
                JOIN kev_catalog_entries k
                  ON k.snapshot_id = :sid AND k.cve = c.cve
                ON CONFLICT (snapshot_id, cve) DO NOTHING
            """),
            {"sid": str(snap_id), "now": now},
        )

    print(f"OK: KEV snapshot inserted: {len(vulns)} entries")

if __name__ == "__main__":
    main()
