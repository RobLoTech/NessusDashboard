import os
import re
from datetime import datetime, timezone

from sqlalchemy import create_engine, text

INGEST_SHA256 = os.environ.get("INGEST_SHA256")  # required
SCANNER_URL = os.environ.get("NESSUS_URL", "unknown").rstrip("/")
FOLDER_NAME = os.environ.get("FOLDER_NAME")  # optional

# Nessus severity mapping (typical): 0=Info,1=Low,2=Medium,3=High,4=Critical
SEV_LABEL = {0: "Informational", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}

def clean_inet(s: str) -> str:
    s = (s or '').strip()
    if not s:
        return ''
    # Nessus sometimes gives ip/mask like 10.0.0.1/32; inet expects plain IP
    if '/' in s:
        s = s.split('/', 1)[0]
    return s

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

def extract_cves(cve_text: str | None) -> list[str]:
    if not cve_text:
        return []
    # Nessus CSV often uses comma-separated CVEs; also tolerate whitespace/semicolons
    hits = CVE_RE.findall(cve_text)
    return sorted({h.upper() for h in hits})

def main():
    if not INGEST_SHA256:
        raise SystemExit("INGEST_SHA256 env var required (sha256 of raw_ingests.file_sha256)")

    db_url = os.environ["DATABASE_URL"]
    engine = create_engine(db_url, future=True)

    now = datetime.now(timezone.utc)

    with engine.begin() as conn:
        ingest = conn.execute(
            text("""
                SELECT id, source, nessus_scan_id, scan_name, folder_id, exported_at
                FROM raw_ingests
                WHERE file_sha256 = :sha
            """),
            {"sha": INGEST_SHA256},
        ).fetchone()
        if not ingest:
            raise SystemExit(f"No raw_ingest found for sha256={INGEST_SHA256}")

        ingest_id, source, nessus_scan_id, scan_name, folder_id, exported_at = ingest

        # Create/lookup scan record (unique by nessus_scan_id + exported_at per our schema)
        scan_row = conn.execute(
            text("""
                SELECT id FROM scans
                WHERE nessus_scan_id = :scan_id AND exported_at = :exported_at
            """),
            {"scan_id": int(nessus_scan_id) if nessus_scan_id is not None else 0, "exported_at": exported_at},
        ).fetchone()

        if scan_row:
            scan_uuid = scan_row[0]
        else:
            # if nessus_scan_id missing, we still store scan with a placeholder 0; MVP acceptable for now
            scan_uuid = conn.execute(
                text("""
                    INSERT INTO scans
                    (id, nessus_scan_id, scan_name, folder_id, folder_name, scanner_url, scan_start, scan_end, exported_at)
                    VALUES
                    (gen_random_uuid(), :nessus_scan_id, :scan_name, :folder_id, :folder_name, :scanner_url, NULL, NULL, :exported_at)
                    RETURNING id
                """),
                {
                    "nessus_scan_id": int(nessus_scan_id) if nessus_scan_id is not None else 0,
                    "scan_name": scan_name,
                    "folder_id": int(folder_id) if folder_id is not None else None,
                    "folder_name": FOLDER_NAME,
                    "scanner_url": SCANNER_URL,
                    "exported_at": exported_at,
                },
            ).scalar_one()

        raw_rows = conn.execute(
            text("""
                SELECT row_num, row_json, severity, plugin_id, plugin_name, (row_json->>'CVE') as cve_text, host_ip::text, host_fqdn, port, protocol
                FROM raw_nessus_rows
                WHERE ingest_id = :ingest_id
                ORDER BY row_num
            """),
            {"ingest_id": str(ingest_id)},
        ).fetchall()

        for row in raw_rows:
            row_num, row_json, sev, plugin_id, plugin_name, cve_text, host_ip, host_fqdn, port, protocol = row

            if plugin_id is None:
                # can't normalize without plugin_id; keep raw only
                continue

            sev_num = int(sev) if sev is not None else 0
            sev_label = SEV_LABEL.get(sev_num, "Informational")
            is_info = (sev_num == 0)

            # ---- Plugin upsert ----
            conn.execute(
                text("""
                    INSERT INTO plugins (plugin_id, plugin_name, family, synopsis, solution, cvss_base)
                    VALUES (:pid, :pname, NULL, NULL, NULL, NULL)
                    ON CONFLICT (plugin_id) DO UPDATE SET plugin_name = EXCLUDED.plugin_name
                """),
                {"pid": int(plugin_id), "pname": plugin_name or f"plugin_{plugin_id}"},
            )

            # ---- Asset identify ----
            # Nessus CSV "Host" is often a DNS/FQDN for credentialed scans.
            # Prefer IP when Host/IP is actually an IP; otherwise treat Host as FQDN.
            host_from_json = None
            try:
                # row_json is jsonb coming back from Postgres; SQLAlchemy may return it as dict already.
                if isinstance(row_json, dict):
                    host_from_json = (row_json.get("Host") or "").strip()
                elif isinstance(row_json, str):
                    # fallback: if somehow it's a string, avoid importing json at top-level
                    import json as _json
                    host_from_json = (_json.loads(row_json).get("Host") or "").strip()
            except Exception:
                host_from_json = None

            raw_host = (host_from_json or "").strip()
            ip = clean_inet(host_ip or "")
            fqdn = (host_fqdn or "").strip()

            # If Host looks like a DNS name and host_ip is empty, use Host as canonical
            # If host_ip exists, canonicalize as IP (current MVP behavior)
            if ip:
                canonical = ip
                # also treat raw_host as fqdn identity if it isn't an IP
                if raw_host and raw_host != ip and "." in raw_host:
                    fqdn = fqdn or raw_host
            else:
                canonical = (raw_host or fqdn or "unknown").strip()

            # normalize canonical for fqdn-ish values
            if canonical != "unknown" and "/" not in canonical and "." in canonical:
                canonical = canonical.lower()

            # Upsert asset by canonical_name (MVP)
            asset_uuid = conn.execute(
                text("""
                    INSERT INTO assets (id, canonical_name, first_seen, last_seen)
                    VALUES (gen_random_uuid(), :cn, :now, :now)
                    ON CONFLICT (canonical_name) DO UPDATE SET last_seen = EXCLUDED.last_seen
                    RETURNING id
                """),
                {"cn": canonical, "now": now},
            ).scalar_one()

            # identity rows (best-effort, ignore conflicts)
            if ip:
                conn.execute(
                    text("""
                        INSERT INTO asset_identities (id, asset_id, identity_type, identity_value, ip_value, first_seen, last_seen)
                        VALUES (gen_random_uuid(), :aid, 'ip', :val_text, CAST(:val_inet AS inet), :now, :now)
                        ON CONFLICT (identity_type, identity_value) DO UPDATE SET last_seen = EXCLUDED.last_seen
                    """),
                    {"aid": str(asset_uuid), "val_text": ip, "val_inet": ip, "now": now},
                )

            # treat fqdn as either host_fqdn OR Host (when Host is dns)
            if fqdn:
                fqdn_norm = fqdn.strip().lower()
                conn.execute(
                    text("""
                        INSERT INTO asset_identities (id, asset_id, identity_type, identity_value, ip_value, first_seen, last_seen)
                        VALUES (gen_random_uuid(), :aid, 'fqdn', :val, NULL, :now, :now)
                        ON CONFLICT (identity_type, identity_value) DO UPDATE SET last_seen = EXCLUDED.last_seen
                    """),
                    {"aid": str(asset_uuid), "val": fqdn_norm, "now": now},
                )

            # ---- Finding (remediation unit) upsert: asset + plugin ----
            finding_uuid = conn.execute(
                text("""
                    INSERT INTO findings
                    (id, asset_id, plugin_id, severity_label, severity_nessus, first_seen, last_seen, status, is_informational)
                    VALUES
                    (gen_random_uuid(), :asset_id, :plugin_id, :sev_label, :sev_num, :now, :now, 'open', :is_info)
                    ON CONFLICT (asset_id, plugin_id) DO UPDATE
                      SET last_seen = EXCLUDED.last_seen,
                          severity_label = EXCLUDED.severity_label,
                          severity_nessus = EXCLUDED.severity_nessus,
                          is_informational = EXCLUDED.is_informational
                    RETURNING id
                """),
                {
                    "asset_id": str(asset_uuid),
                    "plugin_id": int(plugin_id),
                    "sev_label": sev_label,
                    "sev_num": sev_num,
                    "is_info": is_info,
                    "now": now,
                },
            ).scalar_one()

            # ---- Finding instance (evidence per scan row) ----
            conn.execute(
                text("""
                    INSERT INTO finding_instances (id, finding_id, scan_id, port, protocol, plugin_output)
                    VALUES (gen_random_uuid(), :fid, :sid, :port, :proto, NULL)
                    ON CONFLICT DO NOTHING
                """),
                {
                    "fid": str(finding_uuid),
                    "sid": str(scan_uuid),
                    "port": int(port) if port is not None else None,
                    "proto": (protocol or "").strip() or None,
                },
            )
            # ---- Extract CVSS / VPR / EPSS from CSV row ----
            def _as_float(v):
                if v is None:
                    return None
                v = str(v).strip()
                if v == "" or v.lower() in {"na", "n/a", "none"}:
                    return None
                try:
                    return float(v)
                except ValueError:
                    return None

            cvss_v2 = cvss_v3 = cvss_v4 = vpr = epss = None

            if isinstance(row_json, dict):
                cvss_v2 = _as_float(row_json.get("CVSS v2.0 Base Score"))
                cvss_v3 = _as_float(row_json.get("CVSS v3.0 Base Score"))
                cvss_v4 = _as_float(row_json.get("CVSS v4.0 Base Score"))
                vpr     = _as_float(row_json.get("VPR Score"))
                epss    = _as_float(row_json.get("EPSS Score"))

            # ---- CVE truth layer from CSV column ----
            for cve in extract_cves(cve_text):
                conn.execute(
                    text("""
                        INSERT INTO cve_scores
                        (cve_id, cvss_v2_base, cvss_v3_base, cvss_v4_base,
                        vpr_score, epss_score, data_source, first_seen, last_updated)
                        VALUES
                        (:cve, :cvss2, :cvss3, :cvss4, :vpr, :epss, 'nessus_csv', :now, :now)
                        ON CONFLICT (cve_id) DO UPDATE SET
                        cvss_v2_base = COALESCE(EXCLUDED.cvss_v2_base, cve_scores.cvss_v2_base),
                        cvss_v3_base = COALESCE(EXCLUDED.cvss_v3_base, cve_scores.cvss_v3_base),
                        cvss_v4_base = COALESCE(EXCLUDED.cvss_v4_base, cve_scores.cvss_v4_base),
                        vpr_score    = COALESCE(EXCLUDED.vpr_score,    cve_scores.vpr_score),
                        epss_score   = COALESCE(EXCLUDED.epss_score,   cve_scores.epss_score),
                        last_updated = EXCLUDED.last_updated
                    """),
                    {
                        "cve": cve,
                        "cvss2": cvss_v2,
                        "cvss3": cvss_v3,
                        "cvss4": cvss_v4,
                        "vpr": vpr,
                        "epss": epss,
                        "now": now,
                    },
                )

                conn.execute(
                    text("""
                        INSERT INTO finding_cves (finding_id, cve, source)
                        VALUES (:fid, :cve, 'csv')
                        ON CONFLICT (finding_id, cve) DO NOTHING
                    """),
                    {"fid": str(finding_uuid), "cve": cve},
                )

    print("OK: normalized ingest", INGEST_SHA256)

if __name__ == "__main__":
    main()
