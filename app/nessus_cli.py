import os
DATABASE_URL = os.environ.get('DATABASE_URL')
import time
import json
import hashlib
import pathlib
import httpx
import typer
from rich import print
from rich.table import Table
import csv
from datetime import datetime, timezone
from sqlalchemy import create_engine, text

def ingest_csv_to_raw(database_url: str, csv_path: str, file_sha256: str, scan_id: int, scan_name: str, folder_id: int | None, folder_name: str | None):
    import csv
    import json
    from datetime import datetime, timezone
    from sqlalchemy import create_engine, text

    engine = create_engine(database_url)
    now = datetime.now(timezone.utc)

    # 1) Ensure raw_ingests row exists (idempotent by file_sha256)
    with engine.begin() as conn:
        conn.execute(text("""
            INSERT INTO raw_ingests (id, source, nessus_scan_id, scan_name, folder_id, exported_at, file_sha256, row_count, ingested_at)
            VALUES (gen_random_uuid(), 'nessus', :nessus_scan_id, :scan_name, :folder_id, :exported_at, :sha, 0, :now)
            ON CONFLICT (file_sha256) DO NOTHING
        """), {
            "nessus_scan_id": int(scan_id),
            "scan_name": scan_name,
            "folder_id": folder_id,
            "exported_at": now,
            "sha": file_sha256,
            "now": now,
        })

        ingest_id = conn.execute(
            text("SELECT id FROM raw_ingests WHERE file_sha256 = :sha"),
            {"sha": file_sha256},
        ).scalar_one()

    # 2) Stream CSV and insert rows (idempotent by (ingest_id, row_num))
    row_count = 0
    with open(csv_path, "r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        with engine.begin() as conn:
            for row in reader:
                row_count += 1
                conn.execute(text("""
                    INSERT INTO raw_nessus_rows (ingest_id, row_num, row_json)
                    VALUES (:ingest_id, :row_num, CAST(:row_json AS jsonb))
                    ON CONFLICT (ingest_id, row_num) DO NOTHING
                """), {
                    "ingest_id": ingest_id,
                    "row_num": row_count,
                    "row_json": json.dumps(row),
                })

            conn.execute(text("""
                UPDATE raw_ingests
                SET row_count = :row_count
                WHERE id = :ingest_id
            """), {"row_count": row_count, "ingest_id": ingest_id})

    return row_count
app = typer.Typer(add_completion=False)

EXPORT_DIR = pathlib.Path("/app/exports")  # bind-mounted via Dockerfile copy; we’ll copy out to host by writing into /app then docker cp if needed

def _base():
    url = os.environ.get("NESSUS_URL")
    ak = os.environ.get("NESSUS_ACCESS_KEY")
    sk = os.environ.get("NESSUS_SECRET_KEY")
    if not url or not ak or not sk:
        raise typer.BadParameter("Set NESSUS_URL, NESSUS_ACCESS_KEY, NESSUS_SECRET_KEY env vars.")
    return url.rstrip("/"), ak, sk

def _headers(ak: str, sk: str):
    return {"X-ApiKeys": f"accessKey={ak}; secretKey={sk};", "Accept": "application/json"}

def _client(verify_ssl: bool):
    return httpx.Client(verify=verify_ssl, timeout=120)

@app.command()
def folders(verify_ssl: bool = False):
    url, ak, sk = _base()
    with _client(verify_ssl) as c:
        r = c.get(f"{url}/folders", headers=_headers(ak, sk))
        r.raise_for_status()
        data = r.json()

    tbl = Table(title="Nessus Folders")
    tbl.add_column("id", style="cyan")
    tbl.add_column("name")
    for f in data.get("folders", []):
        tbl.add_row(str(f.get("id")), str(f.get("name")))
    print(tbl)

@app.command()
def scans(verify_ssl: bool = False):
    url, ak, sk = _base()
    with _client(verify_ssl) as c:
        r = c.get(f"{url}/scans", headers=_headers(ak, sk))
        r.raise_for_status()
        data = r.json()

    tbl = Table(title="Nessus Scans")
    tbl.add_column("scan_id", style="cyan")
    tbl.add_column("name")
    tbl.add_column("folder_id")
    tbl.add_column("last_mod", justify="right")
    for s in data.get("scans", []):
        lm = s.get("last_modification_date")
        lm_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(lm)) if isinstance(lm, int) and lm > 0 else ""
        tbl.add_row(str(s.get("id")), str(s.get("name")), str(s.get("folder_id")), lm_str)
    print(tbl)

@app.command()
def export_csv(
    scan_id: int = typer.Argument(...),
    verify_ssl: bool = False,
):
    """
    Export a scan as Nessus CSV and save it locally (inside container at /app/exports).
    """
    url, ak, sk = _base()
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)

    headers = _headers(ak, sk)
    with _client(verify_ssl) as c:
        # 1) Request export
        # Request export with explicit columns (so CSV includes VPR/EPSS/CVSSv4)
        payload = {
            "format": "csv",
            "reportContents": {
                "csvColumns": {
                    "id": True,
                    "cve": True,
                    "cvss": True,  # Nessus' default CVSS column (often v2 label in CSV)
                    "risk": True,
                    "hostname": True,
                    "protocol": True,
                    "port": True,
                    "plugin_name": True,
                    "synopsis": True,
                    "description": True,
                    "solution": True,
                    "see_also": True,
                    "plugin_output": True,

                    # add-on columns
                    "cvss4_base_score": True,
                    "cvss4_bt_score": True,
                    "cvss3_base_score": True,
                    "vpr_score": True,
                    "epss_score": True,
                    "risk_factor": True,
                }
            },
        }

        r = c.post(f"{url}/scans/{scan_id}/export", headers=headers, json=payload)

        r.raise_for_status()
        file_id = r.json().get("file")
        if not file_id:
            raise RuntimeError(f"Unexpected export response: {r.text}")

        # 2) Poll status
        while True:
            s = c.get(f"{url}/scans/{scan_id}/export/{file_id}/status", headers=headers)
            s.raise_for_status()
            status = s.json().get("status")
            if status == "ready":
                break
            if status == "error":
                raise RuntimeError(f"Export status error: {s.text}")
            time.sleep(1)

        # 3) Download
        d = c.get(f"{url}/scans/{scan_id}/export/{file_id}/download", headers=headers)
        d.raise_for_status()
        content = d.content

    sha = hashlib.sha256(content).hexdigest()
    ts = time.strftime("%Y%m%d_%H%M%S")
    out = EXPORT_DIR / f"scan_{scan_id}_{ts}_{sha[:12]}.csv"
    out.write_bytes(content)

    print(f"[green]Saved:[/green] {out}")
    print(f"[green]Bytes:[/green] {len(content)}")
    print(f"[green]SHA256:[/green] {sha}")

@app.command()
def export_nessus(
    scan_id: int = typer.Argument(...),
    verify_ssl: bool = False,
):
    """
    Export a scan as .nessus (XML) and save it locally (inside container at /app/exports).
    """
    url, ak, sk = _base()
    EXPORT_DIR.mkdir(parents=True, exist_ok=True)

    headers = _headers(ak, sk)
    with _client(verify_ssl) as c:
        # 1) Request export
        r = c.post(f"{url}/scans/{scan_id}/export", headers=headers, json={"format": "nessus"})
        r.raise_for_status()
        file_id = r.json().get("file")
        if not file_id:
            raise RuntimeError(f"Unexpected export response: {r.text}")

        # 2) Poll status
        while True:
            s = c.get(f"{url}/scans/{scan_id}/export/{file_id}/status", headers=headers)
            s.raise_for_status()
            status = s.json().get("status")
            if status == "ready":
                break
            if status == "error":
                raise RuntimeError(f"Export status error: {s.text}")
            time.sleep(1)

        # 3) Download
        d = c.get(f"{url}/scans/{scan_id}/export/{file_id}/download", headers=headers)
        d.raise_for_status()
        content = d.content

    sha = hashlib.sha256(content).hexdigest()
    ts = time.strftime("%Y%m%d_%H%M%S")
    out = EXPORT_DIR / f"scan_{scan_id}_{ts}_{sha[:12]}.nessus"
    out.write_bytes(content)

    print(f"[green]Saved:[/green] {out}")
    print(f"[green]Bytes:[/green] {len(content)}")
    print(f"[green]SHA256:[/green] {sha}")

if __name__ == "__main__":
    app()