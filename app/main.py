from typing import Optional, Literal
import os
import csv
import io

from fastapi import FastAPI, Query, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy import create_engine, text
from api.kev import router as kev_router


app = FastAPI(title="Nessus KEV Dashboard Builder")

# Routers
app.include_router(kev_router)


@app.get("/healthz")
def healthz():
    return {"status": "ok"}


def _get_engine():
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL is not set (expected in .env / container env)")
    return create_engine(db_url, pool_pre_ping=True)


engine = _get_engine()

# --- allowed ORDER BY columns (prevents SQL injection) ---
SORT_MAP = {
    "triage": """(CASE due_status
        WHEN 'OVERDUE' THEN 0
        WHEN 'DUE_SOON' THEN 1
        WHEN 'OK' THEN 2
        ELSE 3 END)""",
    "priority_bucket": "priority_bucket",
    "kev_cve_count": "kev_cve_count",
    "affected_asset_count": "affected_asset_count",
    "max_severity_nessus": "max_severity_nessus",
    "kev_earliest_due_date": "kev_earliest_due_date",
    "last_seen": "last_seen",
    "remediation_key": "remediation_key",
}


@app.get("/api/remediation-actions")
def kev_remediation_actions(
    has_kev: Optional[bool] = Query(default=None),
    remediation_type: Optional[Literal["kb", "plugin"]] = Query(default=None),
    min_severity_nessus: Optional[int] = Query(default=None, ge=0, le=4),
    search: Optional[str] = Query(default=None),
    sort_by: Literal[
        "triage",
        "kev_cve_count",
        "affected_asset_count",
        "max_severity_nessus",
        "kev_earliest_due_date",
        "last_seen",
        "remediation_key",
    ] = "triage",
    sort_dir: Literal["asc", "desc"] = "desc",
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    order_col = SORT_MAP[sort_by]

    # triage always uses a fixed direction (most urgent first)
    if sort_by == "triage":
        order_by_sql = (
            " priority_bucket ASC, "
            " days_to_due ASC NULLS LAST, "
            " kev_cve_count DESC, "
            " affected_asset_count DESC, "
            " max_severity_nessus DESC, "
            " remediation_key ASC "
        )
    else:
        order_dir = "ASC" if sort_dir == "asc" else "DESC"
        order_by_sql = f"{order_col} {order_dir} NULLS LAST"



    where = []
    params = {}

    if has_kev is True:
        where.append("kev_cve_count > 0")
    elif has_kev is False:
        where.append("kev_cve_count = 0")

    if remediation_type:
        where.append("remediation_type = :remediation_type")
        params["remediation_type"] = remediation_type

    if min_severity_nessus is not None:
        where.append("max_severity_nessus >= :min_sev")
        params["min_sev"] = min_severity_nessus

    if search:
        where.append("(remediation_key ILIKE :q OR remediation_title ILIKE :q)")
        params["q"] = f"%{search}%"

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    total_sql = text(f"""
        SELECT COUNT(*)::int
        FROM kev_remediation_actions_mv
        {where_sql}
    """)

    items_sql = text(f"""
        SELECT
          remediation_key,
          remediation_type,
          remediation_title,
          priority_bucket,
          plugin_ids,
          affected_asset_count,
          affected_assets,
          finding_count,
          max_severity_nessus,
          max_severity_label,
          kev_cve_count,
          cves_all,
          kev_cves,
          kev_earliest_due_date,
          days_to_due,
          due_status,
          kev_due_dates,
          kev_required_actions,
          kev_known_ransomware_flags,
          first_seen,
          last_seen
        FROM kev_remediation_actions_mv
        {where_sql}
        ORDER BY {order_by_sql}
        LIMIT :limit OFFSET :offset
    """)

    params["limit"] = limit
    params["offset"] = offset

    with engine.connect() as conn:
        total = conn.execute(total_sql, params).scalar_one()
        rows = conn.execute(items_sql, params).mappings().all()

    return {"total": total, "limit": limit, "offset": offset, "items": [dict(r) for r in rows]}

from fastapi import HTTPException  # add near the top with other imports


@app.get("/api/remediation-actions/{remediation_key}")
def kev_remediation_action_detail(
    remediation_key: str,
    include_non_kev_cves: bool = Query(
        default=False,
        description="false = only KEV CVEs in per-asset lists (default). true = include all CVEs too.",
    ),
):
    # 1) Pull the summary row from the MV
    summary_sql = text("""
        SELECT
          remediation_key,
          remediation_type,
          remediation_title,
          priority_bucket,
          plugin_ids,
          affected_asset_count,
          finding_count,
          max_severity_nessus,
          max_severity_label,
          kev_cve_count,
          cves_all,
          kev_cves,
          kev_earliest_due_date,
          days_to_due,
          due_status,
          kev_due_dates,
          kev_required_actions,
          kev_known_ransomware_flags,
          first_seen,
          last_seen
        FROM kev_remediation_actions_mv
        WHERE remediation_key = :rk
        LIMIT 1
    """)

    # 2) Build the per-asset breakdown using the SAME remediation_key logic as the MV
    #    (so clicks always match the MV row they came from)
    assets_sql = text("""
        WITH current_snapshot AS (
          SELECT km.snapshot_id
          FROM kev_matches km
          ORDER BY km.matched_at DESC
          LIMIT 1
        ),
        base AS (
          SELECT
            f.id              AS finding_id,
            f.asset_id,
            a.canonical_name  AS asset_name,
            f.plugin_id,
            p.plugin_name,
            p.solution,
            f.severity_label,
            f.severity_nessus,
            fc.cve,
            kce.due_date      AS kev_due_date
          FROM findings f
          JOIN assets a
            ON a.id = f.asset_id
          JOIN plugins p
            ON p.plugin_id = f.plugin_id
          LEFT JOIN finding_cves fc
            ON fc.finding_id = f.id
          LEFT JOIN current_snapshot cs
            ON TRUE
          LEFT JOIN kev_catalog_entries kce
            ON kce.cve = fc.cve
           AND kce.snapshot_id = cs.snapshot_id
          WHERE COALESCE(f.is_informational, FALSE) = FALSE
        ),
        actioned AS (
          SELECT
            COALESCE(
              (regexp_match(solution, '(?i)\\m(KB[0-9]{6,8})\\M'))[1],
              (regexp_match(plugin_name, '(?i)\\m(KB[0-9]{6,8})\\M'))[1],
              'PLUGIN:' || plugin_id::text
            ) AS remediation_key,
            *
          FROM base
        )
        SELECT
          asset_id,
          asset_name,
          MAX(severity_nessus) AS max_severity_nessus,
          (ARRAY_AGG(severity_label ORDER BY severity_nessus DESC))[1] AS max_severity_label,

          ARRAY_AGG(DISTINCT plugin_id ORDER BY plugin_id) AS plugin_ids,
          ARRAY_AGG(DISTINCT plugin_name ORDER BY plugin_name) AS plugin_names,

          COUNT(DISTINCT finding_id) AS finding_count,

          -- KEV CVEs for this asset+action
          ARRAY_REMOVE(
            ARRAY_AGG(DISTINCT cve ORDER BY cve) FILTER (WHERE kev_due_date IS NOT NULL),
            NULL
          ) AS kev_cves,

          -- All CVEs for this asset+action (optional to expose)
          ARRAY_REMOVE(
            ARRAY_AGG(DISTINCT cve ORDER BY cve),
            NULL
          ) AS all_cves

        FROM actioned
        WHERE remediation_key = :rk
        GROUP BY asset_id, asset_name
        ORDER BY
          MAX(severity_nessus) DESC,
          COUNT(DISTINCT finding_id) DESC,
          asset_name ASC
    """)

    with engine.connect() as conn:
        summary = conn.execute(summary_sql, {"rk": remediation_key}).mappings().first()
        if not summary:
            raise HTTPException(status_code=404, detail="remediation_key not found")

        assets = conn.execute(assets_sql, {"rk": remediation_key}).mappings().all()

    # Default behavior: avoid CVE noise in per-asset payload unless explicitly requested
    items = []
    for r in assets:
        d = dict(r)
        if not include_non_kev_cves:
            d.pop("all_cves", None)
        items.append(d)

    summary_dict = dict(summary)

    # Default: don’t ship noisy CVE list in the summary
    if not include_non_kev_cves:
        summary_dict.pop("cves_all", None)

    return {
        "summary": summary_dict,
        "assets": items,
    }

@app.get("/api/remediation-actions/{remediation_key}/export.csv")
def kev_remediation_action_export_csv(
    remediation_key: str,
    include_non_kev_cves: bool = Query(
        default=False,
        description="false = KEV CVEs only (default). true = include all CVEs too.",
    ),
):
    # Re-use the detail endpoint logic but keep it self-contained (no internal HTTP calls)
    summary_sql = text("""
        SELECT
          remediation_key,
          remediation_type,
          remediation_title,
          priority_bucket,
          plugin_ids,
          affected_asset_count,
          finding_count,
          max_severity_nessus,
          max_severity_label,
          kev_cve_count,
          cves_all,
          kev_cves,
          kev_earliest_due_date,
          days_to_due,
          due_status,
          kev_due_dates,
          kev_required_actions,
          kev_known_ransomware_flags,
          first_seen,
          last_seen
        FROM kev_remediation_actions_mv
        WHERE remediation_key = :rk
        LIMIT 1
    """)

    assets_sql = text("""
        WITH current_snapshot AS (
          SELECT km.snapshot_id
          FROM kev_matches km
          ORDER BY km.matched_at DESC
          LIMIT 1
        ),
        base AS (
          SELECT
            f.id              AS finding_id,
            f.asset_id,
            a.canonical_name  AS asset_name,
            f.plugin_id,
            p.plugin_name,
            p.solution,
            f.severity_label,
            f.severity_nessus,
            fc.cve,
            kce.due_date      AS kev_due_date
          FROM findings f
          JOIN assets a
            ON a.id = f.asset_id
          JOIN plugins p
            ON p.plugin_id = f.plugin_id
          LEFT JOIN finding_cves fc
            ON fc.finding_id = f.id
          LEFT JOIN (
            SELECT km.snapshot_id
            FROM kev_matches km
            ORDER BY km.matched_at DESC
            LIMIT 1
          ) cs ON TRUE
          LEFT JOIN kev_catalog_entries kce
            ON kce.cve = fc.cve
           AND kce.snapshot_id = cs.snapshot_id
          WHERE COALESCE(f.is_informational, FALSE) = FALSE
        ),
        actioned AS (
          SELECT
            COALESCE(
              (regexp_match(solution, '(?i)\\m(KB[0-9]{6,8})\\M'))[1],
              (regexp_match(plugin_name, '(?i)\\m(KB[0-9]{6,8})\\M'))[1],
              'PLUGIN:' || plugin_id::text
            ) AS remediation_key,
            *
          FROM base
        )
        SELECT
          asset_name,
          MAX(severity_nessus) AS max_severity_nessus,
          (ARRAY_AGG(severity_label ORDER BY severity_nessus DESC))[1] AS max_severity_label,
          COUNT(DISTINCT finding_id) AS finding_count,
          ARRAY_REMOVE(
            ARRAY_AGG(DISTINCT cve ORDER BY cve) FILTER (WHERE kev_due_date IS NOT NULL),
            NULL
          ) AS kev_cves,
          ARRAY_REMOVE(
            ARRAY_AGG(DISTINCT cve ORDER BY cve),
            NULL
          ) AS all_cves
        FROM actioned
        WHERE remediation_key = :rk
        GROUP BY asset_name
        ORDER BY
          MAX(severity_nessus) DESC,
          COUNT(DISTINCT finding_id) DESC,
          asset_name ASC
    """)

    with engine.connect() as conn:
        summary = conn.execute(summary_sql, {"rk": remediation_key}).mappings().first()
        if not summary:
            raise HTTPException(status_code=404, detail="remediation_key not found")
        assets = conn.execute(assets_sql, {"rk": remediation_key}).mappings().all()

    s = dict(summary)

    # Build CSV in-memory
    buf = io.StringIO()
    w = csv.writer(buf)

    # Header (stable, patch-first)
    w.writerow([
        "remediation_key",
        "remediation_type",
        "remediation_title",
        "priority_bucket",
        "asset_name",
        "max_severity_label",
        "max_severity_nessus",
        "finding_count",
        "kev_cve_count",
        "kev_cves",
        "kev_earliest_due_date",
        "days_to_due",
        "due_status",
        "kev_due_dates",
        "kev_required_actions",
        "cves_all",
    ])

    for a in assets:
        a = dict(a)
        kev_cves = a.get("kev_cves") or []
        all_cves = a.get("all_cves") or []

        w.writerow([
            s.get("remediation_key"),
            s.get("remediation_type"),
            s.get("remediation_title"),
            s.get("priority_bucket"),
            a.get("asset_name"),
            a.get("max_severity_label"),
            a.get("max_severity_nessus"),
            a.get("finding_count"),
            s.get("kev_cve_count"),
            ";".join(kev_cves),
            s.get("kev_earliest_due_date"),
            s.get("days_to_due"),
            s.get("due_status"),
            ";".join(s.get("kev_due_dates") or []),
            " | ".join(s.get("kev_required_actions") or []),
            ";".join(all_cves) if include_non_kev_cves else "",
        ])

    buf.seek(0)

    filename = f"kev_remediation_{remediation_key}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )

@app.get("/api/remediation-actions-export.csv")
def kev_remediation_actions_export_csv(
    has_kev: Optional[bool] = Query(default=True, description="default true (KEV queue)"),
    remediation_type: Optional[Literal["kb", "plugin"]] = Query(default=None),
    min_severity_nessus: Optional[int] = Query(default=None, ge=0, le=4),
    search: Optional[str] = Query(default=None),
    sort_by: Literal[
        "triage",
        "kev_cve_count",
        "affected_asset_count",
        "max_severity_nessus",
        "kev_earliest_due_date",
        "last_seen",
        "remediation_key",
    ] = "triage",
    sort_dir: Literal["asc", "desc"] = "desc",
    limit: int = Query(default=5000, ge=1, le=20000),
    offset: int = Query(default=0, ge=0),
    include_non_kev_cves: bool = Query(
        default=False,
        description="false = keep summary patch-first (default). true = include cves_all column.",
    ),
):
    order_col = SORT_MAP[sort_by]

    # triage always uses a fixed direction (most urgent first)
    if sort_by == "triage":
        order_by_sql = (
            " (CASE due_status "
            "WHEN 'OVERDUE' THEN 0 "
            "WHEN 'DUE_SOON' THEN 1 "
            "WHEN 'OK' THEN 2 "
            "ELSE 3 END) ASC, "
            " days_to_due ASC NULLS LAST, "
            " kev_cve_count DESC, "
            " affected_asset_count DESC, "
            " max_severity_nessus DESC, "
            " remediation_key ASC "
        )
    else:
        order_dir = "ASC" if sort_dir == "asc" else "DESC"
        order_by_sql = f"{order_col} {order_dir} NULLS LAST"



    where = []
    params = {}

    if has_kev is True:
        where.append("kev_cve_count > 0")
    elif has_kev is False:
        where.append("kev_cve_count = 0")

    if remediation_type:
        where.append("remediation_type = :remediation_type")
        params["remediation_type"] = remediation_type

    if min_severity_nessus is not None:
        where.append("max_severity_nessus >= :min_sev")
        params["min_sev"] = min_severity_nessus

    if search:
        where.append("(remediation_key ILIKE :q OR remediation_title ILIKE :q)")
        params["q"] = f"%{search}%"

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    rows_sql = text(f"""
        SELECT
          remediation_key,
          remediation_type,
          remediation_title,
          priority_bucket,
          plugin_ids,
          affected_asset_count,
          finding_count,
          max_severity_nessus,
          max_severity_label,
          kev_cve_count,
          kev_cves,
          kev_earliest_due_date,
          days_to_due,
          due_status,
          kev_due_dates,
          kev_required_actions,
          kev_known_ransomware_flags,
          cves_all,
          first_seen,
          last_seen
        FROM kev_remediation_actions_mv
        {where_sql}
        ORDER BY {order_by_sql}
        LIMIT :limit OFFSET :offset
    """)

    params["limit"] = limit
    params["offset"] = offset

    with engine.connect() as conn:
        rows = conn.execute(rows_sql, params).mappings().all()

    buf = io.StringIO()
    w = csv.writer(buf)

    w.writerow([
        "remediation_key",
        "remediation_type",
        "remediation_title",
        "priority_bucket",
        "affected_asset_count",
        "finding_count",
        "max_severity_label",
        "max_severity_nessus",
        "kev_cve_count",
        "kev_cves",
        "kev_earliest_due_date",
        "days_to_due",
        "due_status",
        "kev_due_dates",
        "kev_required_actions",
        "kev_known_ransomware_flags",
        "cves_all",
        "first_seen",
        "last_seen",
        "drilldown_url",
    ])

    for r in rows:
        r = dict(r)
        w.writerow([
            r.get("remediation_key"),
            r.get("remediation_type"),
            r.get("remediation_title"),
            r.get("priority_bucket"),
            r.get("affected_asset_count"),
            r.get("finding_count"),
            r.get("max_severity_label"),
            r.get("max_severity_nessus"),
            r.get("kev_cve_count"),
            ";".join(r.get("kev_cves") or []),
            r.get("kev_earliest_due_date"),
            r.get("days_to_due"),
            r.get("due_status"),
            ";".join(r.get("kev_due_dates") or []),
            " | ".join(r.get("kev_required_actions") or []),
            ";".join(r.get("kev_known_ransomware_flags") or []),
            ";".join(r.get("cves_all") or []) if include_non_kev_cves else "",
            r.get("first_seen"),
            r.get("last_seen"),
            f"/api/remediation-actions/{r.get('remediation_key')}",
        ])

    buf.seek(0)

    filename = "kev_remediation_actions.csv" if has_kev else "remediation_actions.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
# ---------------------------------------------------------------------------
# Nessus-like "Findings" export endpoints (asset + plugin + instance details)
# ---------------------------------------------------------------------------

# --- allowed ORDER BY columns (prevents SQL injection) ---
FINDINGS_SORT_MAP = {
    "last_seen": "f.last_seen",
    "first_seen": "f.first_seen",
    "severity_nessus": "f.severity_nessus",
    "asset": "a.canonical_name",
    "plugin_id": "p.plugin_id",
    "plugin_name": "p.plugin_name",
}


@app.get("/api/findings")
def list_findings(
    q: Optional[str] = Query(default=None),
    min_severity_nessus: Optional[int] = Query(default=None, ge=0, le=4),
    status: Optional[str] = Query(default=None),  # e.g. "open"
    severity_in: Optional[str] = Query(default=None, description="Comma-separated severity_nessus values (0-4), e.g. 4,3,2"),
    dedup: str = Query(
        default="none",
        description="Dedup mode: none | instance (aggregate by finding_id+port+protocol) | asset_plugin (aggregate by asset+plugin only)",
    ),
    sort_by: Literal[
        "last_seen",
        "first_seen",
        "severity_nessus",
        "asset",
        "plugin_id",
        "plugin_name",
    ] = "severity_nessus",
    sort_dir: Literal["asc", "desc"] = "desc",
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    where = []
    params = {}

    if min_severity_nessus is not None:
        where.append("f.severity_nessus >= :min_sev")
        params["min_sev"] = min_severity_nessus

    if status:
        where.append("f.status = :status")
        params["status"] = status
        
    if severity_in:
        vals = []
        for part in severity_in.split(","):
            part = part.strip()
            if not part:
                continue
            try:
                v = int(part)
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid severity_in value: {part}")
            if v < 0 or v > 4:
                raise HTTPException(status_code=400, detail=f"severity_in out of range (0-4): {v}")
            vals.append(v)

        # de-dupe, stable
        vals = sorted(set(vals))

        if vals:
            ph = ", ".join([f":sev{i}" for i in range(len(vals))])
            where.append(f"f.severity_nessus IN ({ph})")
            for i, v in enumerate(vals):
                params[f"sev{i}"] = v


    if q:
        where.append(
            "("
            "a.canonical_name ILIKE :q OR "
            "p.plugin_name ILIKE :q OR "
            "CAST(p.plugin_id AS text) ILIKE :q OR "
            "COALESCE(fi.plugin_output,'') ILIKE :q"
            ")"
        )
        params["q"] = f"%{q}%"

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    order_col = FINDINGS_SORT_MAP[sort_by]
    order_dir = "ASC" if sort_dir == "asc" else "DESC"
    order_by_sql = f"{order_col} {order_dir} NULLS LAST"

    if dedup == "instance":
        # Dedup = aggregate finding_instances by (finding_id, port, protocol)
        total_sql = text(f"""
            SELECT COUNT(*)::int
            FROM (
              SELECT f.id AS finding_id, fi.port, fi.protocol
              FROM public.finding_instances fi
              JOIN public.findings f ON f.id = fi.finding_id
              JOIN public.assets a ON a.id = f.asset_id
              JOIN public.plugins p ON p.plugin_id = f.plugin_id
              LEFT JOIN LATERAL (
                SELECT ai.ip_value
                FROM public.asset_identities ai
                WHERE ai.asset_id = a.id AND ai.ip_value IS NOT NULL
                ORDER BY ai.last_seen DESC
                LIMIT 1
              ) ip ON TRUE
              {where_sql}
              GROUP BY f.id, fi.port, fi.protocol
            ) x
        """)

        rows_sql = text(f"""
            SELECT
              a.canonical_name AS asset,
              ip.ip_value AS ip,

              f.severity_label AS severity,
              f.severity_nessus,
              f.status,

              f.first_seen,
              f.last_seen,

              p.plugin_id,
              p.plugin_name,
              p.family AS plugin_family,
              p.cvss_base,

              MAX(LEFT(COALESCE(p.synopsis,''), 240)) AS synopsis_preview,
              MAX(LEFT(COALESCE(p.solution,''), 240)) AS solution_preview,

              COALESCE(fi.port, 0) AS port,
              COALESCE(fi.protocol, 'host') AS protocol,

              MAX(LEFT(COALESCE(fi.plugin_output,''), 240)) AS plugin_output_preview,

              COUNT(*)::int AS instance_count

            FROM public.finding_instances fi
            JOIN public.findings f ON f.id = fi.finding_id
            JOIN public.assets a ON a.id = f.asset_id
            JOIN public.plugins p ON p.plugin_id = f.plugin_id
            LEFT JOIN LATERAL (
              SELECT ai.ip_value
              FROM public.asset_identities ai
              WHERE ai.asset_id = a.id AND ai.ip_value IS NOT NULL
              ORDER BY ai.last_seen DESC
              LIMIT 1
            ) ip ON TRUE
            {where_sql}
            GROUP BY
              a.canonical_name,
              ip.ip_value,
              f.severity_label,
              f.severity_nessus,
              f.status,
              f.first_seen,
              f.last_seen,
              p.plugin_id,
              p.plugin_name,
              p.family,
              p.cvss_base,
              fi.port,
              fi.protocol
            ORDER BY {order_by_sql}
            LIMIT :limit OFFSET :offset
        """)
    elif dedup == "asset_plugin":
        # Dedup = one row per (asset, plugin); aggregate endpoints for export/drilldown
        total_sql = text(f"""
            SELECT COUNT(*)::int
            FROM (
              SELECT a.id, f.plugin_id
              FROM public.finding_instances fi
              JOIN public.findings f ON f.id = fi.finding_id
              JOIN public.assets a ON a.id = f.asset_id
              JOIN public.plugins p ON p.plugin_id = f.plugin_id
              LEFT JOIN LATERAL (
                SELECT ai.ip_value
                FROM public.asset_identities ai
                WHERE ai.asset_id = a.id AND ai.ip_value IS NOT NULL
                ORDER BY ai.last_seen DESC
                LIMIT 1
              ) ip ON TRUE
              {where_sql}
              GROUP BY a.id, f.plugin_id
            ) x
        """)

        rows_sql = text(f"""
            SELECT
              a.canonical_name AS asset,
              ip.ip_value AS ip,

              f.severity_label AS severity,
              f.severity_nessus,
              f.status,

              f.first_seen,
              f.last_seen,

              p.plugin_id,
              p.plugin_name,
              p.family AS plugin_family,
              p.cvss_base,

              MAX(LEFT(COALESCE(p.synopsis,''), 240)) AS synopsis_preview,
              MAX(LEFT(COALESCE(p.solution,''), 240)) AS solution_preview,

              NULL::int AS port,
              NULL::text AS protocol,
              NULL::text AS plugin_output_preview,

              COUNT(fi.id)::int AS instance_count,
              STRING_AGG(
                DISTINCT (COALESCE(fi.protocol,'?') || ':' || COALESCE(fi.port,0)::text),
                ', ' ORDER BY (COALESCE(fi.protocol,'?') || ':' || COALESCE(fi.port,0)::text)
              ) AS endpoints

            FROM public.finding_instances fi
            JOIN public.findings f ON f.id = fi.finding_id
            JOIN public.assets a ON a.id = f.asset_id
            JOIN public.plugins p ON p.plugin_id = f.plugin_id
            LEFT JOIN LATERAL (
              SELECT ai.ip_value
              FROM public.asset_identities ai
              WHERE ai.asset_id = a.id AND ai.ip_value IS NOT NULL
              ORDER BY ai.last_seen DESC
              LIMIT 1
            ) ip ON TRUE
            {where_sql}
            GROUP BY
              a.canonical_name,
              ip.ip_value,
              f.severity_label,
              f.severity_nessus,
              f.status,
              f.first_seen,
              f.last_seen,
              p.plugin_id,
              p.plugin_name,
              p.family,
              p.cvss_base
            ORDER BY {order_by_sql}
            LIMIT :limit OFFSET :offset
        """)

    params["limit"] = limit
    params["offset"] = offset

    with engine.connect() as conn:
        total = conn.execute(total_sql, params).scalar_one()
        rows = conn.execute(rows_sql, params).mappings().all()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [dict(r) for r in rows],
    }


@app.get("/api/findings-export.csv")
def export_findings_csv(
    q: Optional[str] = Query(default=None),
    min_severity_nessus: Optional[int] = Query(default=None, ge=0, le=4),
    status: Optional[str] = Query(default=None),
    sort_by: Literal[
        "last_seen",
        "first_seen",
        "severity_nessus",
        "asset",
        "plugin_id",
        "plugin_name",
    ] = "severity_nessus",
    sort_dir: Literal["asc", "desc"] = "desc",
    limit: int = Query(default=5000, ge=1, le=50000),
):
    # CSV export is the same query, just without offset and with a larger limit cap
    where = []
    params = {}

    if min_severity_nessus is not None:
        where.append("f.severity_nessus >= :min_sev")
        params["min_sev"] = min_severity_nessus

    if status:
        where.append("f.status = :status")
        params["status"] = status

    if q:
        where.append(
            "("
            "a.canonical_name ILIKE :q OR "
            "p.plugin_name ILIKE :q OR "
            "CAST(p.plugin_id AS text) ILIKE :q OR "
            "COALESCE(fi.plugin_output,'') ILIKE :q"
            ")"
        )
        params["q"] = f"%{q}%"

    where_sql = ("WHERE " + " AND ".join(where)) if where else ""

    order_col = FINDINGS_SORT_MAP[sort_by]
    order_dir = "ASC" if sort_dir == "asc" else "DESC"
    order_by_sql = f"{order_col} {order_dir} NULLS LAST"

    rows_sql = text(f"""
        SELECT
          a.canonical_name AS asset,
          ip.ip_value AS ip,
          f.severity_label AS severity,
          f.severity_nessus,
          f.status,
          f.first_seen,
          f.last_seen,

          p.plugin_id,
          p.plugin_name,
          p.family AS plugin_family,
          p.cvss_base,

          p.synopsis,
          p.solution,

          fi.port,
          fi.protocol,
          fi.plugin_output
        FROM public.finding_instances fi
        JOIN public.findings f ON f.id = fi.finding_id
        JOIN public.assets a ON a.id = f.asset_id
        JOIN public.plugins p ON p.plugin_id = f.plugin_id
        LEFT JOIN LATERAL (
          SELECT ai.ip_value
          FROM public.asset_identities ai
          WHERE ai.asset_id = a.id AND ai.ip_value IS NOT NULL
          ORDER BY ai.last_seen DESC
          LIMIT 1
        ) ip ON TRUE
        {where_sql}
        ORDER BY {order_by_sql}
        LIMIT :limit
    """)

    params["limit"] = limit

    with engine.connect() as conn:
        rows = conn.execute(rows_sql, params).mappings().all()

    buf = io.StringIO()
    w = csv.writer(buf)

    # “Nessus-ish” header set (keeps it readable for remediation teams)
    w.writerow([
        "asset",
        "ip",
        "severity",
        "severity_nessus",
        "status",
        "first_seen",
        "last_seen",
        "plugin_id",
        "plugin_name",
        "plugin_family",
        "cvss_base",
        "synopsis",
        "solution",
        "port",
        "protocol",
        "plugin_output",
    ])

    for r in rows:
        r = dict(r)
        w.writerow([
            r.get("asset"),
            r.get("ip"),
            r.get("severity"),
            r.get("severity_nessus"),
            r.get("status"),
            r.get("first_seen"),
            r.get("last_seen"),
            r.get("plugin_id"),
            r.get("plugin_name"),
            r.get("plugin_family"),
            r.get("cvss_base"),
            r.get("synopsis"),
            r.get("solution"),
            r.get("port"),
            r.get("protocol"),
            r.get("plugin_output"),
        ])

    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="findings.csv"'},
    )
