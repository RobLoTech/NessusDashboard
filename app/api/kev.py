from typing import Dict, Any

import os
from fastapi import APIRouter, Query
from sqlalchemy import create_engine, text

def get_engine():
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL is not set")
    return create_engine(db_url, pool_pre_ping=True)

# Create a module-level engine once (simple + works fine for your use case)
engine = get_engine()

router = APIRouter(prefix="/api/kev", tags=["kev"])


@router.get("/patch-snapshot")
def kev_patch_snapshot(
    min_assets: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """
    Returns KEV patch/plugin remediation snapshot from `public.v_kev_patch_snapshot`.
    """
    sql = text("""
        SELECT
          kev_pulled_at,
          kev_snapshot_id,
          plugin_id,
          plugin_name,
          affected_assets,
          kev_cves,
          cves,
          sample_assets
        FROM public.v_kev_patch_snapshot
        WHERE affected_assets >= :min_assets
        ORDER BY affected_assets DESC, kev_cves DESC, plugin_id
        LIMIT :limit OFFSET :offset
    """)

    with engine.connect() as conn:
        rows = conn.execute(
            sql,
            {"min_assets": min_assets, "limit": limit, "offset": offset},
        ).mappings().all()

    return {
        "limit": limit,
        "offset": offset,
        "count": len(rows),
        "rows": [dict(r) for r in rows],
    }


@router.get("/cves")
def kev_cves(
    only_kev: bool = Query(True),
    min_score: float = Query(0, ge=0),
    min_assets: int = Query(0, ge=0),
    limit: int = Query(200, ge=1, le=2000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """
    Returns CVE-level prioritization from `public.v_cve_priority_kev`.
    """
    sql = text("""
        SELECT
          kev_pulled_at,
          kev_snapshot_id,
          cve_id,
          is_kev,
          final_priority_score,
          priority_score,
          affected_assets,
          finding_cve_links,
          vpr_score,
          epss_score,
          effective_cvss_score,
          effective_cvss_version
        FROM public.v_cve_priority_kev
        WHERE (:only_kev = false OR is_kev = true)
          AND final_priority_score >= :min_score
          AND affected_assets >= :min_assets
        ORDER BY
          final_priority_score DESC,
          priority_score DESC,
          affected_assets DESC,
          cve_id
        LIMIT :limit OFFSET :offset
    """)

    with engine.connect() as conn:
        rows = conn.execute(
            sql,
            {
                "only_kev": only_kev,
                "min_score": min_score,
                "min_assets": min_assets,
                "limit": limit,
                "offset": offset,
            },
        ).mappings().all()

    return {
        "limit": limit,
        "offset": offset,
        "count": len(rows),
        "rows": [dict(r) for r in rows],
    }
