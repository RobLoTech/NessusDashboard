import React, { useEffect, useMemo, useState } from "react";
import "./App.css";

type PatchRow = {
  kev_pulled_at: string;
  kev_snapshot_id: string;
  plugin_id: number;
  plugin_name: string;
  affected_assets: number;
  kev_cves: number;
  cves: string;
  sample_assets: string;
};

type CveRow = {
  kev_pulled_at: string;
  kev_snapshot_id: string;
  cve_id: string;
  is_kev: boolean;

  final_priority_score: string;
  priority_score: string;

  affected_assets: number;
  finding_cve_links: number;

  vpr_score: string | null;
  epss_score: string | null;

  effective_cvss_score: string | null;
  effective_cvss_version: string | null;
};

type ApiResp<T> = {
  limit: number;
  offset: number;
  count: number;
  rows: T[];
};

type View = "patch" | "cves" | "remediation" | "findings";
type FindCol = "any" | "asset" | "ip" | "plugin_name" | "plugin_id" | "severity" | "status" | "protocol" | "port";
type FindOp = "contains" | "starts_with" | "equals" | "not_contains" | "not_starts_with" | "not_equals";

type RemediationItem = {
  remediation_key: string;
  remediation_type: string;
  remediation_title: string;

  priority_bucket?: string | null;

  plugin_ids?: number[];
  affected_asset_count?: number;
  affected_assets?: string[];

  finding_count?: number;

  max_severity_nessus?: number;
  max_severity_label?: string;

  kev_cve_count?: number;

  // these exist in your payload; keep optional so TS doesn't block you
  cves_all?: string[];
  cves_kev?: string[];
};

type RemediationResp = {
  total: number;
  limit: number;
  offset: number;
  items: RemediationItem[];
};
type FindingRow = {
  asset: string;
  ip: string | null;

  severity: string;
  severity_nessus: number;
  status: string;

  first_seen: string;
  last_seen: string;

  plugin_id: number;
  plugin_name: string;
  plugin_family: string | null;
  cvss_base: string | null;

  synopsis_preview: string;
  solution_preview: string;

  port: number | null;
  protocol: string | null;

  plugin_output_preview: string;
};

type FindingsResp = {
  total: number;
  limit: number;
  offset: number;
  items: FindingRow[];
};

function fmtDate(iso: string) {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }

}
function pageRange(offset: number, limit: number, total: number | null) {
  const start = total ? Math.min(offset + 1, total) : offset + 1;
  const end = total ? Math.min(offset + limit, total) : offset + limit;
  return { start, end };
}


export default function App() {
  // --- top-level view switch ---
  const [view, setView] = useState<View>("patch");

  // --- shared UI controls ---
  const [limit, setLimit] = useState<number>(50);
  const [q, setQ] = useState<string>("");

  // --- findings-only controls (match /api/findings params) ---
  const [findQ, setFindQ] = useState<string>("");
  const [findMinSev, setFindMinSev] = useState<number | "">("");
  const [findStatus, setFindStatus] = useState<"" | "open" | "fixed">("");
  // --- findings severity toggles (UI) ---
  // Default: show Low+ (1-4). Info (0) off by default.
  const [sevCrit, setSevCrit] = useState<boolean>(true);
  const [sevHigh, setSevHigh] = useState<boolean>(true);
  const [sevMed, setSevMed] = useState<boolean>(true);
  const [sevLow, setSevLow] = useState<boolean>(true);
  const [sevInfo, setSevInfo] = useState<boolean>(false);

  const selectedSev = new Set<number>([
    ...(sevCrit ? [4] : []),
    ...(sevHigh ? [3] : []),
    ...(sevMed ? [2] : []),
    ...(sevLow ? [1] : []),
    ...(sevInfo ? [0] : []),
  ]);
  const [findExactSev, setFindExactSev] = useState<"" | 4 | 3 | 2 | 1 | 0>("");
  const [findSortBy, setFindSortBy] = useState<
    "severity_nessus" | "last_seen" | "first_seen" | "plugin_id" | "asset"
  >("severity_nessus");
  const [findSortDir, setFindSortDir] = useState<"asc" | "desc">("desc");

  // --- findings column-aware filter (client-side) ---
  const [findCol, setFindCol] = useState<FindCol>("any");
  const [findOp, setFindOp] = useState<FindOp>("contains");
  const [findVal, setFindVal] = useState<string>("");


  // patch-only control
  const [minAssets, setMinAssets] = useState<number>(5);

  // findings-only controls (server-side)
  const [findLimit, setFindLimit] = useState<number>(50);
  const [findOffset, setFindOffset] = useState<number>(0);

  // --- data ---
  const [loading, setLoading] = useState<boolean>(false);
  const [err, setErr] = useState<string | null>(null);

  const [patchData, setPatchData] = useState<ApiResp<PatchRow> | null>(null);
  const [cveData, setCveData] = useState<ApiResp<CveRow> | null>(null);
  const [remData, setRemData] = useState<RemediationResp | null>(null);
  const [findingsData, setFindingsData] = useState<FindingsResp | null>(null);

  // cve-only UI state (expand row)
  const [openCve, setOpenCve] = useState<string | null>(null);
  const [openRemediationKey, setOpenRemediationKey] = useState<string | null>(null);
  const [remediationDetail, setRemediationDetail] = useState<any | null>(null);

  // --- findings: click-to-sort helpers ---
  const findArrow = (col: "severity_nessus" | "last_seen" | "first_seen" | "plugin_id" | "asset") => {
    if (findSortBy !== col) return "";
    return findSortDir === "asc" ? " ▲" : " ▼";
  };

  const onFindSort = (col: "severity_nessus" | "last_seen" | "first_seen" | "plugin_id" | "asset") => {
    // whenever sort changes, jump back to the first page
    setFindOffset(0);

    if (findSortBy === col) {
      setFindSortDir(findSortDir === "asc" ? "desc" : "asc");
      return;
    }

    setFindSortBy(col);
    // sensible defaults: asset alpha, everything else severity-style (desc)
    setFindSortDir(col === "asset" ? "asc" : "desc");
  };

  async function loadRemediationDetail(remediation_key: string) {
    const resp = await fetch(
      `/api/remediation-actions/${encodeURIComponent(remediation_key)}`,
      { headers: { Accept: "application/json" } }
    );
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    return await resp.json();
  }


  // fetch whenever view/inputs change (simple + predictable)
  useEffect(() => {
    const controller = new AbortController();

    async function run() {
      setLoading(true);
      setErr(null);
      try {
        if (view === "patch") {
          const url = `/api/kev/patch-snapshot?min_assets=${encodeURIComponent(
            String(minAssets)
          )}&limit=${encodeURIComponent(String(limit))}`;

          const resp = await fetch(url, { signal: controller.signal });
          if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
          const json = (await resp.json()) as ApiResp<PatchRow>;
          setPatchData(json);
        } else if (view === "cves") {
          const url = `/api/kev/cves?limit=${encodeURIComponent(String(limit))}`;

          const resp = await fetch(url, { signal: controller.signal });
          if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
          const json = (await resp.json()) as ApiResp<CveRow>;
          setCveData(json);
        } else if (view === "findings") {
          const qs = new URLSearchParams();
          qs.set("limit", String(limit));

          if (findQ.trim()) qs.set("q", findQ.trim());
          if (findStatus) qs.set("status", findStatus);

          qs.set("sort_by", findSortBy);
          qs.set("sort_dir", findSortDir);

          const params = new URLSearchParams();

          params.set("limit", String(findLimit));
          if (view === "findings") {
            params.set("dedup", "1");
          }
          params.set("offset", String(findOffset));

          if (findQ.trim()) {
            params.set("q", findQ.trim());
          }

          if (findMinSev !== "") {
          }

          if (findStatus) {
            params.set("status", findStatus);
          }

          // Build severity_in from the UI toggles
          const selected: number[] = [];
          if (sevCrit) selected.push(4);
          if (sevHigh) selected.push(3);
          if (sevMed) selected.push(2);
          if (sevLow) selected.push(1);
          if (sevInfo) selected.push(0);

          if (selected.length > 0) {
            params.set("severity_in", selected.join(","));
          } else {
            // If user unchecks everything, return nothing (avoid showing everything)
            params.set("severity_in", "-1");
          }

          const url = `/api/findings?${params.toString()}&dedup=1`;

          const resp = await fetch(url, { signal: controller.signal });
          if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

          const json = (await resp.json()) as FindingsResp;
          setFindingsData(json);
        } else {
          const url = `/api/remediation-actions?limit=${encodeURIComponent(String(limit))}`;

          const resp = await fetch(url, { signal: controller.signal });
          if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
          const json = (await resp.json()) as RemediationResp;
          setRemData(json);
        }
      } catch (e: any) {
        if (e?.name === "AbortError") return;
        setErr(e?.message ?? "Request failed");
      } finally {
        setLoading(false);
      }
    }

    run();

    return () => controller.abort();
  }, [
    view,
    limit,
    minAssets,
    findQ,
    findMinSev,
    findStatus,
    findSortBy,
    findSortDir,
    findLimit,
    findOffset,
    sevCrit,
    sevHigh,
    sevMed,
    sevLow,
    sevInfo,
    findVal,
  ]);


  const patchRows = useMemo(() => {
    const base = patchData?.rows ?? [];
    const needle = q.trim().toLowerCase();
    if (!needle) return base;

    return base.filter((r) => {
      return (
        r.plugin_name.toLowerCase().includes(needle) ||
        r.cves.toLowerCase().includes(needle) ||
        r.sample_assets.toLowerCase().includes(needle) ||
        String(r.plugin_id).includes(needle)
      );
    });
  }, [patchData, q]);

    const remRows = useMemo(() => {
    const base = remData?.items ?? [];
    const needle = q.trim().toLowerCase();
    if (!needle) return base;

    return base.filter((r) => {
      return (
        (r.remediation_key ?? "").toLowerCase().includes(needle) ||
        (r.remediation_title ?? "").toLowerCase().includes(needle) ||
        (r.priority_bucket ?? "").toLowerCase().includes(needle) ||
        (r.max_severity_label ?? "").toLowerCase().includes(needle) ||
        String(r.affected_asset_count ?? "").includes(needle) ||
        String(r.kev_cve_count ?? "").includes(needle) ||
        (r.cves_kev ?? []).join(",").toLowerCase().includes(needle) ||
        (r.cves_all ?? []).join(",").toLowerCase().includes(needle) ||
        (r.plugin_ids ?? []).join(",").toLowerCase().includes(needle)
      );
    });
  }, [remData, q]);

  const findingsRows = useMemo(() => {
    const base = findingsData?.items ?? [];
    const baseExact = base;
    const needle = findVal.trim().toLowerCase();
if (!needle) {
  return baseExact.filter((r) => selectedSev.has(r.severity_nessus));
}

    const getField = (r: FindingRow, col: FindCol) => {
      switch (col) {
        case "asset":
          return r.asset ?? "";
        case "ip":
          return r.ip ?? "";
        case "plugin_name":
          return r.plugin_name ?? "";
        case "plugin_id":
          return String(r.plugin_id ?? "");
        case "severity":
          return r.severity ?? "";
        case "status":
          return r.status ?? "";
        case "protocol":
          return r.protocol ?? "";
        case "port":
          return String(r.port ?? "");
        case "any":
        default:
          return [
            r.asset,
            r.ip ?? "",
            r.plugin_name,
            String(r.plugin_id),
            r.severity,
            r.status,
            r.protocol ?? "",
            String(r.port ?? ""),
          ]
            .filter(Boolean)
            .join(" ");
      }
    };

    const match = (haystackRaw: string) => {
      const haystack = (haystackRaw ?? "").toLowerCase();

      switch (findOp) {
        case "contains":
          return haystack.includes(needle);
        case "starts_with":
          return haystack.startsWith(needle);
        case "equals":
          return haystack === needle;
        case "not_contains":
          return !haystack.includes(needle);
        case "not_starts_with":
          return !haystack.startsWith(needle);
        case "not_equals":
          return haystack !== needle;
        default:
          return haystack.includes(needle);
      }
    };

    return baseExact
      .filter((r) => selectedSev.has(r.severity_nessus))
      .filter((r) => match(getField(r, findCol)));
}, [findingsData, findExactSev, findCol, findOp, findVal, sevCrit, sevHigh, sevMed, sevLow, sevInfo]);


  const cveRows = useMemo(() => {
    const base = cveData?.rows ?? [];
    const needle = q.trim().toLowerCase();
    if (!needle) return base;

    return base.filter((r) => {
      return (
        r.cve_id.toLowerCase().includes(needle) ||
        String(r.affected_assets).includes(needle) ||
        String(r.finding_cve_links).includes(needle) ||
        (r.effective_cvss_score ?? "").toLowerCase().includes(needle) ||
        (r.vpr_score ?? "").toLowerCase().includes(needle) ||
        (r.epss_score ?? "").toLowerCase().includes(needle)
      );
    });
  }, [cveData, q]);

  const headerPulledAt =
    view === "patch"
      ? patchData?.rows?.[0]?.kev_pulled_at
      : cveData?.rows?.[0]?.kev_pulled_at;

  const rowsCount =
    view === "patch"
      ? patchRows.length
      : view === "cves"
        ? cveRows.length
        : view === "findings"
          ? findingsRows.length
          : remRows.length;

  const totalCount =
    view === "patch"
      ? patchData?.count ?? null
      : view === "cves"
        ? cveData?.count ?? null
        : view === "findings"
          ? findingsData?.total ?? null
          : remData?.total ?? null;

  return (
    <div className="page">
      <header className="header">
        <div>
          <h1>Nessus KEV</h1>
          <p className="sub">
            {view === "patch" ? (
              <>
                Data source: <code>v_kev_patch_snapshot</code>
              </>
            ) : view === "cves" ? (
              <>
                Data source: <code>v_cve_priority_kev</code>
              </>
            ) : view === "findings" ? (
              <>
                Data source: <code>/api/findings</code>
              </>
            ) : (
              <>
                Data source: <code>/api/remediation-actions</code>
              </>
            )}
            {headerPulledAt ? ` • KEV pulled: ${fmtDate(headerPulledAt)}` : ""}
          </p>
        </div>

        <div className="controls">
          {/* --- tabs --- */}
          <div className="tabs">
            <button
              className={view === "patch" ? "tab active" : "tab"}
              onClick={() => {
                setView("patch");
                setErr(null);
                setOpenCve(null);
              }}
              type="button"
            >
              Patch snapshot
            </button>
            <button
              className={view === "findings" ? "tab tab-active" : "tab"}
              onClick={() => setView("findings")}
            >
              Findings
            </button>
            <button
              className={view === "cves" ? "tab active" : "tab"}
              onClick={() => {
                setView("cves");
                setErr(null);
                setOpenCve(null);
              }}
              type="button"
            >
              KEV CVEs
            </button>
                        <button
              className={view === "remediation" ? "tab active" : "tab"}
              onClick={() => {
                setView("remediation");
                setErr(null);
                setOpenCve(null);
              }}
              type="button"
            >
              Remediation
            </button>
          </div>

          {/* --- view-specific controls --- */}
          {view === "patch" && (
            <label className="ctrl">
              <span>Min assets</span>
              <input
                type="number"
                min={0}
                value={minAssets}
                onChange={(e) => setMinAssets(Number(e.target.value))}
              />
            </label>
          )}

          {view !== "findings" && (
            <label className="ctrl">
              <span>Limit</span>
              <input
                type="number"
                min={1}
                max={2000}
                value={limit}
                onChange={(e) => setLimit(Number(e.target.value))}
              />
            </label>
          )}
          {view === "findings" && (
            <>
            <label className="ctrl">
              <span>Page size</span>
              <input
                type="number"
                min={1}
                max={500}
                value={findLimit}
                onChange={(e) => {
                  setFindLimit(Number(e.target.value));
                  setFindOffset(0);
                }}
              />
            </label>
              <label className="ctrl">
                <span>Severity</span>
                <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
                  <label style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    <input type="checkbox" checked={sevCrit} onChange={(e) => setSevCrit(e.target.checked)} />
                    <span>Critical</span>
                  </label>
                  <label style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    <input type="checkbox" checked={sevHigh} onChange={(e) => setSevHigh(e.target.checked)} />
                    <span>High</span>
                  </label>
                  <label style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    <input type="checkbox" checked={sevMed} onChange={(e) => setSevMed(e.target.checked)} />
                    <span>Medium</span>
                  </label>
                  <label style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    <input type="checkbox" checked={sevLow} onChange={(e) => setSevLow(e.target.checked)} />
                    <span>Low</span>
                  </label>
                  <label style={{ display: "flex", gap: 6, alignItems: "center" }}>
                    <input type="checkbox" checked={sevInfo} onChange={(e) => setSevInfo(e.target.checked)} />
                    <span>Info</span>
                  </label>
                </div>
              </label>
                            <label className="ctrl">
                <span>Exact severity</span>
                <select
                  value={findExactSev === "" ? "" : String(findExactSev)}
                  onChange={(e) => {
                    const v = e.target.value;
                    setFindExactSev(v === "" ? "" : (Number(v) as 0 | 1 | 2 | 3 | 4));
                    setFindOffset(0);
                  }}
                >
                  <option value="">Any</option>
                  <option value="4">Critical (4)</option>
                  <option value="3">High (3)</option>
                  <option value="2">Medium (2)</option>
                  <option value="1">Low (1)</option>
                  <option value="0">Info (0)</option>
                </select>
              </label>

              <label className="ctrl">
                <span>Status</span>
                <select
                  value={findStatus}
                  onChange={(e) => setFindStatus(e.target.value as "" | "open" | "fixed")}
                >
                  <option value="">Any</option>
                  <option value="open">Open</option>
                  <option value="fixed">Fixed</option>
                </select>
              </label>

              <label className="ctrl">
                <span>Sort by</span>
                <select
                  value={findSortBy}
                  onChange={(e) => setFindSortBy(e.target.value as any)}
                >
                  <option value="severity_nessus">Severity</option>
                  <option value="last_seen">Last seen</option>
                  <option value="first_seen">First seen</option>
                  <option value="plugin_id">Plugin ID</option>
                  <option value="asset">Asset</option>
                </select>
              </label>

              <label className="ctrl">
                <span>Dir</span>
                <select
                  value={findSortDir}
                  onChange={(e) => setFindSortDir(e.target.value as "asc" | "desc")}
                >
                  <option value="desc">Desc</option>
                  <option value="asc">Asc</option>
                </select>
              </label>
            </>
          )}
          {/* shared filter (non-findings) */}
          {view !== "findings" && (
            <label className="ctrl ctrl-wide">
              <span>Filter</span>
              <input
                placeholder={
                  view === "patch"
                    ? "plugin, CVE, asset, plugin_id..."
                    : view === "cves"
                    ? "CVE, score, affected assets, EPSS, VPR..."
                    : "KB / remediation key, title, severity, CVEs..."
                }
                value={q}
                onChange={(e) => setQ(e.target.value)}
              />
            </label>
          )}

          {/* findings column-aware filter */}
          {view === "findings" && (
            <>
              <label className="ctrl">
                <span>Column</span>
                <select value={findCol} onChange={(e) => setFindCol(e.target.value as FindCol)}>
                  <option value="any">Any field</option>
                  <option value="asset">Asset</option>
                  <option value="ip">IP</option>
                  <option value="plugin_name">Plugin name</option>
                  <option value="plugin_id">Plugin ID</option>
                  <option value="severity">Severity</option>
                  <option value="status">Status</option>
                  <option value="protocol">Protocol</option>
                  <option value="port">Port</option>
                </select>
              </label>

              <label className="ctrl">
                <span>Operator</span>
                <select value={findOp} onChange={(e) => setFindOp(e.target.value as FindOp)}>
                  <option value="contains">Contains</option>
                  <option value="starts_with">Starts with</option>
                  <option value="equals">Equals</option>
                  <option value="not_contains">Not contains</option>
                  <option value="not_starts_with">Not starts with</option>
                  <option value="not_equals">Not equals</option>
                </select>
              </label>

              <label className="ctrl ctrl-wide">
                <span>Value</span>
                <input
                  placeholder="e.g. PC24, 192.168., chrome, 210851, open..."
                  value={findVal}
                  onChange={(e) => setFindVal(e.target.value)}
                />
              </label>
            </>
          )}

        </div>
      </header>

      {loading && <div className="banner">Loading…</div>}
      {err && <div className="banner banner-err">Error: {err}</div>}

      <div className="card">
        <div className="meta">
          {view === "findings" && findingsData ? (
            (() => {
              const { start, end } = pageRange(
                findOffset,
                findLimit,
                findingsData.total
              );

              return (
                <>
                  <span>
                    Showing <b>{start}–{end}</b> of {findingsData.total}
                  </span>

                  <div style={{ display: "flex", gap: 8 }}>
                    <button
                      disabled={findOffset === 0}
                      onClick={() =>
                        setFindOffset(Math.max(0, findOffset - findLimit))
                      }
                    >
                      ◀ Prev
                    </button>

                    <button
                      disabled={findOffset + findLimit >= findingsData.total}
                      onClick={() =>
                        setFindOffset(findOffset + findLimit)
                      }
                    >
                      Next ▶
                    </button>
                  </div>
                </>
              );
            })()
          ) : (
            <>
              <span>
                Showing <b>{rowsCount}</b>
                {typeof totalCount === "number" ? ` of ${totalCount}` : ""} rows
              </span>
              <span className="hint">Tip: scroll horizontally on small screens</span>
            </>
          )}
        </div>

        <div className="tableWrap">
          {view === "patch" ? (
            <table>
              <thead>
                <tr>
                  <th>Plugin</th>
                  <th className="num">Assets</th>
                  <th className="num">KEV CVEs</th>
                  <th>CVEs</th>
                  <th>Sample assets</th>
                </tr>
              </thead>
              <tbody>
                {patchRows.map((r) => (
                  <tr key={r.plugin_id}>
                    <td>
                      <div className="pluginName">{r.plugin_name}</div>
                      <div className="muted">plugin_id: {r.plugin_id}</div>
                    </td>
                    <td className="num">{r.affected_assets}</td>
                    <td className="num">{r.kev_cves}</td>
                    <td className="mono">{r.cves}</td>
                    <td className="mono">{r.sample_assets}</td>
                  </tr>
                ))}
                {!loading && patchRows.length === 0 && (
                  <tr>
                    <td colSpan={5} className="empty">
                      No rows match your filter.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          ) : view === "cves" ? (
            <table>
              <thead>
                <tr>
                  <th>CVE</th>
                  <th className="num">Final</th>
                  <th className="num">Priority</th>
                  <th className="num">Assets</th>
                  <th className="num">Links</th>
                  <th className="num">CVSS</th>
                  <th className="num">VPR</th>
                  <th className="num">EPSS</th>
                </tr>
              </thead>
              <tbody>
                {cveRows.map((r) => {
                  const isOpen = openCve === r.cve_id;
                  return (
                    <React.Fragment key={r.cve_id}>
                      <tr
                        style={{ cursor: "pointer" }}
                        onClick={() => setOpenCve(isOpen ? null : r.cve_id)}
                        title="Click to expand"
                      >
                        <td>
                          <div className="pluginName">{r.cve_id}</div>
                          <div className="muted">
                            {r.is_kev ? "KEV: yes" : "KEV: no"}
                            {r.effective_cvss_version ? ` • ${r.effective_cvss_version}` : ""}
                          </div>
                        </td>

                        <td className="num mono">{r.final_priority_score}</td>
                        <td className="num mono">{r.priority_score}</td>

                        <td className="num">{r.affected_assets}</td>
                        <td className="num">{r.finding_cve_links}</td>

                        <td className="num mono">{r.effective_cvss_score ?? ""}</td>
                        <td className="num mono">{r.vpr_score ?? ""}</td>
                        <td className="num mono">{r.epss_score ?? ""}</td>
                      </tr>

                      {isOpen && (
                        <CveDetails key={`${r.cve_id}-details`} cveId={r.cve_id} limit={200} />
                      )}
                    </React.Fragment>
                  );
                })}

                {!loading && cveRows.length === 0 && (
                  <tr>
                    <td colSpan={10} className="empty">
                      No rows match your filter.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          ) : view === "findings" ? (
            <div className="tableWrap">
              <table>
                <thead>
                  <tr>
                    <th
                      style={{ cursor: "pointer" }}
                      title="Sort by asset"
                      onClick={() => onFindSort("asset")}
                    >
                      Asset{findArrow("asset")}
                    </th>

                    <th>IP</th>

                    <th
                      style={{ cursor: "pointer" }}
                      title="Sort by severity"
                      onClick={() => onFindSort("severity_nessus")}
                    >
                      Severity{findArrow("severity_nessus")}
                    </th>

                    <th>Status</th>
                    <th
                      style={{ cursor: "pointer" }}
                      title="Sort by last_seen"
                      onClick={() => onFindSort("last_seen")}
                    >
                      Last seen{findArrow("last_seen")}
                    </th>
                    <th
                      style={{ cursor: "pointer" }}
                      title="Sort by first_seen"
                      onClick={() => onFindSort("first_seen")}
                    >
                      First seen{findArrow("first_seen")}
                    </th>

                    <th
                      style={{ cursor: "pointer" }}
                      title="Sort by plugin_id"
                      onClick={() => onFindSort("plugin_id")}
                    >
                      Plugin{findArrow("plugin_id")}
                    </th>

                    <th className="num">Count</th>
                    <th className="num">Port</th>
                    <th>Proto</th>
                    <th>Solution</th>
                  </tr>
                </thead>
                <tbody>
                  {findingsRows.map((r, idx) => (
                    <tr key={`${r.asset}-${r.plugin_id}-${r.port ?? "na"}-${r.protocol ?? "na"}-${idx}`}>
                      <td className="mono">{r.asset}</td>
                      <td className="mono">{r.ip ?? ""}</td>
                      <td>{r.severity}</td>
                      <td>{r.status}</td>
                      <td className="mono">{r.last_seen ? fmtDate(r.last_seen) : ""}</td>
                      <td className="mono">{r.first_seen ? fmtDate(r.first_seen) : ""}</td>
                      <td>
                        <div className="pluginName">{r.plugin_name}</div>
                        <div className="muted">plugin_id: {r.plugin_id}</div>
                      </td>
                      <td className="num mono">{(r as any).instance_count ?? ""}</td>
                      <td className="num mono">{r.port ?? ""}</td>
                      <td className="mono">{r.protocol ?? ""}</td>
                      <td className="mono">{r.solution_preview ?? ""}</td>
                    </tr>
                  ))}

                  {!loading && findingsRows.length === 0 && (
                    <tr>
                      <td colSpan={10} className="empty">
                        No rows match your filter.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>Remediation</th>
                  <th className="num">Bucket</th>
                  <th className="num">Assets</th>
                  <th className="num">Findings</th>
                  <th className="num">KEV CVE count</th>
                  <th>CVEs (KEV/all)</th>
                </tr>
              </thead>
              <tbody>
                {remRows.map((r) => {
                  const isOpen = openRemediationKey === r.remediation_key;

                  return (
                    <React.Fragment key={r.remediation_key}>
                      <tr
                        style={{ cursor: "pointer" }}
                        title="Click to expand"
                        onClick={async () => {
                          try {
                            if (isOpen) {
                              setOpenRemediationKey(null);
                              setRemediationDetail(null);
                              return;
                            }
                            setOpenRemediationKey(r.remediation_key);
                            setRemediationDetail(null); // clear previous
                            const detail = await loadRemediationDetail(r.remediation_key);
                            setRemediationDetail(detail);
                          } catch (e: any) {
                            // keep it simple: show error in the detail panel
                            setRemediationDetail({ error: e?.message ?? "Failed to load detail" });
                          }
                        }}
                      >
                        <td>
                          <div className="pluginName">{r.remediation_title || r.remediation_key}</div>
                          <div className="muted">
                            key: {r.remediation_key}
                            {r.remediation_type ? ` • type: ${r.remediation_type}` : ""}
                            {r.max_severity_label ? ` • severity: ${r.max_severity_label}` : ""}
                          </div>
                        </td>

                        <td className="num mono">{r.priority_bucket ?? ""}</td>

                        <td className="num">{r.affected_asset_count ?? ""}</td>

                        <td className="num">{r.finding_count ?? ""}</td>

                        <td className="num">{r.kev_cve_count ?? ""}</td>

                        <td className="mono">
                          {(r.cves_kev ?? []).join(", ")}
                          {(r.cves_all ?? []).length ? (
                            <div className="muted" style={{ marginTop: 4 }}>
                              all: {(r.cves_all ?? []).join(", ")}
                            </div>
                          ) : null}
                        </td> 
                      </tr>

                      {isOpen && (
                        <tr>
                          <td colSpan={999} className="mono" style={{ whiteSpace: "pre-wrap" }}>
                            <div style={{ display: "flex", gap: 12, marginBottom: 10, flexWrap: "wrap" }}>
                              <a
                                href={`/api/remediation-actions/${encodeURIComponent(r.remediation_key)}/export.csv`}
                                target="_blank"
                                rel="noreferrer"
                              >
                                Download CSV
                              </a>

                              <a
                                href={`/api/remediation-actions/${encodeURIComponent(r.remediation_key)}`}
                                target="_blank"
                                rel="noreferrer"
                              >
                                View JSON
                              </a>
                            </div>

                            {remediationDetail ? JSON.stringify(remediationDetail, null, 2) : "Loading…"}
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}


                {!loading && remRows.length === 0 && (
                  <tr>
                    <td colSpan={6} className="empty">
                      No rows match your filter.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <footer className="footer">
        {view === "patch" ? (
          <>
            <span>
              API: <code>/api/kev/patch-snapshot</code>
            </span>
            <span>Next: drill-down from plugin → assets</span>
          </>
        ) : view === "cves" ? (
          <>
            <span>
              API: <code>/api/kev/cves</code>
            </span>
            <span>Next: drill-down from CVE → assets/plugins</span>
          </>
        ) : view === "findings" ? (
          <>
            <span>
              API: <code>/api/findings</code>
            </span>
            <span>Next: (optional) expand row → synopsis/solution/plugin_output</span>
          </>
        ) : (
          <>
            <span>
              API: <code>/api/remediation-actions</code>
            </span>
            <span>Next: remediation drill-down → export + per-remediation details</span>
          </>
        )}
      </footer>
    </div>
  );
}

function splitCves(s: string): string[] {
  return (s || "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

function CveDetails({ cveId, limit }: { cveId: string; limit: number }) {
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [rows, setRows] = useState<PatchRow[]>([]);

  useEffect(() => {
    const controller = new AbortController();

    async function run() {
      setLoading(true);
      setErr(null);
      try {
        // pull patch snapshot rows, then filter client-side for this CVE
        const url = `/api/kev/patch-snapshot?min_assets=0&limit=${encodeURIComponent(
          String(limit)
        )}`;
        const resp = await fetch(url, { signal: controller.signal });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);

        const json = (await resp.json()) as ApiResp<PatchRow>;
        const filtered = (json.rows || []).filter((r) =>
          splitCves(r.cves).includes(cveId)
        );
        setRows(filtered);
      } catch (e: any) {
        if (e?.name === "AbortError") return;
        setErr(e?.message ?? "Request failed");
      } finally {
        setLoading(false);
      }
    }

    run();
    return () => controller.abort();
  }, [cveId, limit]);

  return (
    <tr>
      <td colSpan={8}>
        <div className="details">
          <div className="detailsHead">
            <div>
              <div className="detailsTitle">Related patches/plugins</div>
              <div className="detailsSub mono">{cveId}</div>
            </div>
            <div className="detailsMeta muted">
              {loading ? "Loading…" : `${rows.length} match(es)`}
              {err ? ` • Error: ${err}` : ""}
            </div>
          </div>

          {!loading && !err && rows.length === 0 && (
            <div className="muted">No matching patch/plugin rows in snapshot.</div>
          )}

          {rows.length > 0 && (
            <div className="tableWrap" style={{ marginTop: 10 }}>
              <table style={{ minWidth: 900 }}>
                <thead>
                  <tr>
                    <th>Plugin</th>
                    <th className="num">Assets</th>
                    <th className="num">KEV CVEs</th>
                    <th>CVEs</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((p) => (
                    <tr key={p.plugin_id}>
                      <td>
                        <div className="pluginName">{p.plugin_name}</div>
                        <div className="muted">plugin_id: {p.plugin_id}</div>
                      </td>
                      <td className="num">{p.affected_assets}</td>
                      <td className="num">{p.kev_cves}</td>
                      <td className="mono">{p.cves}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </td>
    </tr>
  );
}

