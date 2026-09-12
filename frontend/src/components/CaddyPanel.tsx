import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  fetchCaddy,
  type CaddyInventoryPayload,
  type CaddyRecordRow,
} from "../api";

function formatTakenAt(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function containerHref(name: string): string {
  return `/containers?scope=all&open=${encodeURIComponent(name)}`;
}

function upstreamLabel(r: CaddyRecordRow): string {
  if (typeof r.port === "number" && r.upstream) {
    return r.upstream;
  }
  if (typeof r.port === "number") return String(r.port);
  if (r.upstream) return r.upstream;
  return "—";
}

function sourceLabel(source: string | null | undefined): string {
  const s = (source || "").toLowerCase();
  if (s === "api") return "Admin API";
  if (s === "caddyfile") return "Caddyfile";
  if (s === "label") return "Label";
  return source || "—";
}

export function CaddyPanel() {
  const [data, setData] = useState<CaddyInventoryPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const payload = await fetchCaddy();
        if (!cancelled) {
          setData(payload);
          setError(null);
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e));
        }
      }
    })();
    const id = window.setInterval(() => {
      void fetchCaddy()
        .then((payload) => {
          if (!cancelled) {
            setData(payload);
            setError(null);
          }
        })
        .catch(() => {
          /* keep last good snapshot */
        });
    }, 15000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);

  const networking = data?.networking;
  const records = data?.records || [];

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return records;
    return records.filter((r: CaddyRecordRow) => {
      const hay = [
        r.hostname,
        r.upstream || "",
        r.container || "",
        r.source || "",
        typeof r.port === "number" ? String(r.port) : "",
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [records, query]);

  const notConfigured = networking && !networking.configured;
  const fetchFailed =
    networking?.configured === true && networking.ok === false && records.length === 0;
  const emptyOk =
    networking?.configured === true &&
    networking.ok !== false &&
    records.length === 0;

  return (
    <div className="panel dns-panel">
      <div className="panel-head">
        <h2>Caddy</h2>
        <span className="meta">{formatTakenAt(data?.taken_at)}</span>
      </div>

      <div className="container-toolbar">
        <input
          className="container-search"
          type="search"
          placeholder="Filter…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Filter Caddy routes"
        />
      </div>

      {error ? (
        <div className="empty empty-error" role="status">
          <strong>Could not load Caddy routes</strong>
          <p>{error}</p>
        </div>
      ) : null}

      {!error && notConfigured ? (
        <div className="empty-cta" role="status">
          <p>Caddy isn’t configured.</p>
          <Link to="/settings/networking" className="home-meta-link">
            Settings → Networking
          </Link>
        </div>
      ) : null}

      {!error && fetchFailed ? (
        <div className="empty empty-error" role="status">
          <strong>No routes discovered</strong>
          <p>{networking?.message || "Check Admin API or Caddyfile path."}</p>
          <Link to="/settings/networking" className="home-meta-link">
            Settings → Networking
          </Link>
        </div>
      ) : null}

      {!error && emptyOk ? (
        <div className="empty" role="status">
          No Caddy sites yet.{" "}
          <Link to="/settings/networking" className="home-meta-link">
            Settings → Networking
          </Link>
        </div>
      ) : null}

      {!error && records.length > 0 && !filtered.length ? (
        <div className="empty">No matches.</div>
      ) : null}

      {!error && filtered.length > 0 ? (
        <div className="table-scroll containers-table-wrap">
          <table className="table containers-table dns-table">
            <thead>
              <tr>
                <th>Domain</th>
                <th>Upstream</th>
                <th>Container</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((r) => (
                <tr key={`${r.hostname}-${r.upstream || ""}-${r.source || ""}`}>
                  <td className="name">
                    <div className="dns-domain-block">
                      <span className="mono wrap">{r.hostname}</span>
                      <span className="dns-domain-meta quiet">
                        <span className="chip chip-muted">
                          {sourceLabel(r.source)}
                        </span>
                        {r.in_dns ? (
                          <span className="badge-dns" title="In Pi-hole Local DNS">
                            DNS
                          </span>
                        ) : null}
                      </span>
                    </div>
                  </td>
                  <td className="mono wrap" title={r.upstream || undefined}>
                    {upstreamLabel(r)}
                  </td>
                  <td>
                    {r.container ? (
                      <Link
                        to={containerHref(r.container)}
                        className="home-meta-link"
                        title={
                          r.container_state
                            ? r.container_state
                            : undefined
                        }
                      >
                        {r.container}
                      </Link>
                    ) : (
                      <span className="quiet">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}
