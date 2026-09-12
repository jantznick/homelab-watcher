import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  fetchDns,
  type DnsInventoryPayload,
  type DnsRecordRow,
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

function portLabel(r: DnsRecordRow): string {
  if (typeof r.port === "number") return String(r.port);
  if (r.upstream) return r.upstream;
  return "—";
}

export function DnsPanel() {
  const [data, setData] = useState<DnsInventoryPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const payload = await fetchDns();
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
      void fetchDns()
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

  const pihole = data?.pihole;
  const records = data?.records || [];
  const networking = data?.networking;

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return records;
    return records.filter((r: DnsRecordRow) => {
      const hay = [
        r.hostname,
        r.type,
        r.target,
        r.container || "",
        r.upstream || "",
        typeof r.port === "number" ? String(r.port) : "",
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [records, query]);

  const notConfigured = pihole && !pihole.configured;
  const fetchFailed = pihole?.configured && pihole.ok === false;
  const emptyOk =
    pihole?.configured && pihole.ok === true && records.length === 0;

  return (
    <div className="panel dns-panel">
      <div className="panel-head">
        <h2>Local DNS</h2>
        <span className="meta">{formatTakenAt(data?.taken_at)}</span>
      </div>

      <div className="container-toolbar">
        <input
          className="container-search"
          type="search"
          placeholder="Filter…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Filter DNS records"
        />
      </div>

      {error ? (
        <div className="empty empty-error" role="status">
          <strong>Could not load DNS</strong>
          <p>{error}</p>
        </div>
      ) : null}

      {!error && notConfigured ? (
        <div className="empty-cta" role="status">
          <p>Pi-hole isn’t configured.</p>
          <Link to="/settings/pihole" className="home-meta-link">
            Settings → Pi-hole
          </Link>
        </div>
      ) : null}

      {!error && fetchFailed ? (
        <div className="empty empty-error" role="status">
          <strong>Pi-hole unreachable</strong>
          <p>{pihole?.message || "Last poll failed."}</p>
          <Link to="/settings/pihole" className="home-meta-link">
            Settings → Pi-hole
          </Link>
        </div>
      ) : null}

      {!error && emptyOk ? (
        <div className="empty" role="status">
          No Local DNS records.{" "}
          <Link to="/settings/pihole" className="home-meta-link">
            Settings → Pi-hole
          </Link>
        </div>
      ) : null}

      {!error &&
      pihole?.configured &&
      pihole.ok === true &&
      records.length > 0 &&
      !filtered.length ? (
        <div className="empty">No matches.</div>
      ) : null}

      {!error &&
      pihole?.configured &&
      pihole.ok === true &&
      filtered.length > 0 ? (
        <>
          {networking?.configured && networking.ok === false ? (
            <div className="pihole-note">
              {networking.message ||
                "Networking join incomplete — port/container may be empty."}{" "}
              <Link to="/settings/networking" className="home-meta-link">
                Settings → Networking
              </Link>
            </div>
          ) : null}
          <div className="table-scroll containers-table-wrap">
            <table className="table containers-table dns-table">
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>Port</th>
                  <th>Container</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((r) => (
                  <tr key={`${r.hostname}-${r.type}-${r.target}`}>
                    <td className="name">
                      <div className="dns-domain-block">
                        <span className="mono wrap">{r.hostname}</span>
                        <span className="dns-domain-meta quiet">
                          <span className="chip chip-muted">{r.type}</span>
                          <span className="mono">{r.target || "—"}</span>
                        </span>
                      </div>
                    </td>
                    <td className="mono wrap" title={r.upstream || undefined}>
                      {portLabel(r)}
                    </td>
                    <td>
                      {r.container ? (
                        <Link
                          to={containerHref(r.container)}
                          className="home-meta-link"
                          title={
                            r.upstream
                              ? `${r.upstream}${
                                  r.container_state
                                    ? ` · ${r.container_state}`
                                    : ""
                                }`
                              : r.container_state || undefined
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
        </>
      ) : null}
    </div>
  );
}
