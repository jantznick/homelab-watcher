import { useEffect, useMemo, useState, type MouseEvent } from "react";
import { useSearchParams } from "react-router-dom";
import { setWatched, type ContainerItem, type PiHoleStatus } from "../api";
import { ContainerDrawer, type ContainerDrawerStep } from "./ContainerDrawer";

function formatUptime(seconds: number | null | undefined): string {
  if (seconds == null) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function stateChip(state: string) {
  const s = (state || "").toLowerCase();
  if (s === "running") return "chip chip-ok";
  if (s === "exited" || s === "dead") return "chip chip-bad";
  if (s === "restarting" || s === "paused") return "chip chip-warn";
  return "chip chip-muted";
}

function isRunning(c: ContainerItem): boolean {
  return (c.state || c.status || "").toLowerCase() === "running";
}

function canQuickStart(c: ContainerItem): boolean {
  const s = (c.state || c.status || "").toLowerCase();
  return s === "exited" || s === "created" || s === "dead" || !s;
}

function isStarred(c: ContainerItem): boolean {
  return Boolean(c.watched ?? c.vital);
}

function displayHost(url: string): string {
  try {
    const u = new URL(url);
    return u.host + (u.pathname !== "/" ? u.pathname.replace(/\/$/, "") : "");
  } catch {
    return url.replace(/^https?:\/\//, "");
  }
}

function securityBadge(c: ContainerItem) {
  const sec = c.security;
  if (!sec?.enabled) return null;
  const status = sec.scan_status;
  if (status === "unavailable" || status === "error") {
    return (
      <span className="badge-sec muted" title={sec.scan_error || "scan unavailable"}>
        scan n/a
      </span>
    );
  }
  if (status === "pending") {
    return <span className="badge-sec muted">scan…</span>;
  }
  const max = (sec.max_severity || "").toLowerCase();
  const count = sec.issue_count || 0;
  if (!count && !max) {
    return <span className="badge-sec ok">ok</span>;
  }
  const cls =
    max === "critical" || max === "high"
      ? "badge-sec warn"
      : "badge-sec";
  return (
    <span className={cls} title={`Max ${max || "—"} · ${count} issues`}>
      {max || "issues"}
      {count ? ` · ${count}` : ""}
    </span>
  );
}

type Scope = "running" | "all" | "starred" | "updates" | "issues" | "down";

const SCOPES: readonly Scope[] = [
  "running",
  "all",
  "starred",
  "updates",
  "issues",
  "down",
];

function scopeFromSearch(params: URLSearchParams): Scope {
  const raw = params.get("scope");
  if (raw && (SCOPES as readonly string[]).includes(raw)) {
    return raw as Scope;
  }
  return "running";
}

export function ContainersPanel({
  items,
  takenAt,
  pihole,
  actionsEnabled,
  onChanged,
  dockerError,
  dockerAvailable,
}: {
  items: ContainerItem[];
  takenAt: string | null;
  pihole: PiHoleStatus | null;
  actionsEnabled: boolean;
  onChanged: () => void;
  dockerError?: string | null;
  dockerAvailable?: boolean | null;
}) {
  const [searchParams, setSearchParams] = useSearchParams();
  const [scope, setScope] = useState<Scope>(() => scopeFromSearch(searchParams));
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<ContainerItem | null>(null);
  const [modalStep, setModalStep] = useState<ContainerDrawerStep>("detail");

  useEffect(() => {
    setScope(scopeFromSearch(searchParams));
  }, [searchParams]);

  useEffect(() => {
    const openName = (searchParams.get("open") || "").trim();
    if (!openName || !items.length) return;
    const match = items.find(
      (c) =>
        c.name === openName ||
        c.container_id === openName ||
        (c.container_id && openName.startsWith(c.container_id)),
    );
    if (!match) return;
    setModalStep("detail");
    setSelected(match);
    const next = new URLSearchParams(searchParams);
    next.delete("open");
    setSearchParams(next, { replace: true });
  }, [items, searchParams, setSearchParams]);

  function openDetail(c: ContainerItem) {
    setModalStep("detail");
    setSelected(c);
  }

  function openStartConfirm(e: MouseEvent, c: ContainerItem) {
    e.stopPropagation();
    if (!actionsEnabled || !canQuickStart(c)) return;
    setModalStep("confirm-start");
    setSelected(c);
  }

  function selectScope(next: Scope) {
    setScope(next);
    if (next === "running") {
      setSearchParams({}, { replace: true });
      return;
    }
    setSearchParams({ scope: next }, { replace: true });
  }

  const runningCount = useMemo(() => items.filter(isRunning).length, [items]);
  const stoppedCount = items.length - runningCount;
  const starredCount = useMemo(() => items.filter(isStarred).length, [items]);

  const dockerDown = Boolean(dockerError) || dockerAvailable === false;

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return items.filter((c) => {
      if (scope === "running" && !isRunning(c)) return false;
      if (scope === "down" && isRunning(c)) return false;
      if (scope === "starred" && !isStarred(c)) return false;
      if (scope === "updates" && !c.update_available) return false;
      if (scope === "issues") {
        const sec = c.security;
        if (!sec?.enabled || !sec.issue_count) return false;
      }
      if (!q) return true;
      const hay = [
        c.name,
        c.image,
        c.state,
        c.status,
        c.access_url || "",
        ...(c.pihole_hostnames || []),
        ...((c.networking?.entries || []).map((e) => e.hostname)),
        ...((c.networking?.entries || []).map((e) => e.upstream)),
      ]
        .join(" ")
        .toLowerCase();
      return hay.includes(q);
    });
  }, [items, scope, query]);

  const piholeNote = (() => {
    if (!pihole || !pihole.configured) return null;
    if (pihole.ok === false) return pihole.message || "Pi-hole unreachable";
    const n = pihole.record_count ?? 0;
    if (n === 0) {
      return (
        pihole.message ||
        "Pi-hole connected but 0 local DNS records — check Settings → Pi-hole Test"
      );
    }
    return null;
  })();

  async function toggleStar(e: MouseEvent, c: ContainerItem) {
    e.stopPropagation();
    try {
      await setWatched({
        watched_key: c.watched_key || c.vital_key || undefined,
        name: c.name,
        compose_project: c.compose_project,
        compose_service: c.compose_service,
        watched: !isStarred(c),
      });
      onChanged();
    } catch {
      /* parent refresh will show state */
    }
  }

  function rowBadges(c: ContainerItem) {
    const bump = c.update_bump;
    return (
      <>
        {c.update_available ? <span className="badge-update">update</span> : null}
        {c.update_available && bump ? (
          <span
            className={`badge-bump bump-${bump}`}
            title={
              c.update_from && c.update_to
                ? `${c.update_from} → ${c.update_to}`
                : bump === "unknown"
                  ? "Version jump unknown"
                  : undefined
            }
          >
            {bump}
          </span>
        ) : null}
        {c.pihole_matched ? (
          <span
            className="badge-dns"
            title={(c.pihole_hostnames || []).join(", ")}
          >
            DNS
          </span>
        ) : null}
        {c.proxy_matched || c.networking?.mapped ? (
          <span
            className="badge-proxy"
            title={(c.networking?.entries || [])
              .map((e) =>
                e.upstream
                  ? `${e.hostname} → ${e.upstream}`
                  : e.hostname,
              )
              .join("\n")}
          >
            proxy
          </span>
        ) : null}
      </>
    );
  }

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Containers</h2>
        <div className="meta">
          {dockerDown
            ? "Docker unavailable"
            : `${runningCount} running${
                stoppedCount > 0 ? ` · ${stoppedCount} stopped` : ""
              }${starredCount > 0 ? ` · ${starredCount} starred` : ""}`}
          {takenAt && !dockerDown ? ` · ${new Date(takenAt).toLocaleString()}` : ""}
        </div>
      </div>

      <div className="container-toolbar">
        <div className="scope-tabs-rail">
          <div className="scope-tabs" role="tablist" aria-label="Container scope">
            {(
              [
                ["running", "Running"],
                ["all", stoppedCount > 0 ? `All (${items.length})` : "All"],
                [
                  "down",
                  stoppedCount > 0 ? `Down (${stoppedCount})` : "Down",
                ],
                ["starred", "Starred"],
                ["updates", "Updates"],
                ["issues", "Issues"],
              ] as const
            ).map(([id, label]) => (
              <button
                key={id}
                type="button"
                role="tab"
                aria-selected={scope === id}
                className={
                  scope === id
                    ? id === "all"
                      ? "scope-tab active scope-tab-all"
                      : "scope-tab active"
                    : id === "all"
                      ? "scope-tab scope-tab-all"
                      : "scope-tab"
                }
                onClick={() => selectScope(id)}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
        <input
          className="container-search"
          type="search"
          placeholder="Filter…"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          aria-label="Filter containers"
        />
      </div>

      {dockerDown ? (
        <div className="empty empty-error" role="status">
          <strong>Cannot reach Docker</strong>
          {dockerError ? <p>{dockerError}</p> : null}
        </div>
      ) : null}

      {piholeNote && !dockerDown ? <div className="pihole-note">{piholeNote}</div> : null}

      {!dockerDown && !items.length ? (
        <div className="empty">No containers yet.</div>
      ) : !dockerDown && !filtered.length ? (
        <div className="empty">No matches.</div>
      ) : !dockerDown ? (
        <>
          <div className="table-scroll containers-table-wrap">
            <table className="table containers-table">
              <thead>
                <tr>
                  <th className="star-col" />
                  <th>Name</th>
                  <th>Status</th>
                  <th>Security</th>
                  <th>Web</th>
                  <th>Image</th>
                  <th>Uptime</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((c) => (
                  <tr
                    key={c.container_id}
                    className={isStarred(c) ? "row-starred clickable" : "clickable"}
                    onClick={() => openDetail(c)}
                  >
                    <td className="star-col">
                      <button
                        type="button"
                        className={isStarred(c) ? "star-btn on" : "star-btn"}
                        title={isStarred(c) ? "Unstar" : "Star"}
                        aria-label={isStarred(c) ? "Unstar container" : "Star container"}
                        onClick={(e) => void toggleStar(e, c)}
                      >
                        {isStarred(c) ? "★" : "☆"}
                      </button>
                    </td>
                    <td className="name">
                      <div className="container-name-block">
                        <span>
                          {c.name}
                          {rowBadges(c)}
                        </span>
                        {c.description ? (
                          <span className="quiet container-desc">{c.description}</span>
                        ) : null}
                      </div>
                    </td>
                    <td>
                      <span className={stateChip(c.state || c.status)}>
                        {c.state || c.status}
                      </span>
                      {actionsEnabled && canQuickStart(c) ? (
                        <button
                          type="button"
                          className="btn btn-row-action"
                          title="Start"
                          onClick={(e) => openStartConfirm(e, c)}
                        >
                          Start
                        </button>
                      ) : null}
                    </td>
                    <td>{securityBadge(c)}</td>
                    <td className="web-cell">
                      {c.access_url ? (
                        <a
                          href={c.access_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="access-link"
                          title={c.access_url}
                          onClick={(e) => e.stopPropagation()}
                        >
                          {displayHost(c.access_url)}
                        </a>
                      ) : (
                        <span className="quiet">—</span>
                      )}
                    </td>
                    <td className="mono">{c.image}</td>
                    <td className="mono">{formatUptime(c.uptime_seconds)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <ul className="container-card-list">
            {filtered.map((c) => (
              <li
                key={c.container_id}
                className={
                  isStarred(c)
                    ? "container-card row-starred clickable"
                    : "container-card clickable"
                }
                onClick={() => openDetail(c)}
              >
                <div className="container-card-top">
                  <button
                    type="button"
                    className={isStarred(c) ? "star-btn on" : "star-btn"}
                    title={isStarred(c) ? "Unstar" : "Star"}
                    aria-label={isStarred(c) ? "Unstar container" : "Star container"}
                    onClick={(e) => void toggleStar(e, c)}
                  >
                    {isStarred(c) ? "★" : "☆"}
                  </button>
                  <div className="container-card-title">
                    <div className="container-name-block">
                      <span className="name">{c.name}</span>
                      {c.description ? (
                        <span className="quiet container-desc">{c.description}</span>
                      ) : null}
                    </div>
                    {rowBadges(c)}
                  </div>
                  <span className={stateChip(c.state || c.status)}>
                    {c.state || c.status}
                  </span>
                  {actionsEnabled && canQuickStart(c) ? (
                    <button
                      type="button"
                      className="btn btn-row-action"
                      title="Start"
                      onClick={(e) => openStartConfirm(e, c)}
                    >
                      Start
                    </button>
                  ) : null}
                </div>
                <div className="container-card-meta">
                  {securityBadge(c)}
                  {c.access_url ? (
                    <a
                      href={c.access_url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="access-link"
                      onClick={(e) => e.stopPropagation()}
                    >
                      {displayHost(c.access_url)}
                    </a>
                  ) : null}
                  <span className="mono">{formatUptime(c.uptime_seconds)}</span>
                </div>
                <div className="mono container-card-image">{c.image}</div>
              </li>
            ))}
          </ul>
        </>
      ) : null}

      <ContainerDrawer
        container={
          selected
            ? items.find((i) => i.container_id === selected.container_id) || selected
            : null
        }
        open={Boolean(selected)}
        onClose={() => {
          setSelected(null);
          setModalStep("detail");
        }}
        actionsEnabled={actionsEnabled}
        onChanged={onChanged}
        initialStep={modalStep}
      />
    </section>
  );
}
