import { Link } from "react-router-dom";
import type {
  CheckItem,
  ContainerItem,
  DiskMetric,
  DockerDiskUsage,
  ListeningPort,
  PiHoleStatus,
  SpeedTestInfo,
  StatusPayload,
} from "../api";

type AttentionTone = "ok" | "warn" | "bad";

type AttentionItem = {
  id: string;
  title: string;
  count: number | string;
  detail: string;
  tone: AttentionTone;
  to: string;
};

type MetricTone = "ok" | "warn" | "bad" | "muted";

type MetricItem = {
  id: string;
  label: string;
  value: number | string;
  tone: MetricTone;
  to: string;
};

function isRunning(c: ContainerItem): boolean {
  return (c.state || c.status || "").toLowerCase() === "running";
}

function isStarred(c: ContainerItem): boolean {
  return Boolean(c.watched ?? c.vital);
}

function secIsHigh(c: ContainerItem): boolean {
  const max = (c.security?.max_severity || "").toUpperCase();
  return max === "CRITICAL" || max === "HIGH" || Boolean(c.security?.notable);
}

function stateChip(state: string) {
  const s = (state || "").toLowerCase();
  if (s === "running") return "chip chip-ok";
  if (s === "exited" || s === "dead") return "chip chip-bad";
  if (s === "restarting" || s === "paused") return "chip chip-warn";
  return "chip chip-muted";
}

function diskTone(
  percent: number | null | undefined,
  warn: number,
): "ok" | "warn" | "bad" {
  if (percent == null) return "ok";
  if (percent >= Math.min(95, warn + 10)) return "bad";
  if (percent >= warn) return "warn";
  return "ok";
}

function formatBytes(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function formatUptime(seconds: number | null | undefined): string {
  if (seconds == null || Number.isNaN(seconds)) return "—";
  const s = Math.max(0, Math.floor(seconds));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function formatWhen(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return "—";
  }
}

function routeForItem(id: string): string {
  switch (id) {
    case "updates":
      return "/containers?scope=updates";
    case "downs":
      return "/containers?scope=down";
    case "docker":
    case "security":
      return "/containers?scope=issues";
    case "disks":
    case "ports":
    case "docker-disk":
      return "/host";
    case "disks-select":
      return "/settings/disks";
    case "pihole":
      return "/settings/pihole";
    case "plex":
      return "/settings/plex";
    case "checks":
      return "/settings/checks";
    default:
      return "/";
  }
}

function checkSettingsPath(c: CheckItem): string {
  const name = c.name.trim().toLowerCase();
  if (name === "plex") return "/settings/plex";
  if (name === "pi-hole" || name === "pihole") return "/settings/pihole";
  return "/settings/checks";
}

export function HomePanel({
  containers,
  disks,
  warn,
  diskSelectionNeeded,
  checks,
  pihole,
  dockerError,
  dockerAvailable,
  dockerDisk,
  listeningPorts,
  listeningPortsEnabled,
  cpu,
  mem,
  memUsed,
  memTotal,
  hostCollecting,
  hostAt,
  uptimeSeconds,
  speedTest,
  status,
}: {
  containers: ContainerItem[];
  disks: DiskMetric[];
  warn: number;
  diskSelectionNeeded?: boolean | null;
  checks: CheckItem[];
  pihole: PiHoleStatus | null;
  dockerError?: string | null;
  dockerAvailable?: boolean | null;
  dockerDisk?: DockerDiskUsage | null;
  listeningPorts?: ListeningPort[];
  listeningPortsEnabled?: boolean | null;
  cpu?: number | null;
  mem?: number | null;
  memUsed?: number | null;
  memTotal?: number | null;
  hostCollecting?: boolean;
  hostAt?: string | null;
  uptimeSeconds?: number | null;
  speedTest?: SpeedTestInfo | null;
  status?: StatusPayload | null;
}) {
  const dockerDown = Boolean(dockerError) || dockerAvailable === false;
  const running = containers.filter(isRunning);
  const updates = containers.filter((c) => c.update_available);
  const starred = containers.filter(isStarred);
  const downs = starred.filter((c) => !isRunning(c));
  const stopped = containers.filter((c) => !isRunning(c));
  const securityHighs = containers.filter(secIsHigh);
  const diskWarns = disks.filter(
    (d) => d.percent != null && !d.error && d.percent >= warn,
  );
  const checksDown = checks.filter((c) => !c.ok);
  const plex = checks.find((c) => c.name.trim().toLowerCase() === "plex");
  const plexIssue = plex && !plex.ok;
  const portsOn = listeningPortsEnabled !== false;
  const exposedPorts = (listeningPorts || []).filter(
    (p) => p.bind_scope === "all" || p.bind_scope === "lan",
  );
  const allBound = exposedPorts.some((p) => p.bind_scope === "all");

  let critCount = 0;
  let highCount = 0;
  let scannedCount = 0;
  for (const c of containers) {
    const sec = c.security;
    if (!sec?.enabled) continue;
    if (sec.scan_status === "pending" || sec.scan_status === "unavailable") continue;
    scannedCount += 1;
    const sev = sec.severity || {};
    critCount += sev.CRITICAL || sev.critical || 0;
    highCount += sev.HIGH || sev.high || 0;
  }
  const securityOn =
    status?.security_enabled === true ||
    containers.some((c) => c.security?.enabled);

  const metrics: MetricItem[] = [
    {
      id: "running",
      label: "Running",
      value: dockerDown ? "—" : running.length,
      tone: dockerDown ? "bad" : "ok",
      to: "/containers",
    },
    {
      id: "updates",
      label: "Updates",
      value: updates.length,
      tone: updates.length ? "warn" : "ok",
      to: "/containers?scope=updates",
    },
    {
      id: "starred-down",
      label: "Starred down",
      value: downs.length,
      tone: downs.length ? "bad" : "ok",
      to: "/containers?scope=down",
    },
    {
      id: "disks",
      label: diskSelectionNeeded ? "Disks" : "Disks warn",
      value: diskSelectionNeeded ? "—" : diskWarns.length,
      tone: diskSelectionNeeded || diskWarns.length ? "warn" : "ok",
      to: diskSelectionNeeded ? "/settings/disks" : "/host",
    },
  ];

  if (!dockerDown && dockerDisk?.available) {
    const reclaim = dockerDisk.reclaimable_bytes ?? 0;
    metrics.push({
      id: "docker-disk",
      label: "Docker reclaimable",
      value: formatBytes(reclaim),
      tone: reclaim >= 5 * 1024 ** 3 ? "warn" : reclaim > 0 ? "muted" : "ok",
      to: "/host#docker-disk",
    });
  }

  if (portsOn) {
    metrics.push({
      id: "ports",
      label: "LAN ports",
      value: exposedPorts.length,
      tone: allBound ? "warn" : exposedPorts.length ? "muted" : "ok",
      to: "/host",
    });
  }

  if (securityOn) {
    metrics.push({
      id: "security",
      label: "HIGH+",
      value: securityHighs.length,
      tone: securityHighs.length ? "warn" : "ok",
      to: "/containers?scope=issues",
    });
  }

  const items: AttentionItem[] = [];

  if (dockerDown) {
    items.push({
      id: "docker",
      title: "Docker unreachable",
      count: "!",
      detail: dockerError || "API unreachable",
      tone: "bad",
      to: routeForItem("docker"),
    });
  }

  items.push({
    id: "updates",
    title: "Image updates",
    count: updates.length,
    detail:
      updates.length === 0
        ? "None"
        : updates
            .slice(0, 4)
            .map((c) => c.name)
            .join(", ") + (updates.length > 4 ? "…" : ""),
    tone: updates.length ? "warn" : "ok",
    to: routeForItem("updates"),
  });

  items.push({
    id: "downs",
    title: "Starred down",
    count: downs.length,
    detail:
      downs.length === 0
        ? stopped.length
          ? `${stopped.length} stopped (none starred)`
          : "All up"
        : downs.map((c) => c.name).join(", "),
    tone: downs.length ? "bad" : "ok",
    to: routeForItem("downs"),
  });

  if (diskSelectionNeeded) {
    items.push({
      id: "disks-select",
      title: "Disks not selected",
      count: "—",
      detail: "Settings → Disks",
      tone: "warn",
      to: routeForItem("disks-select"),
    });
  } else {
    items.push({
      id: "disks",
      title: "Disk pressure",
      count: diskWarns.length,
      detail:
        diskWarns.length === 0
          ? `< ${warn}%`
          : diskWarns
              .map((d) => `${d.mountpoint || d.path} ${d.percent?.toFixed(0)}%`)
              .join(", "),
      tone: diskWarns.length ? "warn" : "ok",
      to: routeForItem("disks"),
    });
  }

  if (portsOn) {
    items.push({
      id: "ports",
      title: "LAN-exposed ports",
      count: exposedPorts.length,
      detail:
        exposedPorts.length === 0
          ? "None"
          : exposedPorts
              .slice(0, 5)
              .map((p) => `${p.protocol}/${p.port}`)
              .join(", ") + (exposedPorts.length > 5 ? "…" : ""),
      tone: allBound ? "warn" : "ok",
      to: routeForItem("ports"),
    });
  }

  if (securityOn) {
    items.push({
      id: "security",
      title: "Security (HIGH+)",
      count: securityHighs.length,
      detail:
        securityHighs.length === 0
          ? "Clear"
          : securityHighs
              .slice(0, 4)
              .map((c) => c.name)
              .join(", ") + (securityHighs.length > 4 ? "…" : ""),
      tone: securityHighs.length ? "warn" : "ok",
      to: routeForItem("security"),
    });
  }

  if (pihole?.configured) {
    items.push({
      id: "pihole",
      title: "Pi-hole",
      count: pihole.ok === false ? "down" : "ok",
      detail:
        pihole.ok === false
          ? pihole.message || "Unreachable"
          : `${pihole.record_count} records`,
      tone: pihole.ok === false ? "bad" : "ok",
      to: routeForItem("pihole"),
    });
  }

  if (plex) {
    items.push({
      id: "plex",
      title: "Plex",
      count: plex.ok ? "up" : "down",
      detail: plex.message || (plex.ok ? "Up" : "Down"),
      tone: plex.ok ? "ok" : "bad",
      to: routeForItem("plex"),
    });
  } else if (checksDown.length) {
    items.push({
      id: "checks",
      title: "Checks down",
      count: checksDown.length,
      detail: checksDown.map((c) => c.name).join(", "),
      tone: "bad",
      to: routeForItem("checks"),
    });
  }

  const calm =
    !dockerDown &&
    !updates.length &&
    !downs.length &&
    !diskWarns.length &&
    !diskSelectionNeeded &&
    !(portsOn && allBound) &&
    !securityHighs.length &&
    !plexIssue &&
    pihole?.ok !== false &&
    !checksDown.length;

  const digest = status?.digest;
  const pollAt = status?.poll.last_poll_at;
  const nextDigest =
    digest?.next_at != null
      ? formatWhen(digest.next_at)
      : digest?.schedule_summary || (digest?.configured ? "—" : "off");

  const hostWaiting = Boolean(hostCollecting) || !hostAt;
  const showHost =
    hostWaiting ||
    cpu != null ||
    mem != null ||
    disks.length > 0 ||
    diskSelectionNeeded;

  const checkChips: Array<{
    key: string;
    label: string;
    ok: boolean | null;
    to: string;
  }> = [];

  if (pihole?.configured) {
    checkChips.push({
      key: "pihole",
      label: "Pi-hole",
      ok: pihole.ok,
      to: "/settings/pihole",
    });
  }
  for (const c of checks) {
    checkChips.push({
      key: `check-${c.name}`,
      label: c.name,
      ok: c.ok,
      to: checkSettingsPath(c),
    });
  }

  return (
    <div className="home-stack">
      <div className="home-status-line">
        <span>
          Poll <strong>{formatWhen(pollAt)}</strong>
        </span>
        <span className="home-status-sep" aria-hidden="true">
          ·
        </span>
        <span>
          Digest <strong>{nextDigest}</strong>
        </span>
      </div>

      <section className="panel home-metrics-panel">
        <div className="panel-head">
          <h2>At a glance</h2>
          <div className="meta">{calm ? "All quiet" : "Needs review"}</div>
        </div>
        <div className="home-metrics">
          {metrics.map((m) => (
            <Link
              key={m.id}
              to={m.to}
              className={`home-metric home-metric-${m.tone}`}
            >
              <span className="home-metric-value">{m.value}</span>
              <span className="home-metric-label">{m.label}</span>
            </Link>
          ))}
        </div>
      </section>

      <section className="panel">
        <div className="panel-head">
          <h2>Needs attention</h2>
          <div className="meta">{calm ? "Clear" : `${items.filter((i) => i.tone !== "ok").length} items`}</div>
        </div>
        <div className="attention-grid">
          {items.map((item) => (
            <Link
              key={item.id}
              to={item.to}
              className={`attention-card ${item.tone}`}
            >
              <h3>{item.title}</h3>
              <div className="attention-count">{item.count}</div>
              <p>{item.detail}</p>
            </Link>
          ))}
        </div>
      </section>

      {starred.length > 0 ? (
        <section className="panel">
          <div className="panel-head">
            <h2>Starred</h2>
            <div className="meta">
              <Link to="/containers?scope=starred" className="home-meta-link">
                {starred.length} · view all
              </Link>
            </div>
          </div>
          <div className="home-starred-strip">
            {starred.map((c) => {
              const state = (c.state || c.status || "unknown").toLowerCase();
              return (
                <Link
                  key={c.container_id || c.name}
                  to="/containers?scope=starred"
                  className="home-starred-item"
                >
                  <span className="home-starred-name">{c.name}</span>
                  <span className={stateChip(state)}>{state}</span>
                  {c.update_available ? (
                    <span className="badge-update">update</span>
                  ) : null}
                </Link>
              );
            })}
          </div>
        </section>
      ) : null}

      {showHost ? (
        <section className="panel">
          <div className="panel-head">
            <h2>Host</h2>
            <div className="meta">
              <Link to="/host" className="home-meta-link">
                {hostWaiting
                  ? "Collecting…"
                  : hostAt
                    ? formatWhen(hostAt)
                    : "Open host"}
              </Link>
            </div>
          </div>
          <div className="home-host-grid">
            <div className="home-host-meters">
              <div>
                <div className="meter-label">
                  <span>CPU</span>
                  <span>
                    {hostWaiting && cpu == null
                      ? "…"
                      : cpu == null
                        ? "—"
                        : `${cpu.toFixed(1)}%`}
                  </span>
                </div>
                <div
                  className={`bar${
                    hostWaiting && cpu == null ? " collecting" : ""
                  }`}
                >
                  <i
                    style={{
                      width:
                        hostWaiting && cpu == null
                          ? "28%"
                          : `${Math.min(100, cpu ?? 0)}%`,
                    }}
                  />
                </div>
              </div>
              <div>
                <div className="meter-label">
                  <span>RAM</span>
                  <span>
                    {hostWaiting && mem == null
                      ? "…"
                      : mem == null
                        ? "—"
                        : `${mem.toFixed(1)}%`}
                    {mem != null && !hostWaiting
                      ? ` · ${formatBytes(memUsed)} / ${formatBytes(memTotal)}`
                      : ""}
                  </span>
                </div>
                <div
                  className={`bar ${diskTone(mem, 90)}${
                    hostWaiting && mem == null ? " collecting" : ""
                  }`}
                >
                  <i
                    style={{
                      width:
                        hostWaiting && mem == null
                          ? "28%"
                          : `${Math.min(100, mem ?? 0)}%`,
                    }}
                  />
                </div>
              </div>
            </div>
            <div className="home-host-disks">
              {diskSelectionNeeded ? (
                <Link to="/settings/disks" className="home-meta-link">
                  Choose disks
                </Link>
              ) : !disks.length ? (
                <span className="mono">{hostWaiting ? "Collecting disks…" : "No disks"}</span>
              ) : (
                disks.slice(0, 4).map((d) => {
                  const mount = d.mountpoint || d.path;
                  const t = diskTone(d.percent, warn);
                  const err = Boolean(d.error) || d.mounted === false;
                  return (
                    <Link
                      key={`${d.filesystem || ""}:${mount}`}
                      to="/host"
                      className="home-disk-row"
                    >
                      <div className="meter-label">
                        <span className="home-disk-mount" title={mount}>
                          {mount}
                        </span>
                        <span>
                          {err
                            ? "n/a"
                            : d.percent != null
                              ? `${d.percent.toFixed(0)}%`
                              : "—"}
                        </span>
                      </div>
                      <div className={`bar ${err ? "bad" : t}`}>
                        <i
                          style={{
                            width: err
                              ? "0%"
                              : `${Math.min(100, d.percent ?? 0)}%`,
                          }}
                        />
                      </div>
                    </Link>
                  );
                })
              )}
              {disks.length > 4 ? (
                <Link to="/host" className="home-meta-link">
                  +{disks.length - 4} more
                </Link>
              ) : null}
            </div>
          </div>
          <div className="home-host-extras">
            <Link to="/host" className="home-host-extra">
              <span className="home-host-extra-label">Uptime</span>
              <span className="mono">
                {hostWaiting && uptimeSeconds == null
                  ? "…"
                  : formatUptime(uptimeSeconds)}
              </span>
            </Link>
            <Link to="/host" className="home-host-extra">
              <span className="home-host-extra-label">Speed</span>
              <span className="mono">
                {speedTest?.busy
                  ? "…"
                  : speedTest?.last?.download_mbps != null
                    ? `${speedTest.last.download_mbps.toFixed(0)}↓ / ${(speedTest.last.upload_mbps ?? 0).toFixed(0)}↑ Mbps`
                    : "—"}
              </span>
            </Link>
          </div>
        </section>
      ) : null}

      {checkChips.length > 0 ? (
        <section className="panel">
          <div className="panel-head">
            <h2>Checks</h2>
            <div className="meta">
              <Link to="/settings/checks" className="home-meta-link">
                {checksDown.length
                  ? `${checksDown.length} down`
                  : `${checkChips.length} up`}
              </Link>
            </div>
          </div>
          <div className="home-check-chips">
            {checkChips.map((c) => (
              <Link
                key={c.key}
                to={c.to}
                className={
                  c.ok === false
                    ? "chip chip-bad home-check-chip"
                    : c.ok === true
                      ? "chip chip-ok home-check-chip"
                      : "chip chip-muted home-check-chip"
                }
              >
                {c.label}
                {c.ok === false ? " down" : c.ok === true ? " up" : ""}
              </Link>
            ))}
          </div>
        </section>
      ) : null}

      {securityOn ? (
        <section className="panel">
          <div className="panel-head">
            <h2>Security</h2>
            <div className="meta">
              <Link to="/containers?scope=issues" className="home-meta-link">
                {scannedCount ? `${scannedCount} scanned` : "Scanners on"}
              </Link>
            </div>
          </div>
          <div className="home-security-row">
            <Link
              to="/containers?scope=issues"
              className={`home-metric ${
                critCount ? "home-metric-bad" : "home-metric-ok"
              }`}
            >
              <span className="home-metric-value">{critCount}</span>
              <span className="home-metric-label">Critical</span>
            </Link>
            <Link
              to="/containers?scope=issues"
              className={`home-metric ${
                highCount ? "home-metric-warn" : "home-metric-ok"
              }`}
            >
              <span className="home-metric-value">{highCount}</span>
              <span className="home-metric-label">High</span>
            </Link>
            <Link
              to="/containers?scope=issues"
              className={`home-metric ${
                securityHighs.length ? "home-metric-warn" : "home-metric-ok"
              }`}
            >
              <span className="home-metric-value">{securityHighs.length}</span>
              <span className="home-metric-label">Containers</span>
            </Link>
          </div>
        </section>
      ) : null}
    </div>
  );
}
