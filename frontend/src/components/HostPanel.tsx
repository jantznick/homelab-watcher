import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type {
  DiskMetric,
  DockerDiskUsage,
  DockerPublishedPort,
  HostNetworkInterface,
  ListeningPort,
  SpeedTestInfo,
} from "../api";
import { runHostSpeedTest } from "../api";
import { DockerPruneModal } from "./DockerPruneModal";
import { Drawer } from "./Drawer";

/** Compact Host page preview; full list lives in the ports drawer. */
const HOST_PORTS_PREVIEW_LIMIT = 5;

const HOST_TAB_STORAGE_KEY = "hlw-host-tab";

export type HostTabId = "system" | "disks" | "docker" | "network";

export const HOST_TABS: { id: HostTabId; label: string }[] = [
  { id: "system", label: "System" },
  { id: "disks", label: "Disks" },
  { id: "docker", label: "Docker" },
  { id: "network", label: "Network" },
];

const HOST_TAB_IDS = new Set<string>(HOST_TABS.map((t) => t.id));

export function isHostTabId(value: string | null | undefined): value is HostTabId {
  return Boolean(value && HOST_TAB_IDS.has(value));
}

export function readStoredHostTab(): HostTabId {
  try {
    const raw = window.localStorage.getItem(HOST_TAB_STORAGE_KEY);
    if (isHostTabId(raw)) return raw;
  } catch {
    /* ignore quota / private mode */
  }
  return "system";
}

export function writeStoredHostTab(tab: HostTabId) {
  try {
    window.localStorage.setItem(HOST_TAB_STORAGE_KEY, tab);
  } catch {
    /* ignore quota / private mode */
  }
}

/** Resolve /host, /host/:section, and legacy #docker-disk into a tab id. */
export function resolveHostTab(section: string | undefined): HostTabId {
  if (typeof window !== "undefined" && window.location.hash === "#docker-disk") {
    return "docker";
  }
  if (isHostTabId(section)) return section;
  if (!section) return readStoredHostTab();
  return "system";
}

function tone(percent: number | null | undefined, warn: number): "ok" | "warn" | "bad" {
  if (percent == null) return "ok";
  if (percent >= Math.min(95, warn + 10)) return "bad";
  if (percent >= warn) return "warn";
  return "ok";
}

function Meter({
  label,
  percent,
  detail,
  warnAt,
  collecting,
}: {
  label: string;
  percent: number | null | undefined;
  detail?: string;
  warnAt?: number;
  collecting?: boolean;
}) {
  const pct = percent ?? 0;
  const t = tone(percent, warnAt ?? 90);
  return (
    <div>
      <div className="meter-label">
        <span>{label}</span>
        <span>
          {collecting
            ? "Collecting…"
            : percent == null
              ? "—"
              : `${pct.toFixed(1)}%`}
          {!collecting && detail ? ` · ${detail}` : ""}
        </span>
      </div>
      <div className={`bar ${t}${collecting ? " collecting" : ""}`}>
        <i style={{ width: collecting ? "28%" : `${Math.min(100, pct)}%` }} />
      </div>
    </div>
  );
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

function formatMbps(n: number | null | undefined): string {
  if (n == null || Number.isNaN(n)) return "—";
  return `${n.toFixed(1)} Mbps`;
}

function isIpv4(addr: string): boolean {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(addr);
}

function splitIfaceAddresses(addresses: string[]): {
  primary: string | null;
  extra: string[];
} {
  const addrs = addresses.filter(Boolean);
  const v4 = addrs.filter(isIpv4);
  const rest = addrs.filter((a) => !isIpv4(a));
  if (v4.length) {
    return { primary: v4[0], extra: [...v4.slice(1), ...rest] };
  }
  if (rest.length) {
    return { primary: rest[0], extra: rest.slice(1) };
  }
  return { primary: null, extra: [] };
}

function softNetworkNote(note: string | null | undefined): string | null {
  if (!note) return null;
  const n = note.trim();
  if (/^Limited host view\.?$/i.test(n)) return "Limited host view";
  if (/container network/i.test(n)) return "Container network view";
  if (/unavailable/i.test(n)) return "Interfaces unavailable";
  return n;
}

function softPortsStatus(note: string | null | undefined): {
  kind: "unavailable" | "limited" | "info";
  text: string;
} | null {
  if (!note) return null;
  const n = note.trim();
  if (/unavailable|HOST_PROC|\/:\/host|PID 1|need \/:\/host/i.test(n)) {
    return {
      kind: "unavailable",
      text: n.length < 160 ? n : "Host listening ports need /:/host:ro (HOST_PROC=/host/proc).",
    };
  }
  if (/limited|container-local|process namespace|this process only/i.test(n)) {
    return {
      kind: "limited",
      text: n.length < 160 ? n : "Host listening ports unavailable — container-local view only.",
    };
  }
  return { kind: "info", text: n };
}

function scopeLabel(scope: string): string {
  if (scope === "all") return "All interfaces";
  if (scope === "lan") return "LAN / NIC";
  if (scope === "localhost") return "Localhost";
  return scope;
}

function scopeChip(scope: string): string {
  if (scope === "all" || scope === "lan") return "chip-warn";
  return "chip-muted";
}

type PortsSourceFilter = "all" | "host" | "docker";
type PortsDockerFilter = "all" | "running" | "stopped";

type UnifiedPortRow = {
  key: string;
  source: "host" | "docker";
  protocol: string;
  port: number;
  address: string;
  bind_scope: string;
  detail: string;
  container: string | null;
  container_state: string | null;
  docker_live: boolean | null;
  correlated: string | null;
  exposed: boolean;
};

function isDockerLive(state: string | null | undefined): boolean {
  const s = (state || "").toLowerCase();
  return s === "running" || s === "restarting" || s === "paused";
}

function dockerStateLabel(
  state: string | null | undefined,
  live: boolean | null | undefined,
): string {
  const s = (state || "").toLowerCase();
  if (s === "paused") return "Paused";
  if (live) return "Running";
  return "Stopped";
}

function buildUnifiedPortRows(
  hostPorts: ListeningPort[],
  dockerPorts: DockerPublishedPort[],
): UnifiedPortRow[] {
  const hostKeys = new Set(
    hostPorts.map(
      (p) => `${(p.protocol || "tcp").toLowerCase()}:${p.port}`,
    ),
  );
  // Correlate host rows with live Docker publishes only.
  const dockerByPort = new Map<string, string[]>();
  for (const d of dockerPorts) {
    if (!isDockerLive(d.container_state)) continue;
    const k = `${(d.protocol || "tcp").toLowerCase()}:${d.host_port}`;
    const name = (d.container || "").trim();
    if (!name) continue;
    const list = dockerByPort.get(k) || [];
    if (!list.includes(name)) list.push(name);
    dockerByPort.set(k, list);
  }

  const rows: UnifiedPortRow[] = [];
  for (const p of hostPorts) {
    const proto = (p.protocol || "tcp").toLowerCase();
    const scope = p.bind_scope || "lan";
    const corrList =
      p.docker_published?.length
        ? p.docker_published
        : dockerByPort.get(`${proto}:${p.port}`) || [];
    const correlated =
      corrList.length > 0 ? corrList.slice(0, 3).join(", ") : null;
    rows.push({
      key: `host:${proto}:${p.address}:${p.port}:${p.pid || ""}`,
      source: "host",
      protocol: proto,
      port: p.port,
      address: p.address,
      bind_scope: scope,
      detail: p.process || (p.pid != null ? `pid ${p.pid}` : "—"),
      container: p.container || null,
      container_state: null,
      docker_live: null,
      correlated,
      exposed: scope === "all" || scope === "lan",
    });
  }
  for (const d of dockerPorts) {
    const proto = (d.protocol || "tcp").toLowerCase();
    const scope = d.bind_scope || "lan";
    const hostKey = `${proto}:${d.host_port}`;
    const live = isDockerLive(d.container_state);
    const correlated = live && hostKeys.has(hostKey) ? "Host listener" : null;
    rows.push({
      key: `docker:${proto}:${d.host_ip}:${d.host_port}:${d.container_port}:${d.container || ""}:${d.container_state || ""}`,
      source: "docker",
      protocol: proto,
      port: d.host_port,
      address: d.host_ip || "0.0.0.0",
      bind_scope: scope,
      detail: `→ ${d.container_port}/${proto}`,
      container: d.container || null,
      container_state: d.container_state || null,
      docker_live: live,
      correlated,
      exposed: scope === "all" || scope === "lan",
    });
  }

  const scopeRank: Record<string, number> = { all: 0, lan: 1, localhost: 2 };
  rows.sort((a, b) => {
    const sa = scopeRank[a.bind_scope] ?? 9;
    const sb = scopeRank[b.bind_scope] ?? 9;
    if (sa !== sb) return sa - sb;
    if (a.port !== b.port) return a.port - b.port;
    if (a.source !== b.source) return a.source === "host" ? -1 : 1;
    return a.address.localeCompare(b.address);
  });
  return rows;
}

function filterPortRows(
  rows: UnifiedPortRow[],
  source: PortsSourceFilter,
  dockerState: PortsDockerFilter,
  search: string,
): UnifiedPortRow[] {
  const q = search.trim().toLowerCase();
  return rows.filter((r) => {
    if (source === "host" && r.source !== "host") return false;
    if (source === "docker" && r.source !== "docker") return false;
    if (r.source === "docker" && dockerState !== "all") {
      if (dockerState === "running" && !r.docker_live) return false;
      if (dockerState === "stopped" && r.docker_live) return false;
    }
    if (!q) return true;
    const hay = [
      String(r.port),
      r.protocol,
      r.address,
      r.detail,
      r.container || "",
      r.correlated || "",
      r.container_state || "",
    ]
      .join(" ")
      .toLowerCase();
    return hay.includes(q);
  });
}

function containerHref(name: string | null): string | null {
  if (!name) return null;
  return `/containers?scope=all&open=${encodeURIComponent(name)}`;
}

function PortRowTable({ rows }: { rows: UnifiedPortRow[] }) {
  return (
    <div className="table-scroll ports-table-wrap">
      <table className="table ports-table">
        <thead>
          <tr>
            <th>Source</th>
            <th>Port</th>
            <th>Bind</th>
            <th>Scope</th>
            <th>Detail</th>
            <th>Container</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => {
            const href = containerHref(r.container);
            return (
              <tr
                key={r.key}
                className={r.exposed ? "port-row-exposed" : undefined}
              >
                <td>
                  <span
                    className={
                      r.source === "docker"
                        ? "chip chip-muted port-source-chip"
                        : "chip chip-ok port-source-chip"
                    }
                  >
                    {r.source === "docker" ? "Docker" : "Host"}
                  </span>
                  {r.source === "docker" ? (
                    <span
                      className={
                        r.docker_live
                          ? "chip chip-ok port-state-chip"
                          : "chip chip-muted port-state-chip"
                      }
                    >
                      {dockerStateLabel(r.container_state, r.docker_live)}
                    </span>
                  ) : null}
                </td>
                <td className="mono">
                  {r.protocol}/{r.port}
                </td>
                <td className="mono path-cell">{r.address}</td>
                <td>
                  <span className={`chip ${scopeChip(r.bind_scope)}`}>
                    {scopeLabel(r.bind_scope)}
                  </span>
                </td>
                <td className="mono path-cell">
                  {r.detail}
                  {r.correlated ? (
                    <span className="port-corr" title="Correlated">
                      {" "}
                      · {r.correlated}
                    </span>
                  ) : null}
                </td>
                <td className="mono path-cell">
                  {href ? (
                    <Link to={href} className="home-meta-link">
                      {r.container}
                    </Link>
                  ) : (
                    r.container || "—"
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function PortCardList({ rows }: { rows: UnifiedPortRow[] }) {
  return (
    <div className="port-card-list">
      {rows.map((r) => {
        const href = containerHref(r.container);
        return (
          <div
            key={`card-${r.key}`}
            className={`port-card ${r.exposed ? "exposed" : ""}`}
          >
            <div className="port-card-head">
              <span className="mono">
                {r.protocol}/{r.port}
              </span>
              <span className="port-card-chips">
                <span
                  className={
                    r.source === "docker"
                      ? "chip chip-muted port-source-chip"
                      : "chip chip-ok port-source-chip"
                  }
                >
                  {r.source === "docker" ? "Docker" : "Host"}
                </span>
                {r.source === "docker" ? (
                  <span
                    className={
                      r.docker_live
                        ? "chip chip-ok port-state-chip"
                        : "chip chip-muted port-state-chip"
                    }
                  >
                    {dockerStateLabel(r.container_state, r.docker_live)}
                  </span>
                ) : null}
              </span>
            </div>
            <div className="port-card-meta mono">
              {r.address}
              {" · "}
              <span className={`chip ${scopeChip(r.bind_scope)}`}>
                {scopeLabel(r.bind_scope)}
              </span>
            </div>
            <div className="port-card-meta">
              {r.detail}
              {r.correlated ? ` · ${r.correlated}` : ""}
              {r.container ? (
                <>
                  {" · "}
                  {href ? (
                    <Link to={href} className="home-meta-link">
                      {r.container}
                    </Link>
                  ) : (
                    r.container
                  )}
                </>
              ) : null}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function PortsFilterBar({
  source,
  onSource,
  dockerState,
  onDockerState,
  counts,
  showDockerState,
}: {
  source: PortsSourceFilter;
  onSource: (v: PortsSourceFilter) => void;
  dockerState: PortsDockerFilter;
  onDockerState: (v: PortsDockerFilter) => void;
  counts: {
    all: number;
    host: number;
    docker: number;
    dockerRunning: number;
    dockerStopped: number;
  };
  showDockerState: boolean;
}) {
  return (
    <div className="ports-toolbar">
      <div className="ports-filter" role="tablist" aria-label="Port source">
        {(
          [
            ["all", "All", counts.all],
            ["host", "Host", counts.host],
            ["docker", "Docker", counts.docker],
          ] as const
        ).map(([id, label, count]) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={source === id}
            className={
              source === id ? "ports-filter-btn active" : "ports-filter-btn"
            }
            onClick={() => onSource(id)}
          >
            {label}
            <span className="ports-filter-count">{count}</span>
          </button>
        ))}
      </div>
      {showDockerState ? (
        <div className="ports-filter" role="tablist" aria-label="Docker state">
          {(
            [
              ["all", "All", counts.docker],
              ["running", "Running", counts.dockerRunning],
              ["stopped", "Stopped", counts.dockerStopped],
            ] as const
          ).map(([id, label, count]) => (
            <button
              key={id}
              type="button"
              role="tab"
              aria-selected={dockerState === id}
              className={
                dockerState === id
                  ? "ports-filter-btn active"
                  : "ports-filter-btn"
              }
              onClick={() => onDockerState(id)}
            >
              {label}
              <span className="ports-filter-count">{count}</span>
            </button>
          ))}
        </div>
      ) : null}
    </div>
  );
}

function HostSection({
  title,
  meta,
  children,
}: {
  title: string;
  meta?: string | null;
  children: ReactNode;
}) {
  return (
    <div className="host-section">
      <div className="host-section-head">
        <h3 className="host-section-title">{title}</h3>
        {meta ? <p className="host-section-meta">{meta}</p> : null}
      </div>
      {children}
    </div>
  );
}

function NetworkBlock({
  title,
  meta,
  children,
}: {
  title: string;
  meta?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="network-block">
      <div className="network-block-head">
        <h4 className="network-block-title">{title}</h4>
        {meta ? <div className="network-block-meta">{meta}</div> : null}
      </div>
      {children}
    </div>
  );
}

function IfaceRow({ iface }: { iface: HostNetworkInterface }) {
  const [open, setOpen] = useState(false);
  const { primary, extra } = splitIfaceAddresses(iface.addresses || []);
  return (
    <div className="host-iface-row">
      <div className="host-iface-main">
        <span className="host-iface-name">{iface.name}</span>
        <span className="mono host-iface-primary">{primary || "—"}</span>
      </div>
      {extra.length ? (
        <div className="host-iface-extra">
          <button
            type="button"
            className="host-iface-toggle"
            aria-expanded={open}
            onClick={() => setOpen((v) => !v)}
          >
            {open ? "Hide addresses" : `${extra.length} more`}
          </button>
          {open ? (
            <ul className="host-iface-extra-list">
              {extra.map((addr) => (
                <li key={addr} className="mono">
                  {addr}
                </li>
              ))}
            </ul>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

export function HostPanel({
  tab,
  onTabChange,
  cpu,
  mem,
  memUsed,
  memTotal,
  disks,
  warn,
  takenAt,
  hostNote,
  diskSource,
  collecting,
  diskSelectionNeeded,
  onOpenDiskSettings,
  listeningPorts,
  listeningPortsEnabled,
  listeningPortsNote,
  listeningPortsSource,
  dockerPublishedPorts,
  dockerPublishedNote,
  dockerDisk,
  dockerDiskLoading,
  actionsEnabled,
  onDockerDiskRefresh,
  uptimeSeconds,
  loadAvg,
  networkInterfaces,
  networkNote,
  speedTest,
  onSpeedTestChange,
}: {
  tab: HostTabId;
  onTabChange: (tab: HostTabId) => void;
  cpu: number | null;
  mem: number | null;
  memUsed: number | null;
  memTotal: number | null;
  disks: DiskMetric[];
  warn: number;
  takenAt: string | null;
  hostNote?: string | null;
  diskSource?: string | null;
  collecting?: boolean;
  diskSelectionNeeded?: boolean | null;
  onOpenDiskSettings?: () => void;
  listeningPorts?: ListeningPort[];
  listeningPortsEnabled?: boolean | null;
  listeningPortsNote?: string | null;
  listeningPortsSource?: string | null;
  dockerPublishedPorts?: DockerPublishedPort[];
  dockerPublishedNote?: string | null;
  dockerDisk?: DockerDiskUsage | null;
  dockerDiskLoading?: boolean;
  actionsEnabled?: boolean;
  onDockerDiskRefresh?: () => void;
  uptimeSeconds?: number | null;
  loadAvg?: number[] | null;
  networkInterfaces?: HostNetworkInterface[];
  networkNote?: string | null;
  networkSource?: string | null;
  speedTest?: SpeedTestInfo | null;
  onSpeedTestChange?: () => void;
}) {
  const waiting = collecting || !takenAt;
  const needsDiskPick = Boolean(diskSelectionNeeded) || (!waiting && !disks?.length);
  const portsOn = listeningPortsEnabled !== false;
  const hostPorts = listeningPorts || [];
  const dockerPorts = dockerPublishedPorts || [];
  const ifaces = networkInterfaces || [];
  const [pruneOpen, setPruneOpen] = useState(false);
  const [speedBusy, setSpeedBusy] = useState(false);
  const [portsFilter, setPortsFilter] = useState<PortsSourceFilter>("all");
  const [portsDockerFilter, setPortsDockerFilter] =
    useState<PortsDockerFilter>("all");
  const [portsDrawerOpen, setPortsDrawerOpen] = useState(false);
  const [portsSearch, setPortsSearch] = useState("");

  const unifiedPorts = useMemo(
    () => buildUnifiedPortRows(hostPorts, dockerPorts),
    [hostPorts, dockerPorts],
  );
  const dockerRunningCount = useMemo(
    () => unifiedPorts.filter((r) => r.source === "docker" && r.docker_live).length,
    [unifiedPorts],
  );
  const dockerStoppedCount = useMemo(
    () =>
      unifiedPorts.filter((r) => r.source === "docker" && !r.docker_live).length,
    [unifiedPorts],
  );
  const portCounts = useMemo(
    () => ({
      all: unifiedPorts.length,
      host: hostPorts.length,
      docker: dockerPorts.length,
      dockerRunning: dockerRunningCount,
      dockerStopped: dockerStoppedCount,
    }),
    [
      unifiedPorts.length,
      hostPorts.length,
      dockerPorts.length,
      dockerRunningCount,
      dockerStoppedCount,
    ],
  );
  const filteredPorts = useMemo(
    () => filterPortRows(unifiedPorts, portsFilter, portsDockerFilter, ""),
    [unifiedPorts, portsFilter, portsDockerFilter],
  );
  const hostPortsPreview = useMemo(
    () => filteredPorts.slice(0, HOST_PORTS_PREVIEW_LIMIT),
    [filteredPorts],
  );
  const drawerPorts = useMemo(
    () =>
      filterPortRows(
        unifiedPorts,
        portsFilter,
        portsDockerFilter,
        portsSearch,
      ),
    [unifiedPorts, portsFilter, portsDockerFilter, portsSearch],
  );
  const showDockerStateFilter =
    portsFilter === "docker" || portsFilter === "all";

  useEffect(() => {
    const selected = document.querySelector<HTMLElement>(
      '.host-tabs-rail [role="tab"][aria-selected="true"]',
    );
    selected?.scrollIntoView({
      behavior: "smooth",
      inline: "nearest",
      block: "nearest",
    });
  }, [tab]);

  const dockerAvailable = dockerDisk?.available === true;
  const dockerCats = dockerDisk?.categories || [];
  const speed = speedTest;
  const speedLast = speed?.last;
  const speedRunning = Boolean(speed?.busy) || speedBusy;
  const networkStatus = softNetworkNote(networkNote);
  const portsStatus = softPortsStatus(listeningPortsNote);
  const hostPortsOk = listeningPortsSource === "host_proc";
  const hostPortsMissing = portsOn && !hostPorts.length && Boolean(portsStatus);
  const portsMeta =
    dockerPorts.length > 0
      ? `${unifiedPorts.length} total · ${hostPorts.length} host · ${dockerPorts.length} docker (${dockerRunningCount} run · ${dockerStoppedCount} stopped)`
      : `${hostPorts.length} host · ${dockerPorts.length} docker`;

  async function onRunSpeed() {
    setSpeedBusy(true);
    try {
      await runHostSpeedTest();
      onSpeedTestChange?.();
    } catch {
      /* refresh will surface state */
    } finally {
      setSpeedBusy(false);
      onSpeedTestChange?.();
    }
  }

  const loadLabel =
    loadAvg && loadAvg.length >= 3
      ? `${loadAvg[0].toFixed(2)} · ${loadAvg[1].toFixed(2)} · ${loadAvg[2].toFixed(2)}`
      : "—";

  const speedMeta = speedRunning
    ? "Running…"
    : speedLast?.taken_at
      ? `Last run ${new Date(speedLast.taken_at).toLocaleString()}`
      : "Not run yet";

  return (
    <section className="panel">
      <div className="panel-head">
        <h2>Host</h2>
        <div className="meta">
          {waiting
            ? "Collecting first snapshot…"
            : `polled ${new Date(takenAt!).toLocaleString()}`}
          {!waiting && diskSource === "host" ? " · host df" : null}
          {!waiting && diskSource === "local" ? " · local view" : null}
        </div>
      </div>

      <div className="host-tabs-rail scope-tabs-rail">
        <div className="scope-tabs" role="tablist" aria-label="Host sections">
          {HOST_TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              role="tab"
              aria-selected={tab === t.id}
              className={tab === t.id ? "scope-tab active" : "scope-tab"}
              onClick={() => onTabChange(t.id)}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {hostNote ? <div className="host-note">{hostNote}</div> : null}

      {tab === "system" ? (
        <>
          <HostSection title="Resources">
            <div className="meters">
              <Meter
                label="CPU"
                percent={cpu}
                collecting={waiting && cpu == null}
              />
              <Meter
                label="Memory"
                percent={mem}
                detail={`${formatBytes(memUsed)} / ${formatBytes(memTotal)}`}
                warnAt={90}
                collecting={waiting && mem == null}
              />
            </div>
          </HostSection>

          <HostSection title="System">
            <div className="host-kv-grid">
              <div className="host-kv">
                <span className="host-kv-label">Uptime</span>
                <span className="mono host-kv-value">
                  {waiting && uptimeSeconds == null
                    ? "…"
                    : formatUptime(uptimeSeconds)}
                </span>
              </div>
              <div className="host-kv">
                <span className="host-kv-label">Load avg</span>
                <span className="mono host-kv-value">
                  {waiting && !loadAvg ? "…" : loadLabel}
                </span>
              </div>
            </div>
          </HostSection>
        </>
      ) : null}

      {tab === "disks" ? (
        <HostSection title="Disks" meta={`warn ≥ ${warn}%`}>
        {waiting && !disks?.length && !diskSelectionNeeded ? (
          <div className="empty collecting-empty">Collecting disk usage…</div>
        ) : needsDiskPick ? (
          <div className="empty-cta">
            {onOpenDiskSettings ? (
              <button type="button" className="btn btn-primary" onClick={onOpenDiskSettings}>
                Choose disks in Settings
              </button>
            ) : (
              "Choose disks in Settings"
            )}
          </div>
        ) : !disks?.length ? (
          <div className="empty">No filesystems discovered yet.</div>
        ) : (
          <div className="table-scroll">
            <table className="table disk-table">
              <thead>
                <tr>
                  <th>Filesystem</th>
                  <th>Size</th>
                  <th>Used</th>
                  <th>Avail</th>
                  <th>Use%</th>
                  <th>Mounted on</th>
                </tr>
              </thead>
              <tbody>
                {disks.map((d) => {
                  const mount = d.mountpoint || d.path;
                  const pct = d.percent;
                  const t = tone(pct, warn);
                  const err = d.error || d.mounted === false;
                  return (
                    <tr key={`${d.filesystem || ""}:${mount}`}>
                      <td className="mono" title={d.fstype || undefined}>
                        {d.filesystem || "—"}
                      </td>
                      <td className="mono">{err ? "—" : formatBytes(d.total_bytes)}</td>
                      <td className="mono">{err ? "—" : formatBytes(d.used_bytes)}</td>
                      <td className="mono">{err ? "—" : formatBytes(d.free_bytes)}</td>
                      <td>
                        {err ? (
                          <span className="chip chip-bad" title={d.error || "unavailable"}>
                            n/a
                          </span>
                        ) : (
                          <span className={`chip chip-${t === "ok" ? "ok" : t === "warn" ? "warn" : "bad"}`}>
                            {pct != null ? `${pct.toFixed(0)}%` : "—"}
                          </span>
                        )}
                      </td>
                      <td className="mono path-cell">{mount}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
        </HostSection>
      ) : null}

      {tab === "docker" ? (
        <HostSection
          title="Docker disk"
          meta={
            dockerDiskLoading && !dockerDisk
              ? "loading…"
              : dockerAvailable && dockerDisk?.taken_at
                ? `as of ${new Date(dockerDisk.taken_at).toLocaleString()}`
                : "system df"
          }
        >
          <div className="docker-disk" id="docker-disk">
            {!dockerDisk && dockerDiskLoading ? (
              <div className="empty collecting-empty">Reading Docker disk usage…</div>
            ) : !dockerAvailable ? (
              <div className="empty">
                {dockerDisk?.error || "Docker disk usage unavailable."}
              </div>
            ) : (
              <>
                <p className="host-note docker-disk-note">
                  Space used by images, containers, volumes, and build cache.
                  Reclaimable is unused data Docker can delete. Unused volumes are
                  risky — they may hold data with no container attached.
                </p>
                <div className="table-scroll">
                  <table className="table disk-table">
                    <thead>
                      <tr>
                        <th>Type</th>
                        <th>Total</th>
                        <th>Active</th>
                        <th>Size</th>
                        <th>Reclaimable</th>
                      </tr>
                    </thead>
                    <tbody>
                      {dockerCats.map((c) => (
                        <tr key={c.type}>
                          <td>{c.label || c.type}</td>
                          <td className="mono">{c.total_count}</td>
                          <td className="mono">{c.active_count}</td>
                          <td className="mono">{formatBytes(c.size_bytes)}</td>
                          <td className="mono">
                            {formatBytes(c.reclaimable_bytes)}
                            {c.reclaimable_percent != null && c.size_bytes > 0
                              ? ` (${c.reclaimable_percent.toFixed(0)}%)`
                              : ""}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="docker-disk-footer">
                  <span className="meta">
                    Total {formatBytes(dockerDisk?.total_bytes)} · reclaimable{" "}
                    {formatBytes(dockerDisk?.reclaimable_bytes)}
                  </span>
                  {actionsEnabled ? (
                    <button
                      type="button"
                      className="btn btn-primary"
                      onClick={() => setPruneOpen(true)}
                    >
                      Reclaim…
                    </button>
                  ) : (
                    <span className="quiet">Enable container actions to reclaim</span>
                  )}
                </div>
              </>
            )}
          </div>
        </HostSection>
      ) : null}

      {tab === "network" ? (
        <HostSection title="Network">
        <div className="network-area">
          <NetworkBlock title="Interfaces">
            {networkStatus ? (
              <p className="network-status">{networkStatus}</p>
            ) : null}
            {ifaces.length ? (
              <div className="host-iface-list">
                {ifaces.map((iface) => (
                  <IfaceRow key={iface.name} iface={iface} />
                ))}
              </div>
            ) : (
              <div className="empty">
                {waiting ? "Collecting interfaces…" : "No interfaces to show."}
              </div>
            )}
          </NetworkBlock>

          <NetworkBlock title="Speed" meta={speedMeta}>
            <div className="host-speed-metrics">
              <div className="host-speed-stat">
                <span className="host-kv-label">Down</span>
                <span className="mono host-speed-value">
                  {speedRunning ? "…" : formatMbps(speedLast?.download_mbps)}
                </span>
              </div>
              <div className="host-speed-stat">
                <span className="host-kv-label">Up</span>
                <span className="mono host-speed-value">
                  {speedRunning ? "…" : formatMbps(speedLast?.upload_mbps)}
                </span>
              </div>
              <div className="host-speed-stat">
                <span className="host-kv-label">Ping</span>
                <span className="mono host-speed-value">
                  {speedRunning
                    ? "…"
                    : speedLast?.ping_ms != null
                      ? `${speedLast.ping_ms.toFixed(0)} ms`
                      : "—"}
                </span>
              </div>
            </div>
            {speedLast?.error && !speedRunning ? (
              <p className="network-status network-status-error">{speedLast.error}</p>
            ) : null}
            <div className="host-speed-actions">
              <button
                type="button"
                className="btn"
                disabled={speedRunning}
                onClick={() => void onRunSpeed()}
              >
                {speedRunning ? "Running…" : "Run now"}
              </button>
            </div>
          </NetworkBlock>

          {portsOn ? (
            <NetworkBlock title="Open ports" meta={portsMeta}>
              <PortsFilterBar
                source={portsFilter}
                onSource={setPortsFilter}
                dockerState={portsDockerFilter}
                onDockerState={setPortsDockerFilter}
                counts={portCounts}
                showDockerState={showDockerStateFilter}
              />

              {waiting && !unifiedPorts.length && !portsStatus ? (
                <div className="empty collecting-empty">Collecting open ports…</div>
              ) : (
                <>
                  {portsFilter !== "docker" && hostPortsMissing ? (
                    <p className="network-status">
                      {portsStatus?.text || "Host listening ports unavailable."}{" "}
                      <Link to="/settings/host" className="home-meta-link">
                        Settings → Host
                      </Link>
                    </p>
                  ) : null}
                  {portsFilter !== "docker" && hostPortsOk && portsStatus?.kind === "info" ? (
                    <p className="network-status">{portsStatus.text}</p>
                  ) : null}
                  {dockerPublishedNote && portsFilter !== "host" ? (
                    <p className="network-status">{dockerPublishedNote}</p>
                  ) : null}

                  {!filteredPorts.length ? (
                    (() => {
                      if (portsFilter === "host" && hostPortsMissing) return null;
                      if (portsFilter === "all" && hostPortsMissing && !dockerPorts.length) {
                        return null;
                      }
                      const emptyText =
                        portsFilter === "host"
                          ? "No host listeners discovered."
                          : portsFilter === "docker"
                            ? portsDockerFilter === "running"
                              ? "No running Docker published ports."
                              : portsDockerFilter === "stopped"
                                ? "No stopped Docker published ports."
                                : "No Docker published host ports."
                            : "No open ports to show.";
                      return <p className="network-status">{emptyText}</p>;
                    })()
                  ) : (
                    <>
                      <PortRowTable rows={hostPortsPreview} />
                      <PortCardList rows={hostPortsPreview} />
                      {filteredPorts.length > HOST_PORTS_PREVIEW_LIMIT ? (
                        <button
                          type="button"
                          className="btn btn-sm ports-open-panel"
                          onClick={() => setPortsDrawerOpen(true)}
                        >
                          View all ports
                        </button>
                      ) : null}
                    </>
                  )}
                </>
              )}
            </NetworkBlock>
          ) : null}
        </div>
      </HostSection>
      ) : null}

      <Drawer
        open={portsDrawerOpen}
        title="Open ports"
        onClose={() => {
          setPortsDrawerOpen(false);
          setPortsSearch("");
        }}
      >
        <p className="ports-drawer-meta">{portsMeta}</p>
        <input
          className="container-search"
          type="search"
          placeholder="Search port or container…"
          value={portsSearch}
          onChange={(e) => setPortsSearch(e.target.value)}
          aria-label="Search ports"
        />
        <PortsFilterBar
          source={portsFilter}
          onSource={setPortsFilter}
          dockerState={portsDockerFilter}
          onDockerState={setPortsDockerFilter}
          counts={portCounts}
          showDockerState={showDockerStateFilter}
        />
        {!drawerPorts.length ? (
          <p className="network-status">No ports match these filters.</p>
        ) : (
          <div className="ports-drawer-list">
            {drawerPorts.map((r) => {
              const href = containerHref(r.container);
              return (
                <div
                  key={`drawer-${r.key}`}
                  className={`port-card ${r.exposed ? "exposed" : ""}`}
                >
                  <div className="port-card-head">
                    <span className="mono">
                      {r.protocol}/{r.port}
                    </span>
                    <span className="port-card-chips">
                      <span
                        className={
                          r.source === "docker"
                            ? "chip chip-muted port-source-chip"
                            : "chip chip-ok port-source-chip"
                        }
                      >
                        {r.source === "docker" ? "Docker" : "Host"}
                      </span>
                      {r.source === "docker" ? (
                        <span
                          className={
                            r.docker_live
                              ? "chip chip-ok port-state-chip"
                              : "chip chip-muted port-state-chip"
                          }
                        >
                          {dockerStateLabel(r.container_state, r.docker_live)}
                        </span>
                      ) : null}
                    </span>
                  </div>
                  <div className="port-card-meta mono">
                    {r.address}
                    {" · "}
                    <span className={`chip ${scopeChip(r.bind_scope)}`}>
                      {scopeLabel(r.bind_scope)}
                    </span>
                    {" · "}
                    {r.detail}
                  </div>
                  <div className="port-card-meta">
                    {r.correlated ? `${r.correlated} · ` : ""}
                    {r.container ? (
                      href ? (
                        <Link
                          to={href}
                          className="home-meta-link"
                          onClick={() => setPortsDrawerOpen(false)}
                        >
                          {r.container}
                        </Link>
                      ) : (
                        r.container
                      )
                    ) : (
                      "—"
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </Drawer>

      <DockerPruneModal
        open={pruneOpen}
        onClose={() => setPruneOpen(false)}
        onDone={() => {
          onDockerDiskRefresh?.();
        }}
      />
    </section>
  );
}
