import { useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import type {
  DiskMetric,
  DockerDiskUsage,
  HostNetworkInterface,
  ListeningPort,
  SpeedTestInfo,
} from "../api";
import { runHostSpeedTest } from "../api";
import { DockerPruneModal } from "./DockerPruneModal";

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
  if (/unavailable/i.test(n) || /HOST_PROC|\/:\/host/i.test(n)) {
    return {
      kind: "unavailable",
      text: "Open ports unavailable without a host mount.",
    };
  }
  if (/limited|process namespace/i.test(n)) {
    return {
      kind: "limited",
      text: "Limited view — ports from this process only.",
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
  const ports = listeningPorts || [];
  const ifaces = networkInterfaces || [];
  const [pruneOpen, setPruneOpen] = useState(false);
  const [speedBusy, setSpeedBusy] = useState(false);

  const dockerAvailable = dockerDisk?.available === true;
  const dockerCats = dockerDisk?.categories || [];
  const speed = speedTest;
  const speedLast = speed?.last;
  const speedRunning = Boolean(speed?.busy) || speedBusy;
  const networkStatus = softNetworkNote(networkNote);
  const portsStatus = softPortsStatus(listeningPortsNote);

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

      {hostNote ? <div className="host-note">{hostNote}</div> : null}

      <HostSection title="Resources">
        <div className="meters">
          <Meter label="CPU" percent={cpu} collecting={waiting && cpu == null} />
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
              {waiting && uptimeSeconds == null ? "…" : formatUptime(uptimeSeconds)}
            </span>
          </div>
          <div className="host-kv">
            <span className="host-kv-label">Load avg</span>
            <span className="mono host-kv-value">{waiting && !loadAvg ? "…" : loadLabel}</span>
          </div>
        </div>
      </HostSection>

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

        <div className="docker-disk" id="docker-disk">
          <div className="meter-label">
            <span>Docker disk</span>
            <span>
              {dockerDiskLoading && !dockerDisk
                ? "loading…"
                : dockerAvailable && dockerDisk?.taken_at
                  ? `as of ${new Date(dockerDisk.taken_at).toLocaleString()}`
                  : "system df"}
            </span>
          </div>
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
            <NetworkBlock title="Open ports">
              {waiting && !ports.length && !portsStatus ? (
                <div className="empty collecting-empty">Collecting open ports…</div>
              ) : portsStatus?.kind === "unavailable" && !ports.length ? (
                <p className="network-status">
                  {portsStatus.text}{" "}
                  <Link to="/settings/host" className="home-meta-link">
                    Settings → Host
                  </Link>
                </p>
              ) : !ports.length ? (
                <p className="network-status">
                  {portsStatus?.text || "No open ports discovered."}
                  {portsStatus?.kind === "limited" ? (
                    <>
                      {" "}
                      <Link to="/settings/host" className="home-meta-link">
                        Settings → Host
                      </Link>
                    </>
                  ) : null}
                </p>
              ) : (
                <>
                  {portsStatus ? (
                    <p className="network-status">{portsStatus.text}</p>
                  ) : null}
                  <div className="table-scroll ports-table-wrap">
                    <table className="table ports-table">
                      <thead>
                        <tr>
                          <th>Port</th>
                          <th>Bind</th>
                          <th>Scope</th>
                          <th>Process</th>
                          <th>Container</th>
                        </tr>
                      </thead>
                      <tbody>
                        {ports.map((p) => {
                          const scope = p.bind_scope || "lan";
                          return (
                            <tr
                              key={`${p.protocol}:${p.address}:${p.port}:${p.pid || ""}`}
                              className={
                                scope === "all" || scope === "lan"
                                  ? "port-row-exposed"
                                  : undefined
                              }
                            >
                              <td className="mono">
                                {p.protocol}/{p.port}
                              </td>
                              <td className="mono path-cell">{p.address}</td>
                              <td>
                                <span className={`chip ${scopeChip(scope)}`}>
                                  {scopeLabel(scope)}
                                </span>
                              </td>
                              <td
                                className="mono path-cell"
                                title={p.pid != null ? `pid ${p.pid}` : undefined}
                              >
                                {p.process || (p.pid != null ? `pid ${p.pid}` : "—")}
                              </td>
                              <td className="mono path-cell">{p.container || "—"}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                  <div className="port-card-list">
                    {ports.map((p) => {
                      const scope = p.bind_scope || "lan";
                      return (
                        <div
                          key={`card-${p.protocol}:${p.address}:${p.port}:${p.pid || ""}`}
                          className={`port-card ${scope === "all" || scope === "lan" ? "exposed" : ""}`}
                        >
                          <div className="port-card-head">
                            <span className="mono">
                              {p.protocol}/{p.port}
                            </span>
                            <span className={`chip ${scopeChip(scope)}`}>
                              {scopeLabel(scope)}
                            </span>
                          </div>
                          <div className="port-card-meta mono">{p.address}</div>
                          <div className="port-card-meta">
                            {p.process || (p.pid != null ? `pid ${p.pid}` : "—")}
                            {p.container ? ` · ${p.container}` : ""}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </>
              )}
            </NetworkBlock>
          ) : null}
        </div>
      </HostSection>

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
