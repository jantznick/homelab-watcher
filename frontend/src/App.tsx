import { useCallback, useEffect, useRef, useState } from "react";
import {
  NavLink,
  Navigate,
  Route,
  Routes,
  useLocation,
  useNavigate,
  useParams,
} from "react-router-dom";
import {
  fetchChecks,
  fetchContainers,
  fetchDockerDf,
  fetchHost,
  fetchStatus,
  triggerPoll,
  type CheckItem,
  type ContainerItem,
  type DiskMetric,
  type DockerDiskUsage,
  type DockerPublishedPort,
  type HostNetworkInterface,
  type ListeningPort,
  type PiHoleStatus,
  type SpeedTestInfo,
  type StatusPayload,
} from "./api";
import { ChecksPanel } from "./components/ChecksPanel";
import { ContainersPanel } from "./components/ContainersPanel";
import { DnsPanel } from "./components/DnsPanel";
import { HomePanel } from "./components/HomePanel";
import {
  HOST_TABS,
  HostPanel,
  isHostTabId,
  resolveHostTab,
  writeStoredHostTab,
  type HostTabId,
} from "./components/HostPanel";
import { SettingsPanel } from "./components/SettingsPanel";

const SIDEBAR_COLLAPSED_KEY = "hlw-sidebar-collapsed";

type NavIcon = "home" | "containers" | "dns" | "host" | "settings";

type NavItem = { to: string; label: string; icon: NavIcon; end?: boolean };

const PRIMARY_NAV: NavItem[] = [
  { to: "/", label: "Home", icon: "home", end: true },
  { to: "/containers", label: "Containers", icon: "containers" },
  { to: "/dns", label: "DNS", icon: "dns" },
];

const HOST_NAV: NavItem = { to: "/host", label: "Host", icon: "host" };

const SETTINGS_NAV: NavItem = {
  to: "/settings",
  label: "Settings",
  icon: "settings",
};

/** Mobile bottom nav — DNS stays sidebar/deep-link only (no 5th tab). */
const MOBILE_NAV: NavItem[] = [
  { to: "/", label: "Home", icon: "home", end: true },
  { to: "/containers", label: "Containers", icon: "containers" },
  HOST_NAV,
  SETTINGS_NAV,
];

function NavGlyph({ name }: { name: NavIcon }) {
  const common = {
    className: "nav-link-icon",
    width: 18,
    height: 18,
    viewBox: "0 0 24 24",
    fill: "none",
    stroke: "currentColor",
    strokeWidth: 1.75,
    strokeLinecap: "round" as const,
    strokeLinejoin: "round" as const,
    "aria-hidden": true as const,
  };
  switch (name) {
    case "home":
      return (
        <svg {...common}>
          <path d="M4 10.5 12 4l8 6.5V20a1 1 0 0 1-1 1h-5v-6H10v6H5a1 1 0 0 1-1-1v-9.5z" />
        </svg>
      );
    case "containers":
      return (
        <svg {...common}>
          <rect x="3.5" y="7" width="17" height="12" rx="1.5" />
          <path d="M3.5 11h17M8 7V5.5A1.5 1.5 0 0 1 9.5 4h5A1.5 1.5 0 0 1 16 5.5V7" />
        </svg>
      );
    case "dns":
      return (
        <svg {...common}>
          <circle cx="12" cy="12" r="8.25" />
          <path d="M3.75 12h16.5M12 3.75c2.4 2.6 3.6 5.4 3.6 8.25S14.4 17.65 12 20.25C9.6 17.65 8.4 14.85 8.4 12S9.6 6.35 12 3.75z" />
        </svg>
      );
    case "host":
      return (
        <svg {...common}>
          <rect x="3" y="4" width="18" height="6" rx="1.5" />
          <rect x="3" y="14" width="18" height="6" rx="1.5" />
          <circle cx="7" cy="7" r="1" fill="currentColor" stroke="none" />
          <circle cx="7" cy="17" r="1" fill="currentColor" stroke="none" />
        </svg>
      );
    case "settings":
      return (
        <svg {...common}>
          <path d="M4 8h8M16 8h4M4 16h4M12 16h8" />
          <circle cx="14" cy="8" r="2.25" />
          <circle cx="10" cy="16" r="2.25" />
        </svg>
      );
  }
}

function readSidebarCollapsed(): boolean {
  try {
    return window.localStorage.getItem(SIDEBAR_COLLAPSED_KEY) === "1";
  } catch {
    return false;
  }
}

function HostSidebarNav({ collapsed }: { collapsed: boolean }) {
  const location = useLocation();
  const hostActive =
    location.pathname === "/host" || location.pathname.startsWith("/host/");

  return (
    <div
      className={
        hostActive ? "nav-group nav-group-host active" : "nav-group nav-group-host"
      }
    >
      <NavLink
        to="/host"
        title={collapsed ? "Host" : undefined}
        aria-label={collapsed ? "Host" : undefined}
        aria-haspopup={collapsed ? "true" : undefined}
        className={({ isActive }) =>
          isActive ? "nav-link active" : "nav-link"
        }
      >
        <NavGlyph name="host" />
        <span className="nav-link-label">Host</span>
      </NavLink>
      <div className="nav-sub" role="group" aria-label="Host sections">
        {HOST_TABS.map((t) => (
          <NavLink
            key={t.id}
            to={`/host/${t.id}`}
            title={collapsed ? t.label : undefined}
            className={({ isActive }) =>
              isActive ? "nav-link nav-sub-link active" : "nav-link nav-sub-link"
            }
          >
            <span className="nav-link-label">{t.label}</span>
          </NavLink>
        ))}
      </div>
    </div>
  );
}

function SettingsRoute({ onSaved }: { onSaved: () => void }) {
  const { section } = useParams();
  const navigate = useNavigate();
  return (
    <SettingsPanel
      open
      asPage
      initialTab={section || null}
      onClose={() => navigate("/")}
      onSaved={onSaved}
    />
  );
}

function HostRoute(props: {
  cpu: number | null;
  mem: number | null;
  memUsed: number | null;
  memTotal: number | null;
  disks: DiskMetric[];
  warn: number;
  takenAt: string | null;
  hostNote: string | null;
  diskSource: string | null;
  collecting: boolean;
  diskSelectionNeeded: boolean | null;
  listeningPorts: ListeningPort[];
  listeningPortsEnabled: boolean | null;
  listeningPortsNote: string | null;
  listeningPortsSource: string | null;
  dockerPublishedPorts: DockerPublishedPort[];
  dockerPublishedNote: string | null;
  dockerDisk: DockerDiskUsage | null;
  dockerDiskLoading: boolean;
  actionsEnabled: boolean;
  onDockerDiskRefresh: () => void;
  uptimeSeconds: number | null;
  loadAvg: number[] | null;
  networkInterfaces: HostNetworkInterface[];
  networkNote: string | null;
  networkSource: string | null;
  speedTest: SpeedTestInfo | null;
  onSpeedTestChange: () => void;
}) {
  const { section } = useParams();
  const navigate = useNavigate();
  const tab = resolveHostTab(section);

  useEffect(() => {
    const target = resolveHostTab(section);
    const needsNormalize =
      !isHostTabId(section) || window.location.hash === "#docker-disk";
    if (needsNormalize) {
      navigate(`/host/${target}`, { replace: true });
    }
    writeStoredHostTab(target);
  }, [section, navigate]);

  function onTabChange(next: HostTabId) {
    writeStoredHostTab(next);
    navigate(`/host/${next}`);
  }

  return (
    <HostPanel
      {...props}
      tab={tab}
      onTabChange={onTabChange}
      onOpenDiskSettings={() => navigate("/settings/disks")}
    />
  );
}

export default function App() {
  const [containers, setContainers] = useState<ContainerItem[]>([]);
  const [containersAt, setContainersAt] = useState<string | null>(null);
  const [pihole, setPihole] = useState<PiHoleStatus | null>(null);
  const [actionsEnabled, setActionsEnabled] = useState(true);
  const [dockerError, setDockerError] = useState<string | null>(null);
  const [dockerAvailable, setDockerAvailable] = useState<boolean | null>(null);
  const [cpu, setCpu] = useState<number | null>(null);
  const [mem, setMem] = useState<number | null>(null);
  const [memUsed, setMemUsed] = useState<number | null>(null);
  const [memTotal, setMemTotal] = useState<number | null>(null);
  const [disks, setDisks] = useState<DiskMetric[]>([]);
  const [warn, setWarn] = useState(85);
  const [hostAt, setHostAt] = useState<string | null>(null);
  const [hostNote, setHostNote] = useState<string | null>(null);
  const [diskSource, setDiskSource] = useState<string | null>(null);
  const [diskSelectionNeeded, setDiskSelectionNeeded] = useState<boolean | null>(
    null,
  );
  const [listeningPorts, setListeningPorts] = useState<ListeningPort[]>([]);
  const [listeningPortsEnabled, setListeningPortsEnabled] = useState<
    boolean | null
  >(null);
  const [listeningPortsNote, setListeningPortsNote] = useState<string | null>(
    null,
  );
  const [listeningPortsSource, setListeningPortsSource] = useState<string | null>(
    null,
  );
  const [dockerPublishedPorts, setDockerPublishedPorts] = useState<
    DockerPublishedPort[]
  >([]);
  const [dockerPublishedNote, setDockerPublishedNote] = useState<string | null>(
    null,
  );
  const [uptimeSeconds, setUptimeSeconds] = useState<number | null>(null);
  const [loadAvg, setLoadAvg] = useState<number[] | null>(null);
  const [networkInterfaces, setNetworkInterfaces] = useState<
    HostNetworkInterface[]
  >([]);
  const [networkNote, setNetworkNote] = useState<string | null>(null);
  const [networkSource, setNetworkSource] = useState<string | null>(null);
  const [speedTest, setSpeedTest] = useState<SpeedTestInfo | null>(null);
  const [dockerDisk, setDockerDisk] = useState<DockerDiskUsage | null>(null);
  const [dockerDiskLoading, setDockerDiskLoading] = useState(true);
  const [hostCollecting, setHostCollecting] = useState(true);
  const [checks, setChecks] = useState<CheckItem[]>([]);
  const [checksAt, setChecksAt] = useState<string | null>(null);
  const [checksSource, setChecksSource] = useState<string | null>(null);
  const [status, setStatus] = useState<StatusPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(readSidebarCollapsed);
  const kickedPoll = useRef(false);

  function toggleSidebarCollapsed() {
    setSidebarCollapsed((prev) => {
      const next = !prev;
      try {
        window.localStorage.setItem(SIDEBAR_COLLAPSED_KEY, next ? "1" : "0");
      } catch {
        /* ignore quota / private mode */
      }
      return next;
    });
  }

  const refresh = useCallback(async () => {
    try {
      const [c, h, checksRes, s, df] = await Promise.all([
        fetchContainers(),
        fetchHost(),
        fetchChecks(),
        fetchStatus(),
        fetchDockerDf().catch(() => null),
      ]);
      setContainers(c.items);
      setContainersAt(c.taken_at);
      setPihole(c.pihole ?? null);
      setActionsEnabled(c.actions_enabled !== false);
      setDockerError(c.docker_error ?? s.poll.docker_error ?? null);
      setDockerAvailable(
        c.docker_available ?? s.poll.docker_available ?? null,
      );
      if (df) {
        setDockerDisk(df);
        setDockerDiskLoading(false);
      } else {
        setDockerDiskLoading(false);
      }
      const hasHost = Boolean(h.taken_at) && h.metrics !== null;
      if (
        hasHost ||
        h.cpu_percent != null ||
        h.mem_percent != null ||
        (h.disks && h.disks.length) ||
        h.disk_selection_needed
      ) {
        setCpu(h.cpu_percent ?? null);
        setMem(h.mem_percent ?? null);
        setMemUsed(h.mem_used_bytes ?? null);
        setMemTotal(h.mem_total_bytes ?? null);
        setDisks(h.disks || []);
        setWarn(h.disk_warn_percent ?? 85);
        setHostAt(h.taken_at ?? null);
        setHostNote(h.host_note ?? null);
        setDiskSource(h.disk_source ?? null);
        setDiskSelectionNeeded(Boolean(h.disk_selection_needed));
        setListeningPorts(h.listening_ports || []);
        setListeningPortsEnabled(
          h.listening_ports_enabled == null ? true : Boolean(h.listening_ports_enabled),
        );
        setListeningPortsNote(h.listening_ports_note ?? null);
        setListeningPortsSource(h.listening_ports_source ?? null);
        setDockerPublishedPorts(h.docker_published_ports || []);
        setDockerPublishedNote(h.docker_published_ports_note ?? null);
        setUptimeSeconds(
          typeof h.uptime_seconds === "number" ? h.uptime_seconds : null,
        );
        setLoadAvg(Array.isArray(h.load_avg) ? h.load_avg : null);
        setNetworkInterfaces(h.network_interfaces || []);
        setNetworkNote(h.network_note ?? null);
        setNetworkSource(h.network_source ?? null);
        setSpeedTest(h.speed_test ?? null);
        if (h.taken_at) setHostCollecting(false);
      } else if (h.speed_test) {
        setSpeedTest(h.speed_test);
      }
      setChecks(checksRes.items);
      setChecksAt(checksRes.taken_at);
      setChecksSource(checksRes.config_source ?? null);
      setStatus(s);
      setError(null);

      if (!kickedPoll.current && !s.poll.last_poll_at) {
        kickedPoll.current = true;
        void triggerPoll()
          .then(() => refresh())
          .catch(() => {
            /* poll may already be running */
          });
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  const refreshDockerDisk = useCallback(async () => {
    try {
      const df = await fetchDockerDf();
      setDockerDisk(df);
    } catch {
      /* leave previous snapshot */
    } finally {
      setDockerDiskLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
    const id = window.setInterval(() => void refresh(), 15000);
    return () => window.clearInterval(id);
  }, [refresh]);

  const banner =
    error ||
    status?.poll.last_poll_error ||
    (dockerError && !containers.length ? dockerError : null);

  function renderNav(
    items: NavItem[],
    ariaLabel: string,
    className: string,
    opts?: { iconOnly?: boolean; id?: string },
  ) {
    const iconOnly = Boolean(opts?.iconOnly);
    return (
      <nav className={className} aria-label={ariaLabel} id={opts?.id}>
        {items.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            title={iconOnly ? item.label : undefined}
            aria-label={iconOnly ? item.label : undefined}
            className={({ isActive }) =>
              isActive ? "nav-link active" : "nav-link"
            }
          >
            <NavGlyph name={item.icon} />
            <span className="nav-link-label">{item.label}</span>
          </NavLink>
        ))}
      </nav>
    );
  }

  return (
    <div
      className={
        sidebarCollapsed ? "app-shell sidebar-collapsed" : "app-shell"
      }
    >
      <aside className="sidebar" aria-label="Sidebar">
        <div className="sidebar-top">
          <div className="sidebar-brand">
            <p className="sidebar-mark">Homelab</p>
            <h1 className="sidebar-title">Watcher</h1>
            <span className="sidebar-brand-compact" aria-hidden="true">
              W
            </span>
          </div>
          <button
            type="button"
            className="sidebar-toggle"
            onClick={toggleSidebarCollapsed}
            aria-expanded={!sidebarCollapsed}
            aria-controls="sidebar-nav"
            title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
            aria-label={
              sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"
            }
          >
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.75"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              {sidebarCollapsed ? (
                <>
                  <path d="M6 17l5-5-5-5" />
                  <path d="M13 17l5-5-5-5" />
                </>
              ) : (
                <>
                  <path d="M11 17l-5-5 5-5" />
                  <path d="M18 17l-5-5 5-5" />
                </>
              )}
            </svg>
          </button>
        </div>
        <nav className="sidebar-nav" aria-label="Main" id="sidebar-nav">
          {PRIMARY_NAV.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              title={sidebarCollapsed ? item.label : undefined}
              aria-label={sidebarCollapsed ? item.label : undefined}
              className={({ isActive }) =>
                isActive ? "nav-link active" : "nav-link"
              }
            >
              <NavGlyph name={item.icon} />
              <span className="nav-link-label">{item.label}</span>
            </NavLink>
          ))}
          <HostSidebarNav collapsed={sidebarCollapsed} />
        </nav>
        <div className="sidebar-foot">
          {renderNav([SETTINGS_NAV], "Settings", "sidebar-settings", {
            iconOnly: sidebarCollapsed,
          })}
        </div>
      </aside>

      <div className="app-main">
        <header className="mobile-topbar">
          <div className="mobile-brand">
            <span className="mobile-mark">Homelab</span>
            <strong>Watcher</strong>
          </div>
        </header>

        {banner ? <div className="error-banner">{banner}</div> : null}

        <div className="app-content">
          <Routes>
            <Route
              path="/"
              element={
                <div className="page-stack">
                  <HomePanel
                    containers={containers}
                    disks={disks}
                    warn={warn}
                    diskSelectionNeeded={diskSelectionNeeded}
                    checks={checks}
                    pihole={pihole}
                    dockerError={dockerError}
                    dockerAvailable={dockerAvailable}
                    dockerDisk={dockerDisk}
                    listeningPorts={listeningPorts}
                    listeningPortsEnabled={listeningPortsEnabled}
                    dockerPublishedPorts={dockerPublishedPorts}
                    cpu={cpu}
                    mem={mem}
                    memUsed={memUsed}
                    memTotal={memTotal}
                    hostCollecting={hostCollecting}
                    hostAt={hostAt}
                    uptimeSeconds={uptimeSeconds}
                    speedTest={speedTest}
                    status={status}
                  />
                  <ChecksPanel
                    items={checks}
                    takenAt={checksAt}
                    configSource={checksSource}
                  />
                </div>
              }
            />
            <Route
              path="/containers"
              element={
                <ContainersPanel
                  items={containers}
                  takenAt={containersAt}
                  pihole={pihole}
                  actionsEnabled={actionsEnabled}
                  onChanged={() => void refresh()}
                  dockerError={dockerError}
                  dockerAvailable={dockerAvailable}
                />
              }
            />
            <Route path="/dns" element={<DnsPanel />} />
            <Route
              path="/host/:section?"
              element={
                <HostRoute
                  cpu={cpu}
                  mem={mem}
                  memUsed={memUsed}
                  memTotal={memTotal}
                  disks={disks}
                  warn={warn}
                  takenAt={hostAt}
                  hostNote={hostNote}
                  diskSource={diskSource}
                  collecting={hostCollecting}
                  diskSelectionNeeded={diskSelectionNeeded}
                  listeningPorts={listeningPorts}
                  listeningPortsEnabled={listeningPortsEnabled}
                  listeningPortsNote={listeningPortsNote}
                  listeningPortsSource={listeningPortsSource}
                  dockerPublishedPorts={dockerPublishedPorts}
                  dockerPublishedNote={dockerPublishedNote}
                  dockerDisk={dockerDisk}
                  dockerDiskLoading={dockerDiskLoading}
                  actionsEnabled={actionsEnabled}
                  onDockerDiskRefresh={() => void refreshDockerDisk()}
                  uptimeSeconds={uptimeSeconds}
                  loadAvg={loadAvg}
                  networkInterfaces={networkInterfaces}
                  networkNote={networkNote}
                  networkSource={networkSource}
                  speedTest={speedTest}
                  onSpeedTestChange={() => void refresh()}
                />
              }
            />
            <Route
              path="/settings"
              element={<SettingsRoute onSaved={() => void refresh()} />}
            />
            <Route
              path="/settings/:section"
              element={<SettingsRoute onSaved={() => void refresh()} />}
            />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </div>

        <footer className="footer">
          <div>
            Last poll:{" "}
            <strong>
              {status?.poll.last_poll_at
                ? new Date(status.poll.last_poll_at).toLocaleString()
                : hostCollecting
                  ? "Collecting…"
                  : "—"}
            </strong>
          </div>
          <div>
            Next digest:{" "}
            <strong>
              {status?.digest.next_at
                ? new Date(status.digest.next_at).toLocaleString()
                : status?.digest.schedule_summary || "—"}
            </strong>
          </div>
          <div>
            Last email:{" "}
            <strong>
              {status?.digest.last_sent_at
                ? `${new Date(status.digest.last_sent_at).toLocaleString()}${
                    status.digest.last_kind
                      ? ` (${status.digest.last_kind})`
                      : ""
                  }`
                : "never"}
            </strong>
          </div>
        </footer>
      </div>

      {renderNav(MOBILE_NAV, "Main", "bottom-nav")}
    </div>
  );
}
