import { useEffect, useState } from "react";
import { createPortal } from "react-dom";
import {
  fetchDiskDiscover,
  fetchSettings,
  putSettings,
  runHostSpeedTest,
  sendTestDigest,
  testPihole,
  testPlex,
  type DiskMetric,
  type SettingsPayload,
} from "../api";
import { useScrollLock } from "../hooks/useScrollLock";

type Tab =
  | "general"
  | "plex"
  | "pihole"
  | "checks"
  | "email"
  | "security"
  | "disks"
  | "host";

const TABS: { id: Tab; label: string }[] = [
  { id: "plex", label: "Plex" },
  { id: "pihole", label: "Pi-hole" },
  { id: "checks", label: "Checks" },
  { id: "email", label: "Email" },
  { id: "disks", label: "Disks" },
  { id: "host", label: "Host" },
  { id: "security", label: "Security" },
  { id: "general", label: "General" },
];

const WEEKDAYS: { id: string; short: string; label: string }[] = [
  { id: "1", short: "Mon", label: "Monday" },
  { id: "2", short: "Tue", label: "Tuesday" },
  { id: "3", short: "Wed", label: "Wednesday" },
  { id: "4", short: "Thu", label: "Thursday" },
  { id: "5", short: "Fri", label: "Friday" },
  { id: "6", short: "Sat", label: "Saturday" },
  { id: "0", short: "Sun", label: "Sunday" },
];

type TargetDraft = {
  name: string;
  type: "http" | "ping" | "dns";
  url?: string;
  host?: string;
  query?: string;
  verify_tls?: boolean;
};

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

function pad2(n: number): string {
  return String(n).padStart(2, "0");
}

function timeFromHM(hour: number | null | undefined, minute: number | null | undefined): string {
  if (hour == null || minute == null) return "";
  return `${pad2(hour)}:${pad2(minute)}`;
}

function parseTime(value: string): { hour: number; minute: number } | null {
  const m = /^(\d{1,2}):(\d{2})$/.exec(value.trim());
  if (!m) return null;
  const hour = Number(m[1]);
  const minute = Number(m[2]);
  if (!Number.isFinite(hour) || !Number.isFinite(minute)) return null;
  if (hour < 0 || hour > 23 || minute < 0 || minute > 59) return null;
  return { hour, minute };
}

export function SettingsPanel({
  open,
  onClose,
  onSaved,
  initialTab,
  asPage,
}: {
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
  initialTab?: string | null;
  asPage?: boolean;
}) {
  const [tab, setTab] = useState<Tab>("general");
  const [data, setData] = useState<SettingsPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const [pollSec, setPollSec] = useState(300);
  const [actionsOn, setActionsOn] = useState(true);
  const [targets, setTargets] = useState<TargetDraft[]>([]);
  const [plexOn, setPlexOn] = useState(false);
  const [plexUrl, setPlexUrl] = useState("");
  const [plexTls, setPlexTls] = useState(true);
  const [phUrl, setPhUrl] = useState("");
  const [phVer, setPhVer] = useState("auto");
  const [phPass, setPhPass] = useState("");
  const [phToken, setPhToken] = useState("");
  const [phTls, setPhTls] = useState(true);
  const [digKey, setDigKey] = useState("");
  const [digProfiles, setDigProfiles] = useState<
    Array<{
      id: string;
      name: string;
      enabled: boolean;
      digest_from: string;
      digest_to: string;
      digest_send_all_clear: boolean;
      tz: string;
      schedule_frequency: "" | "daily" | "weekly";
      schedule_weekday: string;
      schedule_time: string;
    }>
  >([]);
  const [digSelectedId, setDigSelectedId] = useState<string | null>(null);
  const [secTrivyEnabled, setSecTrivyEnabled] = useState(false);
  const [secInterval, setSecInterval] = useState(24);
  const [secNotable, setSecNotable] = useState("HIGH");
  const [secIgnoreUnfixed, setSecIgnoreUnfixed] = useState(false);
  const [secScmEnabled, setSecScmEnabled] = useState(false);
  const [secScmInterval, setSecScmInterval] = useState(24);
  const [secGitToken, setSecGitToken] = useState("");
  const [secOpenScaToken, setSecOpenScaToken] = useState("");
  const [secHasGitToken, setSecHasGitToken] = useState(false);
  const [secHasOpenScaToken, setSecHasOpenScaToken] = useState(false);
  const [portsEnabled, setPortsEnabled] = useState(true);
  const [speedEnabled, setSpeedEnabled] = useState(false);
  const [speedInterval, setSpeedInterval] = useState(12);
  const [speedBusy, setSpeedBusy] = useState(false);
  const [speedLastLabel, setSpeedLastLabel] = useState<string | null>(null);
  const [diskWarn, setDiskWarn] = useState(85);
  const [discovered, setDiscovered] = useState<DiskMetric[]>([]);
  const [selectedDisks, setSelectedDisks] = useState<string[]>([]);
  const [diskNote, setDiskNote] = useState<string | null>(null);
  const [diskDiscoverBusy, setDiskDiscoverBusy] = useState(false);
  const [alertExited, setAlertExited] = useState(false);

  useEffect(() => {
    if (!open && !asPage) return;
    const wanted = (initialTab || "").toLowerCase();
    if (wanted === "plex") setTab("plex");
    else if (wanted === "pihole") setTab("pihole");
    else if (wanted === "disks") setTab("disks");
    else if (wanted === "host") setTab("host");
    else if (wanted === "email" || wanted === "digest") setTab("email");
    else if (wanted === "checks" || wanted === "watched") setTab("checks");
    else if (wanted === "security") setTab("security");
    else if (wanted === "general") setTab("general");
  }, [open, asPage, initialTab]);

  useEffect(() => {
    if (!open && !asPage) return;
    void (async () => {
      try {
        const s = await fetchSettings();
        setData(s);
        setPollSec(s.general.poll_interval_seconds);
        setActionsOn(s.general.actions_enabled);
        const checkTargets =
          s.checks?.targets || s.watched?.targets || [];
        setTargets(
          checkTargets.map((t) => ({
            name: String(t.name || ""),
            type: (t.type as TargetDraft["type"]) || "http",
            url: t.url ? String(t.url) : "",
            host: t.host ? String(t.host) : "",
            query: t.query ? String(t.query) : "",
            verify_tls: t.verify_tls !== false,
          })),
        );
        setPlexOn(Boolean(s.plex?.enabled));
        setPlexUrl(s.plex?.url || "");
        setPlexTls(s.plex?.verify_tls !== false);
        setPhUrl(s.pihole.url || "");
        setPhVer(s.pihole.version || "auto");
        setPhTls(s.pihole.verify_tls);
        setPhPass("");
        setPhToken("");
        setDigKey("");
        const rawProfiles =
          s.digest.profiles && s.digest.profiles.length > 0
            ? s.digest.profiles
            : [
                {
                  id: "default",
                  name: "Default",
                  enabled: s.digest.enabled,
                  digest_from: s.digest.digest_from,
                  digest_to: s.digest.digest_to,
                  digest_send_all_clear: s.digest.digest_send_all_clear,
                  tz: s.digest.tz || "UTC",
                  schedule_frequency: s.digest.schedule_frequency,
                  schedule_weekday: s.digest.schedule_weekday,
                  schedule_hour: s.digest.schedule_hour,
                  schedule_minute: s.digest.schedule_minute,
                },
              ];
        const mapped = rawProfiles.map((p, i) => {
          const freq = p.schedule_frequency;
          const schedule_frequency: "" | "daily" | "weekly" =
            freq === "daily" || freq === "weekly" ? freq : "";
          return {
            id: String(p.id || `p${i}`),
            name: String(p.name || `Digest ${i + 1}`),
            enabled: Boolean(p.enabled),
            digest_from: String(p.digest_from || ""),
            digest_to: String(p.digest_to || ""),
            digest_send_all_clear: p.digest_send_all_clear !== false,
            tz: String(p.tz || "UTC"),
            schedule_frequency,
            schedule_weekday:
              p.schedule_weekday != null && p.schedule_weekday !== ""
                ? String(p.schedule_weekday)
                : "",
            schedule_time: timeFromHM(p.schedule_hour, p.schedule_minute),
          };
        });
        setDigProfiles(mapped);
        setDigSelectedId((prev) =>
          prev && mapped.some((p) => p.id === prev) ? prev : mapped[0]?.id ?? null,
        );
        const trivy = (s.security.trivy || {}) as Record<string, unknown>;
        const osca = (s.security.opensca || {}) as Record<string, unknown>;
        // Resolved settings already migrate legacy security.enabled → scanner flags
        setSecTrivyEnabled(Boolean(trivy.enabled));
        setSecInterval(Number(trivy.scan_interval_hours ?? 24));
        setSecNotable(String(s.security.notable_severity || "HIGH"));
        setSecIgnoreUnfixed(Boolean(trivy.ignore_unfixed));
        setSecScmEnabled(Boolean(osca.enabled));
        setSecScmInterval(Number(osca.scan_interval_hours ?? 24));
        setSecHasGitToken(Boolean(osca.has_git_token));
        setSecHasOpenScaToken(Boolean(osca.has_opensca_token));
        setSecGitToken("");
        setSecOpenScaToken("");
        setPortsEnabled(s.listening_ports?.enabled !== false);
        setSpeedEnabled(Boolean(s.speed_test?.enabled));
        setSpeedInterval(
          typeof s.speed_test?.interval_hours === "number"
            ? s.speed_test.interval_hours
            : 12,
        );
        setSpeedBusy(Boolean(s.speed_test?.busy));
        {
          const last = s.speed_test?.last;
          if (last?.download_mbps != null) {
            setSpeedLastLabel(
              `${last.download_mbps.toFixed(1)}↓ / ${(last.upload_mbps ?? 0).toFixed(1)}↑ Mbps` +
                (last.taken_at
                  ? ` · ${new Date(last.taken_at).toLocaleString()}`
                  : ""),
            );
          } else {
            setSpeedLastLabel(null);
          }
        }
        setDiskWarn(s.disks.disk_warn_percent);
        setAlertExited(Boolean(s.disks.alert_on_exited));
        setError(null);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    })();
  }, [open, asPage]);

  useEffect(() => {
    if ((!open && !asPage) || tab !== "disks") return;
    void (async () => {
      setDiskDiscoverBusy(true);
      try {
        const d = await fetchDiskDiscover();
        setDiscovered(d.disks || []);
        setSelectedDisks([...(d.selected || [])]);
        setDiskWarn(d.disk_warn_percent ?? 85);
        setDiskNote(d.note);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setDiskDiscoverBusy(false);
      }
    })();
  }, [open, asPage, tab]);

  useEffect(() => {
    if (!toast) return;
    const id = window.setTimeout(() => setToast(null), 3500);
    return () => window.clearTimeout(id);
  }, [toast]);

  useScrollLock(Boolean(open && !asPage));

  if (!open && !asPage) return null;

  async function save(section: string, body: Record<string, unknown>) {
    setBusy(true);
    setError(null);
    try {
      await putSettings(section, body);
      setToast("Saved");
      onSaved();
      const s = await fetchSettings();
      setData(s);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  function toggleDisk(path: string) {
    setSelectedDisks((prev) =>
      prev.includes(path) ? prev.filter((p) => p !== path) : [...prev, path],
    );
  }

  const body = (
    <div className={asPage ? "settings-page" : "settings-layout"}>
      <div className="settings-tabs-rail">
        <nav className="settings-tabs" aria-label="Settings sections">
          {TABS.map((t) => (
            <button
              key={t.id}
              type="button"
              className={tab === t.id ? "settings-tab active" : "settings-tab"}
              onClick={() => setTab(t.id)}
            >
              {t.label}
            </button>
          ))}
        </nav>
      </div>
      <div className="settings-content">
        {error ? <div className="error-inline">{error}</div> : null}
        {toast ? <div className="settings-toast">{toast}</div> : null}

        {tab === "general" ? (
          <section>
            <label className="field">
              Poll interval (seconds)
              <input
                type="number"
                min={60}
                value={pollSec}
                onChange={(e) => setPollSec(Number(e.target.value))}
              />
            </label>
            <label className="check-row">
              <input
                type="checkbox"
                checked={actionsOn}
                onChange={(e) => setActionsOn(e.target.checked)}
              />
              Enable update / stop / start / restart / remove / reclaim from this app
            </label>
            <p className="helper">
              Compose updates, lifecycle actions (stop/start/restart/pause/kill),
              tear-down, and Docker disk reclaim. Home network
              only. Turn off for inventory-only.
            </p>
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy}
              onClick={() =>
                void save("general", {
                  poll_interval_seconds: pollSec,
                  actions_enabled: actionsOn,
                })
              }
            >
              Save general
            </button>
          </section>
        ) : null}

        {tab === "plex" ? (
          <section>
            <p className="helper">Optional Plex reachability check.</p>
            <label className="check-row">
              <input
                type="checkbox"
                checked={plexOn}
                onChange={(e) => setPlexOn(e.target.checked)}
              />
              Enable Plex check
            </label>
            <label className="field">
              Plex URL
              <input
                placeholder="http://192.168.1.10:32400"
                value={plexUrl}
                onChange={(e) => setPlexUrl(e.target.value)}
              />
            </label>
            <label className="check-row">
              <input
                type="checkbox"
                checked={plexTls}
                onChange={(e) => setPlexTls(e.target.checked)}
              />
              Verify TLS
            </label>
            <div className="detail-actions">
              <button
                type="button"
                className="btn btn-primary"
                disabled={busy}
                onClick={() =>
                  void save("plex", {
                    enabled: plexOn,
                    url: plexUrl,
                    verify_tls: plexTls,
                  })
                }
              >
                Save Plex
              </button>
              <button
                type="button"
                className="btn"
                disabled={busy}
                onClick={() =>
                  void (async () => {
                    setBusy(true);
                    try {
                      const r = await testPlex({
                        enabled: plexOn,
                        url: plexUrl,
                        verify_tls: plexTls,
                      });
                      setToast(r.ok ? "Plex OK" : r.message || "Plex failed");
                    } catch (e) {
                      setError(e instanceof Error ? e.message : String(e));
                    } finally {
                      setBusy(false);
                    }
                  })()
                }
              >
                Test
              </button>
            </div>
          </section>
        ) : null}

        {tab === "pihole" ? (
          <section>
            <p className="helper">Optional — badges containers with matching DNS.</p>
            <label className="field">
              Pi-hole URL
              <input
                placeholder="http://192.168.1.50"
                value={phUrl}
                onChange={(e) => setPhUrl(e.target.value)}
              />
            </label>
            <label className="field">
              Version
              <select value={phVer} onChange={(e) => setPhVer(e.target.value)}>
                <option value="auto">auto</option>
                <option value="6">6</option>
                <option value="5">5</option>
              </select>
            </label>
            <label className="field">
              Password / app password{data?.pihole.has_password ? " · set" : ""}
              <input
                type="password"
                autoComplete="new-password"
                placeholder={data?.pihole.has_password ? "(unchanged)" : ""}
                value={phPass}
                onChange={(e) => setPhPass(e.target.value)}
              />
            </label>
            <label className="field">
              API token (v5){data?.pihole.has_api_token ? " · set" : ""}
              <input
                type="password"
                autoComplete="new-password"
                placeholder={data?.pihole.has_api_token ? "(unchanged)" : ""}
                value={phToken}
                onChange={(e) => setPhToken(e.target.value)}
              />
            </label>
            <label className="check-row">
              <input
                type="checkbox"
                checked={phTls}
                onChange={(e) => setPhTls(e.target.checked)}
              />
              Verify TLS
            </label>
            <div className="detail-actions">
              <button
                type="button"
                className="btn btn-primary"
                disabled={busy}
                onClick={() => {
                  const body: Record<string, unknown> = {
                    url: phUrl,
                    version: phVer,
                    verify_tls: phTls,
                  };
                  if (phPass) body.password = phPass;
                  if (phToken) body.api_token = phToken;
                  void save("pihole", body);
                }}
              >
                Save Pi-hole
              </button>
              <button
                type="button"
                className="btn"
                disabled={busy}
                onClick={() =>
                  void (async () => {
                    setBusy(true);
                    try {
                      const r = await testPihole();
                      setToast(
                        r.ok
                          ? `OK · ${r.record_count ?? 0} records`
                          : r.message || "Failed",
                      );
                    } catch (e) {
                      setError(e instanceof Error ? e.message : String(e));
                    } finally {
                      setBusy(false);
                    }
                  })()
                }
              >
                Test
              </button>
            </div>
          </section>
        ) : null}

        {tab === "checks" ? (
          <section>
            <p className="helper">HTTP, ping, or DNS probes you add.</p>
            {targets.map((t, i) => (
              <div key={i} className="target-card">
                <div className="target-row">
                  <input
                    placeholder="Name"
                    value={t.name}
                    onChange={(e) => {
                      const next = [...targets];
                      next[i] = { ...t, name: e.target.value };
                      setTargets(next);
                    }}
                  />
                  <select
                    value={t.type}
                    onChange={(e) => {
                      const next = [...targets];
                      next[i] = {
                        ...t,
                        type: e.target.value as TargetDraft["type"],
                      };
                      setTargets(next);
                    }}
                  >
                    <option value="http">http</option>
                    <option value="ping">ping</option>
                    <option value="dns">dns</option>
                  </select>
                  <button
                    type="button"
                    className="btn"
                    onClick={() => setTargets(targets.filter((_, j) => j !== i))}
                  >
                    Remove
                  </button>
                </div>
                {t.type === "http" ? (
                  <input
                    placeholder="https://app.example.com"
                    value={t.url || ""}
                    onChange={(e) => {
                      const next = [...targets];
                      next[i] = { ...t, url: e.target.value };
                      setTargets(next);
                    }}
                  />
                ) : (
                  <div className="target-row">
                    <input
                      placeholder="Host / IP"
                      value={t.host || ""}
                      onChange={(e) => {
                        const next = [...targets];
                        next[i] = { ...t, host: e.target.value };
                        setTargets(next);
                      }}
                    />
                    {t.type === "dns" ? (
                      <input
                        placeholder="Query name"
                        value={t.query || ""}
                        onChange={(e) => {
                          const next = [...targets];
                          next[i] = { ...t, query: e.target.value };
                          setTargets(next);
                        }}
                      />
                    ) : null}
                  </div>
                )}
              </div>
            ))}
            <button
              type="button"
              className="btn"
              onClick={() =>
                setTargets([
                  ...targets,
                  { name: "", type: "http", url: "", verify_tls: true },
                ])
              }
            >
              Add check
            </button>{" "}
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy}
              onClick={() =>
                void save("checks", {
                  targets: targets.filter((t) => t.name.trim()),
                })
              }
            >
              Save checks
            </button>
          </section>
        ) : null}

        {tab === "email" ? (
          <section>
            <p className="helper">
              Quiet summaries when something needs a look. Multiple digests can
              go to different inboxes on different schedules.
            </p>

            <label className="field">
              Resend API key{data?.digest.has_resend_api_key ? " · set" : ""}
              <input
                type="password"
                autoComplete="new-password"
                placeholder={
                  data?.digest.has_resend_api_key
                    ? "(unchanged — paste to replace)"
                    : "re_…"
                }
                value={digKey}
                onChange={(e) => setDigKey(e.target.value)}
              />
            </label>

            <div className="digest-profile-list">
              {digProfiles.map((p) => {
                const selected = digSelectedId === p.id;
                const summary =
                  !p.schedule_frequency ||
                  !p.schedule_time ||
                  (p.schedule_frequency === "weekly" && !p.schedule_weekday)
                    ? "Not scheduled"
                    : p.schedule_frequency === "daily"
                      ? `Daily · ${p.schedule_time}`
                      : `Weekly · ${
                          WEEKDAYS.find((d) => d.id === p.schedule_weekday)?.short ||
                          "?"
                        } · ${p.schedule_time}`;
                return (
                  <button
                    key={p.id}
                    type="button"
                    className={
                      selected ? "digest-profile-chip active" : "digest-profile-chip"
                    }
                    onClick={() => setDigSelectedId(p.id)}
                  >
                    <span className="digest-profile-chip-name">
                      {p.name || "Digest"}
                      {p.enabled ? "" : " · off"}
                    </span>
                    <span className="digest-profile-chip-meta">{summary}</span>
                  </button>
                );
              })}
            </div>

            <div className="detail-actions" style={{ marginBottom: "0.75rem" }}>
              <button
                type="button"
                className="btn"
                disabled={busy}
                onClick={() => {
                  const id = `new-${Date.now().toString(36)}`;
                  const baseTz = digProfiles[0]?.tz || "UTC";
                  setDigProfiles((prev) => [
                    ...prev,
                    {
                      id,
                      name: `Digest ${prev.length + 1}`,
                      enabled: false,
                      digest_from: prev[0]?.digest_from || "",
                      digest_to: "",
                      digest_send_all_clear: true,
                      tz: baseTz,
                      schedule_frequency: "",
                      schedule_weekday: "",
                      schedule_time: "",
                    },
                  ]);
                  setDigSelectedId(id);
                }}
              >
                Add digest
              </button>
            </div>

            {(() => {
              const dig = digProfiles.find((p) => p.id === digSelectedId);
              if (!dig) {
                return <p className="helper">Select or add a digest.</p>;
              }
              const updateDig = (
                patch: Partial<(typeof digProfiles)[number]>,
              ) => {
                setDigProfiles((prev) =>
                  prev.map((p) => (p.id === dig.id ? { ...p, ...patch } : p)),
                );
              };
              return (
                <div className="target-card digest-editor">
                  <label className="check-row">
                    <input
                      type="checkbox"
                      checked={dig.enabled}
                      onChange={(e) => updateDig({ enabled: e.target.checked })}
                    />
                    Enabled
                  </label>
                  <label className="field">
                    Name
                    <input
                      value={dig.name}
                      onChange={(e) => updateDig({ name: e.target.value })}
                    />
                  </label>

                  <div className="schedule-block">
                    <div className="schedule-label">How often</div>
                    <div
                      className="seg-control"
                      role="radiogroup"
                      aria-label="How often"
                    >
                      <button
                        type="button"
                        role="radio"
                        aria-checked={dig.schedule_frequency === "daily"}
                        className={
                          dig.schedule_frequency === "daily"
                            ? "seg-btn active"
                            : "seg-btn"
                        }
                        onClick={() => updateDig({ schedule_frequency: "daily" })}
                      >
                        Daily
                      </button>
                      <button
                        type="button"
                        role="radio"
                        aria-checked={dig.schedule_frequency === "weekly"}
                        className={
                          dig.schedule_frequency === "weekly"
                            ? "seg-btn active"
                            : "seg-btn"
                        }
                        onClick={() => updateDig({ schedule_frequency: "weekly" })}
                      >
                        Weekly
                      </button>
                    </div>

                    {dig.schedule_frequency === "weekly" ? (
                      <>
                        <div className="schedule-label">Day</div>
                        <div className="day-chips" role="radiogroup" aria-label="Day">
                          {WEEKDAYS.map((d) => (
                            <button
                              key={d.id}
                              type="button"
                              role="radio"
                              aria-checked={dig.schedule_weekday === d.id}
                              title={d.label}
                              className={
                                dig.schedule_weekday === d.id
                                  ? "day-chip active"
                                  : "day-chip"
                              }
                              onClick={() => updateDig({ schedule_weekday: d.id })}
                            >
                              {d.short}
                            </button>
                          ))}
                        </div>
                      </>
                    ) : null}

                    <label className="field schedule-time-field">
                      Time
                      <input
                        type="time"
                        value={dig.schedule_time}
                        onChange={(e) =>
                          updateDig({ schedule_time: e.target.value })
                        }
                      />
                    </label>

                    {!dig.schedule_frequency ||
                    !dig.schedule_time ||
                    (dig.schedule_frequency === "weekly" &&
                      !dig.schedule_weekday) ? (
                      <p className="helper">
                        {dig.schedule_frequency === "weekly"
                          ? "Pick a day and time to schedule."
                          : "Pick how often and a time to schedule."}
                      </p>
                    ) : (
                      <p className="helper">
                        {dig.schedule_frequency === "daily"
                          ? `Every day at ${dig.schedule_time} (${dig.tz})`
                          : `Every ${
                              WEEKDAYS.find((d) => d.id === dig.schedule_weekday)
                                ?.label || "day"
                            } at ${dig.schedule_time} (${dig.tz})`}
                      </p>
                    )}
                  </div>

                  <label className="field">
                    Timezone
                    <input
                      value={dig.tz}
                      onChange={(e) => updateDig({ tz: e.target.value })}
                    />
                  </label>
                  <label className="field">
                    From
                    <input
                      value={dig.digest_from}
                      onChange={(e) => updateDig({ digest_from: e.target.value })}
                    />
                  </label>
                  <label className="field">
                    To
                    <input
                      value={dig.digest_to}
                      onChange={(e) => updateDig({ digest_to: e.target.value })}
                    />
                  </label>
                  <label className="check-row">
                    <input
                      type="checkbox"
                      checked={dig.digest_send_all_clear}
                      onChange={(e) =>
                        updateDig({ digest_send_all_clear: e.target.checked })
                      }
                    />
                    Send “all clear” when nothing is wrong
                  </label>

                  <div className="detail-actions">
                    <button
                      type="button"
                      className="btn"
                      disabled={busy || digProfiles.length <= 1}
                      onClick={() => {
                        const next = digProfiles.filter((p) => p.id !== dig.id);
                        setDigProfiles(next);
                        setDigSelectedId(next[0]?.id ?? null);
                      }}
                    >
                      Delete
                    </button>
                    <button
                      type="button"
                      className="btn"
                      disabled={busy || dig.id.startsWith("new-")}
                      title={
                        dig.id.startsWith("new-")
                          ? "Save email first, then test"
                          : undefined
                      }
                      onClick={() =>
                        void (async () => {
                          setBusy(true);
                          try {
                            const r = await sendTestDigest(dig.id);
                            setToast(
                              r.sent
                                ? `Sent to ${String(r.profile_name || dig.name)} (${String(r.kind)})`
                                : String(r.reason || "Not sent"),
                            );
                          } catch (e) {
                            setError(
                              e instanceof Error ? e.message : String(e),
                            );
                          } finally {
                            setBusy(false);
                          }
                        })()
                      }
                    >
                      Send test
                    </button>
                  </div>
                </div>
              );
            })()}

            <div className="detail-actions">
              <button
                type="button"
                className="btn btn-primary"
                disabled={busy || digProfiles.length === 0}
                onClick={() => {
                  const body: Record<string, unknown> = {
                    profiles: digProfiles.map((p) => {
                      const parsed = p.schedule_time
                        ? parseTime(p.schedule_time)
                        : null;
                      return {
                        id: p.id.startsWith("new-") ? null : p.id,
                        name: p.name.trim() || "Digest",
                        enabled: p.enabled,
                        digest_from: p.digest_from,
                        digest_to: p.digest_to,
                        digest_send_all_clear: p.digest_send_all_clear,
                        tz: p.tz,
                        schedule_frequency: p.schedule_frequency || "",
                        schedule_weekday:
                          p.schedule_frequency === "weekly" && p.schedule_weekday
                            ? p.schedule_weekday
                            : null,
                        schedule_hour: parsed?.hour ?? null,
                        schedule_minute: parsed?.minute ?? null,
                      };
                    }),
                  };
                  if (digKey) body.resend_api_key = digKey;
                  void save("digest", body);
                }}
              >
                Save email
              </button>
            </div>
          </section>
        ) : null}

        {tab === "security" ? (
          <section>
            <p className="helper">
              Turn scanners on separately. Posture checks run when either is on.
            </p>
            <p className="helper">
              Listening ports and Internet speed are under Settings → Host.
            </p>
            <p className="helper">
              Trivy: {data?.security.trivy_available ? "available" : "not found"}
              {" · "}
              OpenSCA:{" "}
              {data?.security.opensca_available ? "available" : "not found"}
            </p>

            <h4 className="settings-subhead">Image scans (Trivy)</h4>
            <label className="check-row">
              <input
                type="checkbox"
                checked={secTrivyEnabled}
                onChange={(e) => setSecTrivyEnabled(e.target.checked)}
              />
              Image scans (Trivy)
            </label>
            <label className="field">
              Image re-scan interval (hours)
              <input
                type="number"
                min={1}
                value={secInterval}
                onChange={(e) => setSecInterval(Number(e.target.value))}
              />
            </label>
            <label className="field">
              Notable severity
              <select
                value={secNotable}
                onChange={(e) => setSecNotable(e.target.value)}
              >
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH+</option>
                <option value="MEDIUM">MEDIUM+</option>
                <option value="LOW">LOW+</option>
              </select>
            </label>
            <label className="check-row">
              <input
                type="checkbox"
                checked={secIgnoreUnfixed}
                onChange={(e) => setSecIgnoreUnfixed(e.target.checked)}
              />
              Ignore unfixed vulnerabilities
            </label>

            <h4 className="settings-subhead">Repo scans (OpenSCA)</h4>
            <p className="helper">
              Finds repo URLs from image labels, shallow-clones, scans
              dependencies.
            </p>
            <label className="check-row">
              <input
                type="checkbox"
                checked={secScmEnabled}
                onChange={(e) => setSecScmEnabled(e.target.checked)}
              />
              Repo scans (OpenSCA)
            </label>
            <label className="field">
              Repo re-scan interval (hours)
              <input
                type="number"
                min={1}
                value={secScmInterval}
                onChange={(e) => setSecScmInterval(Number(e.target.value))}
              />
            </label>
            <label className="field">
              Git token (private repos)
              <input
                type="password"
                autoComplete="off"
                placeholder={
                  secHasGitToken ? "Saved — leave blank to keep" : "Optional"
                }
                value={secGitToken}
                onChange={(e) => setSecGitToken(e.target.value)}
              />
            </label>
            <label className="field">
              OpenSCA cloud token
              <input
                type="password"
                autoComplete="off"
                placeholder={
                  secHasOpenScaToken
                    ? "Saved — leave blank to keep"
                    : "Optional (richer CVE data)"
                }
                value={secOpenScaToken}
                onChange={(e) => setSecOpenScaToken(e.target.value)}
              />
            </label>

            <button
              type="button"
              className="btn btn-primary"
              disabled={busy}
              onClick={() => {
                void (async () => {
                  setBusy(true);
                  setError(null);
                  const anyOn = secTrivyEnabled || secScmEnabled;
                  try {
                    await putSettings("security", {
                      enabled: anyOn,
                      notable_severity: secNotable,
                      trivy: {
                        enabled: secTrivyEnabled,
                        scan_interval_hours: secInterval,
                        ignore_unfixed: secIgnoreUnfixed,
                      },
                      posture: { enabled: anyOn },
                      opensca: {
                        enabled: secScmEnabled,
                        scan_interval_hours: secScmInterval,
                        ...(secGitToken.trim()
                          ? { git_token: secGitToken.trim() }
                          : {}),
                        ...(secOpenScaToken.trim()
                          ? { opensca_token: secOpenScaToken.trim() }
                          : {}),
                      },
                    });
                    setToast("Saved");
                    onSaved();
                    const s = await fetchSettings();
                    setData(s);
                    const trivy = (s.security.trivy || {}) as Record<
                      string,
                      unknown
                    >;
                    const osca = (s.security.opensca || {}) as Record<
                      string,
                      unknown
                    >;
                    setSecTrivyEnabled(Boolean(trivy.enabled));
                    setSecScmEnabled(Boolean(osca.enabled));
                    setSecHasGitToken(Boolean(osca.has_git_token));
                    setSecHasOpenScaToken(Boolean(osca.has_opensca_token));
                    setSecGitToken("");
                    setSecOpenScaToken("");
                  } catch (e) {
                    setError(e instanceof Error ? e.message : String(e));
                  } finally {
                    setBusy(false);
                  }
                })();
              }}
            >
              Save security
            </button>
          </section>
        ) : null}

        {tab === "host" ? (
          <section>
            <p className="helper">
              Host page extras — listening ports and optional Internet speed.
            </p>
            <label className="check-row">
              <input
                type="checkbox"
                checked={portsEnabled}
                onChange={(e) => setPortsEnabled(e.target.checked)}
              />
              Show listening ports on Host
            </label>
            <p className="helper">
              Inventory of sockets already listening (host /proc via /:/host:ro) —
              not a network scan.
            </p>

            <h4 className="settings-subhead">Internet speed</h4>
            <p className="helper">
              {data?.notes?.speed_test ||
                "Uses Cloudflare speed.cloudflare.com (no API key). Transfers ~5 MiB down / ~2 MiB up — keep infrequent."}
            </p>
            <label className="check-row">
              <input
                type="checkbox"
                checked={speedEnabled}
                onChange={(e) => setSpeedEnabled(e.target.checked)}
              />
              Enable scheduled speed checks
            </label>
            <label className="field">
              Interval (hours; 0 = manual only)
              <input
                type="number"
                min={0}
                step={1}
                value={speedInterval}
                onChange={(e) => setSpeedInterval(Number(e.target.value))}
              />
            </label>
            {speedLastLabel ? (
              <p className="helper">Last: {speedLastLabel}</p>
            ) : (
              <p className="helper">No speed result stored yet.</p>
            )}
            <div className="settings-actions-row">
              <button
                type="button"
                className="btn btn-primary"
                disabled={busy}
                onClick={() => {
                  void (async () => {
                    setBusy(true);
                    setError(null);
                    try {
                      await putSettings("listening_ports", {
                        enabled: portsEnabled,
                      });
                      await putSettings("speed_test", {
                        enabled: speedEnabled,
                        interval_hours: speedInterval,
                      });
                      setToast("Saved");
                      onSaved();
                      const s = await fetchSettings();
                      setData(s);
                      setPortsEnabled(s.listening_ports?.enabled !== false);
                      setSpeedEnabled(Boolean(s.speed_test?.enabled));
                      setSpeedInterval(
                        typeof s.speed_test?.interval_hours === "number"
                          ? s.speed_test.interval_hours
                          : 12,
                      );
                    } catch (e) {
                      setError(e instanceof Error ? e.message : String(e));
                    } finally {
                      setBusy(false);
                    }
                  })();
                }}
              >
                Save host
              </button>
              <button
                type="button"
                className="btn"
                disabled={busy || speedBusy}
                onClick={() => {
                  void (async () => {
                    setSpeedBusy(true);
                    setError(null);
                    try {
                      await runHostSpeedTest();
                      setToast("Speed check started");
                      onSaved();
                      // Poll briefly for result
                      for (let i = 0; i < 12; i += 1) {
                        await new Promise((r) => window.setTimeout(r, 2500));
                        const s = await fetchSettings();
                        setData(s);
                        setSpeedBusy(Boolean(s.speed_test?.busy));
                        const last = s.speed_test?.last;
                        if (last?.download_mbps != null && !s.speed_test?.busy) {
                          setSpeedLastLabel(
                            `${last.download_mbps.toFixed(1)}↓ / ${(last.upload_mbps ?? 0).toFixed(1)}↑ Mbps` +
                              (last.taken_at
                                ? ` · ${new Date(last.taken_at).toLocaleString()}`
                                : ""),
                          );
                          setToast("Speed check done");
                          break;
                        }
                        if (!s.speed_test?.busy && last?.error) {
                          setSpeedLastLabel(last.error);
                          break;
                        }
                      }
                    } catch (e) {
                      setError(e instanceof Error ? e.message : String(e));
                    } finally {
                      setSpeedBusy(false);
                    }
                  })();
                }}
              >
                {speedBusy ? "Running…" : "Run now"}
              </button>
            </div>
          </section>
        ) : null}

        {tab === "disks" ? (
          <section>
            <p className="helper">Pick disks to show on Host.</p>
            <label className="field">
              Warn at percent
              <input
                type="number"
                value={diskWarn}
                onChange={(e) => setDiskWarn(Number(e.target.value))}
              />
            </label>
            {diskDiscoverBusy ? (
              <div className="empty">Discovering disks…</div>
            ) : !discovered.length ? (
              <div className="empty">{diskNote || "No disks found."}</div>
            ) : (
              <div className="disk-pick-table-wrap">
                <table className="table disk-pick-table">
                  <thead>
                    <tr>
                      <th className="disk-check-col" />
                      <th>Path</th>
                      <th>Size</th>
                      <th>Used</th>
                      <th>Avail</th>
                      <th>%</th>
                    </tr>
                  </thead>
                  <tbody>
                    {discovered.map((d) => {
                      const path = d.mountpoint || d.path;
                      const checked = selectedDisks.includes(path);
                      const err = Boolean(d.error) || d.mounted === false;
                      const avail = d.free_bytes;
                      return (
                        <tr
                          key={path}
                          className={checked ? "disk-row-selected clickable" : "clickable"}
                          onClick={() => toggleDisk(path)}
                        >
                          <td className="disk-check-col" onClick={(e) => e.stopPropagation()}>
                            <input
                              type="checkbox"
                              checked={checked}
                              onChange={() => toggleDisk(path)}
                              aria-label={`Monitor ${path}`}
                            />
                          </td>
                          <td className="mono path-cell">{path}</td>
                          <td className="mono">
                            {err ? "—" : formatBytes(d.total_bytes)}
                          </td>
                          <td className="mono">
                            {err ? "—" : formatBytes(d.used_bytes)}
                          </td>
                          <td className="mono">{err ? "—" : formatBytes(avail)}</td>
                          <td className="mono">
                            {err
                              ? "n/a"
                              : d.percent != null
                                ? `${d.percent.toFixed(0)}%`
                                : "—"}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
            {diskNote ? <p className="helper">{diskNote}</p> : null}
            <label className="check-row">
              <input
                type="checkbox"
                checked={alertExited}
                onChange={(e) => setAlertExited(e.target.checked)}
              />
              Treat any stopped container as notable (noisy)
            </label>
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy || diskDiscoverBusy}
              onClick={() =>
                void save("disks", {
                  disk_warn_percent: diskWarn,
                  disks: selectedDisks,
                  alert_on_exited: alertExited,
                })
              }
            >
              Save disks
            </button>
          </section>
        ) : null}
      </div>
    </div>
  );

  if (asPage) {
    return (
      <section className="panel settings-panel-page">
        <div className="panel-head">
          <h2>Settings</h2>
        </div>
        {body}
      </section>
    );
  }

  return createPortal(
    <div className="modal-root" role="presentation">
      <button
        type="button"
        className="modal-backdrop"
        aria-label="Close"
        onClick={onClose}
      />
      <div
        className="modal-panel modal-wide settings-panel"
        role="dialog"
        aria-modal="true"
      >
        <div className="modal-head">
          <h2>Settings</h2>
          <button
            type="button"
            className="modal-close"
            onClick={onClose}
            aria-label="Close"
          >
            ×
          </button>
        </div>
        {body}
      </div>
    </div>,
    document.body,
  );
}
