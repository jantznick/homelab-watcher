import { useCallback, useEffect, useState } from "react";
import {
  fetchContainerLogs,
  fetchJob,
  setWatched,
  startKill,
  startPause,
  startRestart,
  startStart,
  startStop,
  startTeardown,
  startUnpause,
  startUpdate,
  type ActionJob,
  type ContainerItem,
} from "../api";
import { Drawer } from "./Drawer";

const LOG_TAIL = 150;

type ConfirmStep =
  | "confirm-start"
  | "confirm-stop"
  | "confirm-restart"
  | "confirm-pause"
  | "confirm-unpause"
  | "confirm-kill"
  | "confirm-update"
  | "confirm-teardown";

type Step = "detail" | ConfirmStep;

export type ContainerDrawerStep = Step;

function formatUptime(seconds: number | null | undefined): string {
  if (seconds == null) return "—";
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function formatWhen(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return iso;
    return d.toLocaleString();
  } catch {
    return iso;
  }
}

function shortId(id: string | null | undefined, len = 12): string {
  if (!id) return "—";
  const cleaned = id.replace(/^sha256:/, "");
  return cleaned.length > len ? cleaned.slice(0, len) : cleaned;
}

function isStarred(c: ContainerItem): boolean {
  return Boolean(c.watched ?? c.vital);
}

function containerState(c: ContainerItem): string {
  return (c.state || c.status || "").toLowerCase();
}

/** Which lifecycle / mutate actions make sense for the current Docker state. */
export function actionsForState(state: string): {
  start: boolean;
  stop: boolean;
  restart: boolean;
  pause: boolean;
  unpause: boolean;
  kill: boolean;
  update: boolean;
  remove: boolean;
} {
  const running = state === "running";
  const paused = state === "paused";
  const restarting = state === "restarting";
  const stopped =
    state === "exited" || state === "created" || state === "dead" || !state;
  const removing = state === "removing";

  return {
    start: !removing && (stopped || (!running && !paused && !restarting)),
    stop: running || paused || restarting,
    restart: !removing && (running || paused || restarting || stopped),
    pause: running,
    unpause: paused,
    kill: running || paused || restarting,
    update: !removing,
    remove: !removing,
  };
}

export function ContainerDrawer({
  container,
  open,
  onClose,
  actionsEnabled,
  onChanged,
  initialStep = "detail",
}: {
  container: ContainerItem | null;
  open: boolean;
  onClose: () => void;
  actionsEnabled: boolean;
  onChanged: () => void;
  initialStep?: Step;
}) {
  const [step, setStep] = useState<Step>("detail");
  const [understand, setUnderstand] = useState(false);
  const [removeContainer, setRemoveContainer] = useState(true);
  const [removeImage, setRemoveImage] = useState(false);
  const [removeVolumes, setRemoveVolumes] = useState(false);
  const [job, setJob] = useState<ActionJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [logs, setLogs] = useState<string>("");
  const [logsError, setLogsError] = useState<string | null>(null);
  const [logsLoading, setLogsLoading] = useState(false);

  const loadLogs = useCallback(async (id: string) => {
    setLogsLoading(true);
    setLogsError(null);
    try {
      const res = await fetchContainerLogs(id, LOG_TAIL);
      if (res.ok) {
        setLogs(res.logs || "");
        setLogsError(null);
      } else {
        setLogs("");
        setLogsError(res.error || "Logs unavailable");
      }
    } catch (e) {
      setLogs("");
      setLogsError(e instanceof Error ? e.message : String(e));
    } finally {
      setLogsLoading(false);
    }
  }, []);

  useEffect(() => {
    if (open) {
      setStep(initialStep);
      setUnderstand(false);
      setRemoveContainer(true);
      setRemoveImage(false);
      setRemoveVolumes(false);
      setJob(null);
      setError(null);
      setBusy(false);
      setLogs("");
      setLogsError(null);
    }
  }, [open, container?.container_id, initialStep]);

  useEffect(() => {
    if (!open || !container?.container_id) return;
    void loadLogs(container.container_id);
  }, [open, container?.container_id, loadLogs]);

  const pollJob = useCallback(
    async (jobId: string) => {
      const j = await fetchJob(jobId);
      setJob(j);
      if (j.status === "done" || j.status === "error") {
        setBusy(false);
        if (j.status === "done") onChanged();
        return;
      }
      window.setTimeout(() => void pollJob(jobId), 1200);
    },
    [onChanged],
  );

  if (!container) return null;

  const sec = container.security;
  const isCompose = Boolean(container.compose_project && container.compose_service);
  const starred = isStarred(container);
  const networks = container.networks || [];
  const ports = container.published_ports || [];
  const mounts = container.mounts || [];
  const state = containerState(container);
  const avail = actionsForState(state);

  function openConfirm(next: ConfirmStep) {
    setUnderstand(false);
    setError(null);
    setStep(next);
  }

  async function toggleStar() {
    setError(null);
    try {
      await setWatched({
        watched_key: container!.watched_key || container!.vital_key || undefined,
        name: container!.name,
        compose_project: container!.compose_project,
        compose_service: container!.compose_service,
        watched: !starred,
      });
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function runJob(
    starter: (id: string) => Promise<{ ok: boolean; job: ActionJob }>,
  ) {
    setBusy(true);
    setError(null);
    try {
      const res = await starter(container!.container_id);
      setJob(res.job);
      setStep("detail");
      void pollJob(res.job.id);
    } catch (e) {
      setBusy(false);
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  async function runUpdate() {
    if (!understand || !isCompose) return;
    await runJob(startUpdate);
  }

  async function runStart() {
    await runJob(startStart);
  }

  async function runStop() {
    if (!understand) return;
    await runJob(startStop);
  }

  async function runRestart() {
    if (!understand) return;
    await runJob(startRestart);
  }

  async function runPause() {
    await runJob(startPause);
  }

  async function runUnpause() {
    await runJob(startUnpause);
  }

  async function runKill() {
    if (!understand) return;
    await runJob(startKill);
  }

  async function runTeardown() {
    if (!understand) return;
    setBusy(true);
    setError(null);
    try {
      const res = await startTeardown(container!.container_id, {
        remove_container: removeContainer,
        remove_image: removeImage,
        remove_volumes: removeVolumes,
      });
      setJob(res.job);
      setStep("detail");
      void pollJob(res.job.id);
    } catch (e) {
      setBusy(false);
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  const titleByStep: Record<ConfirmStep, string> = {
    "confirm-start": `Start ${container.name}?`,
    "confirm-stop": `Stop ${container.name}?`,
    "confirm-restart": `Restart ${container.name}?`,
    "confirm-pause": `Pause ${container.name}?`,
    "confirm-unpause": `Unpause ${container.name}?`,
    "confirm-kill": `Kill ${container.name}?`,
    "confirm-update": `Update ${container.name}?`,
    "confirm-teardown": `Remove ${container.name}?`,
  };
  const title = step === "detail" ? container.name : titleByStep[step];

  return (
    <Drawer open={open} title={title} onClose={onClose}>
      {step === "detail" ? (
        <>
          <section className="drawer-section">
            <h3 className="drawer-section-title">Overview</h3>
            <dl className="detail-defs">
              <div className="detail-row">
                <dt>Status</dt>
                <dd>{container.state || container.status}</dd>
              </div>
              <div className="detail-row">
                <dt>Health</dt>
                <dd>{container.health || "—"}</dd>
              </div>
              <div className="detail-row">
                <dt>Uptime</dt>
                <dd className="mono">{formatUptime(container.uptime_seconds)}</dd>
              </div>
              <div className="detail-row">
                <dt>Restarts</dt>
                <dd className="mono">{container.restart_count ?? 0}</dd>
              </div>
              <div className="detail-row">
                <dt>Created</dt>
                <dd className="mono">{formatWhen(container.created_at)}</dd>
              </div>
              <div className="detail-row">
                <dt>Started</dt>
                <dd className="mono">{formatWhen(container.started_at)}</dd>
              </div>
              <div className="detail-row">
                <dt>Image</dt>
                <dd>
                  <div className="mono wrap">{container.image}</div>
                  <div className="quiet mono drawer-id-line">
                    id {shortId(container.image_id)}
                    {container.local_digest
                      ? ` · digest ${shortId(container.local_digest, 16)}`
                      : ""}
                  </div>
                  {container.update_available ? (
                    <div className="update-jump-note">
                      {container.update_from && container.update_to ? (
                        <>
                          <span className="mono">{container.update_from}</span>
                          {" → "}
                          <span className="mono">{container.update_to}</span>
                          {container.update_bump ? (
                            <>
                              {" · "}
                              <span className={`badge-bump bump-${container.update_bump}`}>
                                {container.update_bump}
                              </span>
                            </>
                          ) : (
                            <span className="quiet"> · same version, new digest</span>
                          )}
                        </>
                      ) : (
                        <>
                          <span className="badge-update">update</span>
                          {container.update_bump ? (
                            <span className={`badge-bump bump-${container.update_bump}`}>
                              {container.update_bump}
                            </span>
                          ) : null}
                        </>
                      )}
                    </div>
                  ) : null}
                </dd>
              </div>
              {container.access_url ? (
                <div className="detail-row">
                  <dt>Web</dt>
                  <dd>
                    <a href={container.access_url} target="_blank" rel="noopener noreferrer">
                      {container.access_url}
                    </a>
                  </dd>
                </div>
              ) : null}
            </dl>
          </section>

          <section className="drawer-section">
            <h3 className="drawer-section-title">Domains</h3>
            {(() => {
              const entries = container.networking?.entries || [];
              const seen = new Set(
                entries.map((e) => (e.hostname || "").toLowerCase().replace(/\.$/, "")),
              );
              const dnsOnly = (container.pihole_hostnames || []).filter((h) => {
                const n = h.toLowerCase().replace(/\.$/, "");
                return n && !seen.has(n);
              });
              if (!entries.length && !dnsOnly.length) {
                return <div className="quiet">—</div>;
              }
              return (
                <ul className="domains-list">
                  {entries.map((e, i) => (
                    <li key={`net-${e.hostname}-${e.upstream}-${i}`}>
                      <span className="mono">{e.upstream || "—"}</span>
                      <span className="quiet"> → </span>
                      <span className="mono wrap">{e.hostname}</span>
                      {e.in_dns ? (
                        <span className="badge-dns" title="In Pi-hole Local DNS">
                          DNS
                        </span>
                      ) : null}
                    </li>
                  ))}
                  {dnsOnly.map((h) => (
                    <li key={`dns-${h}`}>
                      <span className="quiet">—</span>
                      <span className="quiet"> → </span>
                      <span className="mono wrap">{h}</span>
                      <span className="badge-dns" title="In Pi-hole Local DNS">
                        DNS
                      </span>
                    </li>
                  ))}
                </ul>
              );
            })()}
          </section>

          {container.networking?.mapped &&
          (container.networking.entries || []).length > 0 ? (
            <section className="drawer-section">
              <h3 className="drawer-section-title">Networking</h3>
              <ul className="networking-list">
                {(container.networking.entries || []).map((e, i) => (
                  <li key={`${e.hostname}-${e.upstream}-${i}`}>
                    <span className="mono">{e.hostname}</span>
                    <span className="quiet">
                      {" "}
                      → via {e.proxy || "proxy"}
                      {e.source ? ` (${e.source})` : ""} →{" "}
                    </span>
                    <span className="mono">{e.upstream || "—"}</span>
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          <section className="drawer-section">
            <h3 className="drawer-section-title">Compose</h3>
            {isCompose ? (
              <dl className="detail-defs">
                <div className="detail-row">
                  <dt>Service</dt>
                  <dd className="mono wrap">
                    {container.compose_project} / {container.compose_service}
                  </dd>
                </div>
                {container.compose_workdir ? (
                  <div className="detail-row">
                    <dt>Workdir</dt>
                    <dd className="mono wrap">{container.compose_workdir}</dd>
                  </div>
                ) : null}
              </dl>
            ) : (
              <div className="quiet">Standalone</div>
            )}
          </section>

          <section className="drawer-section">
            <h3 className="drawer-section-title">Networks</h3>
            {networks.length > 0 ? (
              <div className="drawer-chip-row">
                {networks.map((n) => (
                  <span key={n} className="drawer-chip mono">
                    {n}
                  </span>
                ))}
              </div>
            ) : (
              <div className="quiet">None</div>
            )}
          </section>

          <section className="drawer-section">
            <h3 className="drawer-section-title">Published ports</h3>
            {ports.length > 0 ? (
              <ul className="drawer-list">
                {ports.map((p) => (
                  <li key={p} className="mono">
                    {p}
                  </li>
                ))}
              </ul>
            ) : (
              <div className="quiet">None</div>
            )}
          </section>

          <section className="drawer-section">
            <h3 className="drawer-section-title">Mounts</h3>
            {mounts.length > 0 ? (
              <div className="drawer-table-wrap">
                <table className="drawer-table">
                  <thead>
                    <tr>
                      <th>Type</th>
                      <th>Source</th>
                      <th>Destination</th>
                      <th>Mode</th>
                    </tr>
                  </thead>
                  <tbody>
                    {mounts.map((m) => (
                      <tr key={`${m.type}:${m.source}:${m.destination}`}>
                        <td className="quiet">{m.type}</td>
                        <td className="mono">{m.source || "—"}</td>
                        <td className="mono">{m.destination || "—"}</td>
                        <td className="quiet">{m.mode || "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="quiet">None</div>
            )}
          </section>

          <div className="detail-actions">
            <button
              type="button"
              className={starred ? "btn btn-star on" : "btn btn-star"}
              onClick={() => void toggleStar()}
            >
              {starred ? "★ Starred" : "☆ Star"}
            </button>
            {actionsEnabled ? (
              <>
                {avail.start ? (
                  <button
                    type="button"
                    className="btn"
                    disabled={busy}
                    onClick={() => openConfirm("confirm-start")}
                  >
                    Start
                  </button>
                ) : null}
                {avail.stop ? (
                  <button
                    type="button"
                    className="btn"
                    disabled={busy}
                    onClick={() => openConfirm("confirm-stop")}
                  >
                    Stop
                  </button>
                ) : null}
                {avail.restart ? (
                  <button
                    type="button"
                    className="btn"
                    disabled={busy}
                    onClick={() => openConfirm("confirm-restart")}
                  >
                    Restart
                  </button>
                ) : null}
                {avail.pause ? (
                  <button
                    type="button"
                    className="btn"
                    disabled={busy}
                    onClick={() => openConfirm("confirm-pause")}
                  >
                    Pause
                  </button>
                ) : null}
                {avail.unpause ? (
                  <button
                    type="button"
                    className="btn"
                    disabled={busy}
                    onClick={() => openConfirm("confirm-unpause")}
                  >
                    Unpause
                  </button>
                ) : null}
                {avail.kill ? (
                  <button
                    type="button"
                    className="btn btn-danger"
                    disabled={busy}
                    onClick={() => openConfirm("confirm-kill")}
                  >
                    Kill
                  </button>
                ) : null}
                {avail.update ? (
                  <button
                    type="button"
                    className="btn"
                    disabled={busy || !isCompose}
                    title={isCompose ? "Update service" : "Compose only"}
                    onClick={() => {
                      if (!isCompose) return;
                      openConfirm("confirm-update");
                    }}
                  >
                    Update
                  </button>
                ) : null}
                {avail.remove ? (
                  <button
                    type="button"
                    className="btn btn-danger"
                    disabled={busy}
                    onClick={() => openConfirm("confirm-teardown")}
                  >
                    Remove
                  </button>
                ) : null}
              </>
            ) : (
              <span className="quiet">Actions off</span>
            )}
          </div>

          <section className="drawer-section">
            <div className="drawer-section-head">
              <h3 className="drawer-section-title">Recent logs</h3>
              <button
                type="button"
                className="btn btn-sm"
                disabled={logsLoading}
                onClick={() => void loadLogs(container.container_id)}
              >
                {logsLoading ? "Loading…" : "Refresh"}
              </button>
            </div>
            {logsError ? (
              <div className="quiet">Logs unavailable — {logsError}</div>
            ) : (
              <pre className="drawer-logs">{logs || (logsLoading ? "Loading…" : "(empty)")}</pre>
            )}
          </section>

          {sec?.enabled ? (
            <section className="drawer-section security-block">
              <h3 className="drawer-section-title">Security</h3>
              {sec.trivy_enabled !== false ? (
                <>
                  <h4>Image (Trivy)</h4>
                  <div className="quiet">
                    {sec.image_scan_status || "—"}
                    {sec.scanned_at
                      ? ` · ${new Date(sec.scanned_at).toLocaleString()}`
                      : ""}
                    {sec.image_scan_status === "unavailable" ||
                    sec.image_scan_status === "error"
                      ? ` — ${sec.scan_error || "unavailable"}`
                      : ""}
                  </div>
                  <div className="sev-row">
                    {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((s) => (
                      <span key={s} className={`sev-chip sev-${s.toLowerCase()}`}>
                        {s}:{" "}
                        {sec.image_severity?.[s] ??
                          (!sec.scm ? sec.severity?.[s] : undefined) ??
                          0}
                      </span>
                    ))}
                  </div>
                  {(sec.top_findings || []).filter(
                    (f) => !f.source || f.source === "trivy",
                  ).length > 0 ? (
                    <ul className="finding-list">
                      {(sec.top_findings || [])
                        .filter((f) => !f.source || f.source === "trivy")
                        .map((f) => (
                          <li key={(f.source || "") + f.id + (f.pkg || "")}>
                            <span className="mono">{f.severity}</span> {f.id}
                            {f.pkg ? ` · ${f.pkg}` : ""}
                          </li>
                        ))}
                    </ul>
                  ) : null}
                </>
              ) : null}
              {sec.scm && sec.opensca_enabled !== false ? (
                <>
                  <h4>Repo (OpenSCA)</h4>
                  <div className="quiet">
                    {sec.scm.status || "—"}
                    {sec.scm.repo_url
                      ? ` · ${sec.scm.repo_url}`
                      : " · no repo URL"}
                    {sec.scm.commit_sha
                      ? ` @ ${sec.scm.commit_sha.slice(0, 7)}`
                      : ""}
                    {sec.scm.status === "unavailable" ||
                    sec.scm.status === "error"
                      ? ` — ${sec.scm.error || "unavailable"}`
                      : ""}
                  </div>
                  {(sec.scm.top_findings || []).length > 0 ? (
                    <ul className="finding-list">
                      {sec.scm.top_findings!.map((f) => (
                        <li key={"scm" + f.id + (f.pkg || "")}>
                          <span className="mono">{f.severity}</span> {f.id}
                          {f.pkg ? ` · ${f.pkg}` : ""}
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </>
              ) : null}
              {(sec.posture || []).length > 0 ? (
                <>
                  <h4>Posture</h4>
                  <ul className="finding-list">
                    {sec.posture!.map((f) => (
                      <li key={f.id}>
                        <span className="mono">{f.severity}</span> {f.title}
                        {f.detail ? (
                          <div className="quiet">{f.detail}</div>
                        ) : null}
                      </li>
                    ))}
                  </ul>
                </>
              ) : null}
            </section>
          ) : null}

          {job ? (
            <div className="job-box">
              <div className="detail-label">
                Job {job.status}
                {job.kind ? ` (${job.kind})` : ""}
                {job.message ? ` — ${job.message}` : ""}
              </div>
              {job.error ? <div className="error-inline">{job.error}</div> : null}
              <ul className="job-log">
                {(job.logs || []).map((l, i) => (
                  <li key={i} className="mono">
                    {l.message}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
          {error ? <div className="error-inline">{error}</div> : null}
        </>
      ) : null}

      {step === "confirm-start" ? (
        <div className="confirm-flow">
          <p>
            Start <code className="mono">{container.name}</code>?
          </p>
          {error ? <div className="error-inline">{error}</div> : null}
          <div className="detail-actions">
            <button type="button" className="btn" onClick={() => setStep("detail")}>
              Back
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy}
              onClick={() => void runStart()}
            >
              Start
            </button>
          </div>
        </div>
      ) : null}

      {step === "confirm-stop" ? (
        <div className="confirm-flow">
          <p>
            Stop <code className="mono">{container.name}</code>? Graceful stop
            (SIGTERM, then timeout).
          </p>
          <label className="check-row">
            <input
              type="checkbox"
              checked={understand}
              onChange={(e) => setUnderstand(e.target.checked)}
            />
            I understand this will interrupt the container.
          </label>
          {error ? <div className="error-inline">{error}</div> : null}
          <div className="detail-actions">
            <button type="button" className="btn" onClick={() => setStep("detail")}>
              Back
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={!understand || busy}
              onClick={() => void runStop()}
            >
              Stop
            </button>
          </div>
        </div>
      ) : null}

      {step === "confirm-restart" ? (
        <div className="confirm-flow">
          <p>
            Restart <code className="mono">{container.name}</code>?
          </p>
          <label className="check-row">
            <input
              type="checkbox"
              checked={understand}
              onChange={(e) => setUnderstand(e.target.checked)}
            />
            I understand this will briefly interrupt the container.
          </label>
          {error ? <div className="error-inline">{error}</div> : null}
          <div className="detail-actions">
            <button type="button" className="btn" onClick={() => setStep("detail")}>
              Back
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={!understand || busy}
              onClick={() => void runRestart()}
            >
              Restart
            </button>
          </div>
        </div>
      ) : null}

      {step === "confirm-pause" ? (
        <div className="confirm-flow">
          <p>
            Pause <code className="mono">{container.name}</code>? Freezes all
            processes (cgroup freezer).
          </p>
          {error ? <div className="error-inline">{error}</div> : null}
          <div className="detail-actions">
            <button type="button" className="btn" onClick={() => setStep("detail")}>
              Back
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy}
              onClick={() => void runPause()}
            >
              Pause
            </button>
          </div>
        </div>
      ) : null}

      {step === "confirm-unpause" ? (
        <div className="confirm-flow">
          <p>
            Unpause <code className="mono">{container.name}</code>?
          </p>
          {error ? <div className="error-inline">{error}</div> : null}
          <div className="detail-actions">
            <button type="button" className="btn" onClick={() => setStep("detail")}>
              Back
            </button>
            <button
              type="button"
              className="btn btn-primary"
              disabled={busy}
              onClick={() => void runUnpause()}
            >
              Unpause
            </button>
          </div>
        </div>
      ) : null}

      {step === "confirm-kill" ? (
        <div className="confirm-flow">
          <p>
            Force-kill <code className="mono">{container.name}</code> with
            SIGKILL? Prefer Stop when a graceful shutdown is enough.
          </p>
          <label className="check-row warn-check">
            <input
              type="checkbox"
              checked={understand}
              onChange={(e) => setUnderstand(e.target.checked)}
            />
            I understand this skips graceful shutdown and may corrupt data.
          </label>
          {error ? <div className="error-inline">{error}</div> : null}
          <div className="detail-actions">
            <button type="button" className="btn" onClick={() => setStep("detail")}>
              Back
            </button>
            <button
              type="button"
              className="btn btn-danger"
              disabled={!understand || busy}
              onClick={() => void runKill()}
            >
              Kill
            </button>
          </div>
        </div>
      ) : null}

      {step === "confirm-update" ? (
        <div className="confirm-flow">
          {isCompose ? (
            <>
              <p>
                Update{" "}
                <code className="mono">
                  {container.compose_project}/{container.compose_service}
                </code>
                ?
              </p>
              {container.update_available ? (
                <p className="update-jump-note">
                  {container.update_from && container.update_to ? (
                    <>
                      <span className="mono">{container.update_from}</span>
                      {" → "}
                      <span className="mono">{container.update_to}</span>
                      {container.update_bump ? (
                        <>
                          {" · "}
                          <span className={`badge-bump bump-${container.update_bump}`}>
                            {container.update_bump}
                          </span>
                        </>
                      ) : (
                        <span className="quiet"> · same version, new digest</span>
                      )}
                    </>
                  ) : container.update_bump ? (
                    <>
                      Jump{" "}
                      <span className={`badge-bump bump-${container.update_bump}`}>
                        {container.update_bump}
                      </span>
                    </>
                  ) : (
                    <span className="quiet">Newer remote digest for this image tag.</span>
                  )}
                </p>
              ) : null}
              <label className="check-row">
                <input
                  type="checkbox"
                  checked={understand}
                  onChange={(e) => setUnderstand(e.target.checked)}
                />
                I understand this may restart the service.
              </label>
              {error ? <div className="error-inline">{error}</div> : null}
              <div className="detail-actions">
                <button type="button" className="btn" onClick={() => setStep("detail")}>
                  Back
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  disabled={!understand || busy}
                  onClick={() => void runUpdate()}
                >
                  Update
                </button>
              </div>
            </>
          ) : (
            <>
              <p>Compose only.</p>
              <div className="detail-actions">
                <button type="button" className="btn" onClick={() => setStep("detail")}>
                  Back
                </button>
              </div>
            </>
          )}
        </div>
      ) : null}

      {step === "confirm-teardown" ? (
        <div className="confirm-flow">
          <p>Remove this container? This cannot be undone here.</p>
          <label className="check-row">
            <input
              type="checkbox"
              checked={removeContainer}
              onChange={(e) => setRemoveContainer(e.target.checked)}
            />
            Remove container
          </label>
          <label className="check-row">
            <input
              type="checkbox"
              checked={removeImage}
              onChange={(e) => setRemoveImage(e.target.checked)}
            />
            Remove image
          </label>
          <label className="check-row">
            <input
              type="checkbox"
              checked={removeVolumes}
              onChange={(e) => setRemoveVolumes(e.target.checked)}
            />
            Remove volumes
          </label>
          <label className="check-row warn-check">
            <input
              type="checkbox"
              checked={understand}
              onChange={(e) => setUnderstand(e.target.checked)}
            />
            I understand this may delete data.
          </label>
          {error ? <div className="error-inline">{error}</div> : null}
          <div className="detail-actions">
            <button type="button" className="btn" onClick={() => setStep("detail")}>
              Back
            </button>
            <button
              type="button"
              className="btn btn-danger"
              disabled={!understand || busy || (!removeContainer && !removeImage)}
              onClick={() => void runTeardown()}
            >
              Remove
            </button>
          </div>
        </div>
      ) : null}
    </Drawer>
  );
}

/** @deprecated Prefer ContainerDrawer */
export const ContainerModal = ContainerDrawer;
