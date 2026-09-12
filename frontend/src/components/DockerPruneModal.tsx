import { useCallback, useEffect, useState } from "react";
import {
  fetchJob,
  startDockerPrune,
  type ActionJob,
  type DockerPruneOptions,
} from "../api";
import { Modal } from "./Modal";

const SAFE: DockerPruneOptions = {
  containers: true,
  images: true,
  images_all_unused: false,
  build_cache: true,
  build_cache_all: false,
  volumes: false,
  networks: false,
};

const AGGRESSIVE: DockerPruneOptions = {
  containers: true,
  images: true,
  images_all_unused: true,
  build_cache: true,
  build_cache_all: true,
  volumes: false,
  networks: true,
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

export function DockerPruneModal({
  open,
  onClose,
  onDone,
}: {
  open: boolean;
  onClose: () => void;
  onDone: () => void;
}) {
  const [opts, setOpts] = useState<DockerPruneOptions>({ ...SAFE });
  const [understand, setUnderstand] = useState(false);
  const [volumesOk, setVolumesOk] = useState(false);
  const [job, setJob] = useState<ActionJob | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (open) {
      setOpts({ ...SAFE });
      setUnderstand(false);
      setVolumesOk(false);
      setJob(null);
      setError(null);
      setBusy(false);
    }
  }, [open]);

  const pollJob = useCallback(
    async (jobId: string) => {
      const j = await fetchJob(jobId);
      setJob(j);
      if (j.status === "done" || j.status === "error") {
        setBusy(false);
        if (j.status === "done") onDone();
        return;
      }
      window.setTimeout(() => void pollJob(jobId), 1200);
    },
    [onDone],
  );

  function setFlag<K extends keyof DockerPruneOptions>(key: K, value: DockerPruneOptions[K]) {
    setOpts((prev) => {
      const next = { ...prev, [key]: value };
      if (key === "images" && !value) next.images_all_unused = false;
      if (key === "build_cache" && !value) next.build_cache_all = false;
      return next;
    });
    if (key === "volumes" && !value) setVolumesOk(false);
  }

  const anything =
    opts.containers ||
    opts.images ||
    opts.build_cache ||
    opts.volumes ||
    opts.networks;

  const canRun =
    understand &&
    anything &&
    (!opts.volumes || volumesOk) &&
    !busy;

  async function runPrune() {
    if (!canRun) return;
    setBusy(true);
    setError(null);
    try {
      const res = await startDockerPrune(opts);
      setJob(res.job);
      void pollJob(res.job.id);
    } catch (e) {
      setBusy(false);
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <Modal open={open} title="Reclaim Docker disk" onClose={onClose} wide>
      <div className="confirm-flow">
        <p>
          Remove unused Docker data. Stopped containers, dangling images, and
          build cache are usually safe. Unused volumes can delete data.
        </p>

        <div className="prune-presets">
          <button
            type="button"
            className="btn"
            disabled={busy}
            onClick={() => {
              setOpts({ ...SAFE });
              setVolumesOk(false);
            }}
          >
            Safe reclaim
          </button>
          <button
            type="button"
            className="btn"
            disabled={busy}
            onClick={() => {
              setOpts({ ...AGGRESSIVE });
              setVolumesOk(false);
            }}
          >
            Aggressive
          </button>
        </div>

        <label className="check-row">
          <input
            type="checkbox"
            checked={opts.containers}
            disabled={busy}
            onChange={(e) => setFlag("containers", e.target.checked)}
          />
          Stopped containers
        </label>
        <label className="check-row">
          <input
            type="checkbox"
            checked={opts.images}
            disabled={busy}
            onChange={(e) => setFlag("images", e.target.checked)}
          />
          Unused images
          {opts.images ? (
            <span className="quiet">
              {" "}
              ({opts.images_all_unused ? "all unused" : "dangling only"})
            </span>
          ) : null}
        </label>
        {opts.images ? (
          <label className="check-row check-indent">
            <input
              type="checkbox"
              checked={opts.images_all_unused}
              disabled={busy}
              onChange={(e) => setFlag("images_all_unused", e.target.checked)}
            />
            Include all unused tagged images
          </label>
        ) : null}
        <label className="check-row">
          <input
            type="checkbox"
            checked={opts.build_cache}
            disabled={busy}
            onChange={(e) => setFlag("build_cache", e.target.checked)}
          />
          Build cache
        </label>
        {opts.build_cache ? (
          <label className="check-row check-indent">
            <input
              type="checkbox"
              checked={opts.build_cache_all}
              disabled={busy}
              onChange={(e) => setFlag("build_cache_all", e.target.checked)}
            />
            Remove all build cache
          </label>
        ) : null}
        <label className="check-row">
          <input
            type="checkbox"
            checked={opts.networks}
            disabled={busy}
            onChange={(e) => setFlag("networks", e.target.checked)}
          />
          Unused networks
        </label>
        <label className="check-row warn-check">
          <input
            type="checkbox"
            checked={opts.volumes}
            disabled={busy}
            onChange={(e) => setFlag("volumes", e.target.checked)}
          />
          Unused volumes (risky — may delete data)
        </label>

        {opts.volumes ? (
          <label className="check-row warn-check">
            <input
              type="checkbox"
              checked={volumesOk}
              disabled={busy}
              onChange={(e) => setVolumesOk(e.target.checked)}
            />
            I understand unused volumes may permanently delete data.
          </label>
        ) : null}

        <label className="check-row warn-check">
          <input
            type="checkbox"
            checked={understand}
            disabled={busy}
            onChange={(e) => setUnderstand(e.target.checked)}
          />
          I understand this cannot be undone from Homelab Watcher.
        </label>

        {job ? (
          <div className="job-box">
            <div className="detail-label">
              Job {job.status}
              {job.message ? ` — ${job.message}` : ""}
              {job.status === "done" && job.space_reclaimed_bytes != null
                ? ` · ${formatBytes(job.space_reclaimed_bytes)}`
                : ""}
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

        <div className="detail-actions">
          <button type="button" className="btn" onClick={onClose}>
            {job?.status === "done" ? "Close" : "Cancel"}
          </button>
          <button
            type="button"
            className="btn btn-danger"
            disabled={!canRun}
            onClick={() => void runPrune()}
          >
            Reclaim
          </button>
        </div>
      </div>
    </Modal>
  );
}
