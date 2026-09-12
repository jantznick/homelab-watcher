"""
Container lifecycle actions, Compose-only update, and tear-down.

Lifecycle (stop / start / restart):
  Prefer `docker compose … stop|start|restart <service>` when Compose-managed
  and the project directory is visible; otherwise Docker Engine API on the
  container. Pause / unpause / kill use the Engine API (compose kill when
  project dir is available).

Update is Compose-only:
  docker compose -p <project> [-f ...] pull <service>
  docker compose -p <project> [-f ...] up -d <service>

Compose membership comes from labels (project, service, working_dir, config_files).
Paths are resolved on the Watcher host (or via HOST_ROOT remapping, e.g. /host).

Standalone (non-Compose) containers cannot be updated — no inspect/recreate path.
Tear-down prefers Compose stop/rm for labeled services; otherwise Docker API remove.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from docker.errors import APIError, ImageNotFound, NotFound

from app.docker_client import _client

logger = logging.getLogger(__name__)

# In-memory job status for UI polling (single-host app)
_jobs: dict[str, dict[str, Any]] = {}
_jobs_lock = threading.Lock()

COMPOSE_PATH_HELP = (
    "Compose update / stop / start / restart need access to the compose project "
    "directory inside Homelab Watcher. Mount your stacks root into the Watcher "
    "container at the same host path (e.g. /home/user/stacks:/home/user/stacks:ro), "
    "or rely on the existing /:/host:ro mount so paths resolve under HOST_ROOT. "
    "See README → Compose-first updates."
)

# States where docker start / compose start apply
_STOPPED_STATES = frozenset({"exited", "created", "dead"})
_RUNNING_STATES = frozenset({"running"})
_PAUSED_STATES = frozenset({"paused"})
_ACTIVE_STATES = frozenset({"running", "paused", "restarting"})


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_job(job_id: str) -> dict[str, Any] | None:
    with _jobs_lock:
        job = _jobs.get(job_id)
        return dict(job) if job else None


def _set_job(job_id: str, **fields: Any) -> None:
    with _jobs_lock:
        cur = _jobs.get(job_id) or {"id": job_id, "created_at": _utc()}
        cur.update(fields)
        cur["updated_at"] = _utc()
        _jobs[job_id] = cur


def _log(job_id: str, message: str) -> None:
    with _jobs_lock:
        cur = _jobs.get(job_id) or {"id": job_id, "logs": []}
        logs = list(cur.get("logs") or [])
        logs.append({"at": _utc(), "message": message})
        cur["logs"] = logs[-80:]
        cur["message"] = message
        cur["updated_at"] = _utc()
        _jobs[job_id] = cur
    logger.info("[%s] %s", job_id, message)


def _host_root() -> str:
    return (os.environ.get("HOST_ROOT") or "/host").rstrip("/") or "/host"


def resolve_visible_path(path: str) -> str | None:
    """
    Map a host path to one visible inside the Watcher container.

    Tries the path as-is (same-path bind mount), then HOST_ROOT + path
    (default /host when compose mounts /:/host:ro).
    """
    if not path:
        return None
    path = path.strip()
    if not path:
        return None
    if os.path.exists(path):
        return path
    if path.startswith("/"):
        candidate = f"{_host_root()}{path}"
        if os.path.exists(candidate):
            return candidate
    return None


@dataclass(frozen=True)
class ComposeTarget:
    project: str
    service: str
    working_dir: str
    config_files: list[str]
    # Original host paths from labels (for error messages)
    label_workdir: str
    label_config_files: list[str]


def compose_labels_from_attrs(attrs: dict[str, Any]) -> dict[str, str]:
    config = attrs.get("Config") or {}
    labels = config.get("Labels") or {}
    return {str(k): str(v) for k, v in labels.items() if v is not None}


def parse_compose_labels(labels: dict[str, str]) -> tuple[str, str, str, list[str]] | None:
    project = (labels.get("com.docker.compose.project") or "").strip()
    service = (labels.get("com.docker.compose.service") or "").strip()
    if not project or not service:
        return None
    workdir = (labels.get("com.docker.compose.project.working_dir") or "").strip()
    raw_files = (
        labels.get("com.docker.compose.project.config_files")
        or labels.get("com.docker.compose.project.config_file")
        or ""
    ).strip()
    files = [p.strip() for p in raw_files.split(",") if p.strip()]
    return project, service, workdir, files


def resolve_compose_target(labels: dict[str, str]) -> ComposeTarget:
    parsed = parse_compose_labels(labels)
    if not parsed:
        raise RuntimeError(
            "This container is not a Docker Compose service (missing "
            "com.docker.compose.project / com.docker.compose.service labels). "
            "Update requires Compose-managed containers; lifecycle actions on "
            "standalone containers use the Docker Engine API instead."
        )
    project, service, workdir, files = parsed
    if not workdir:
        raise RuntimeError(
            "Compose labels are present but com.docker.compose.project.working_dir "
            f"is missing. {COMPOSE_PATH_HELP}"
        )

    resolved_wd = resolve_visible_path(workdir)
    if not resolved_wd or not os.path.isdir(resolved_wd):
        raise RuntimeError(
            f"Compose project directory is not visible to Homelab Watcher: "
            f"{workdir!r}. {COMPOSE_PATH_HELP}"
        )

    resolved_files: list[str] = []
    missing: list[str] = []
    for f in files:
        rf = resolve_visible_path(f)
        if rf and os.path.isfile(rf):
            resolved_files.append(rf)
        else:
            missing.append(f)

    if files and missing:
        raise RuntimeError(
            "Compose config file(s) not visible to Homelab Watcher: "
            + ", ".join(repr(m) for m in missing)
            + f". {COMPOSE_PATH_HELP}"
        )

    # If labels omitted config_files, compose will look for default names in cwd.
    return ComposeTarget(
        project=project,
        service=service,
        working_dir=resolved_wd,
        config_files=resolved_files,
        label_workdir=workdir,
        label_config_files=files,
    )


def _docker_compose_available() -> str | None:
    """Return path to docker binary if `docker compose` works, else None."""
    docker_bin = shutil.which("docker")
    if not docker_bin:
        return None
    try:
        proc = subprocess.run(
            [docker_bin, "compose", "version"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        if proc.returncode == 0:
            return docker_bin
    except Exception:
        return None
    return None


def _compose_base_cmd(docker_bin: str, target: ComposeTarget) -> list[str]:
    cmd = [docker_bin, "compose", "-p", target.project]
    for f in target.config_files:
        cmd.extend(["-f", f])
    return cmd


def _run_compose(
    job_id: str,
    docker_bin: str,
    target: ComposeTarget,
    args: list[str],
    *,
    status: str,
) -> None:
    cmd = _compose_base_cmd(docker_bin, target) + args
    _set_job(job_id, status=status, message=" ".join(args))
    _log(job_id, f"$ {' '.join(cmd)}  (cwd={target.working_dir})")
    try:
        proc = subprocess.run(
            cmd,
            cwd=target.working_dir,
            capture_output=True,
            text=True,
            timeout=600,
            check=False,
            env={**os.environ},
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Compose command timed out: {' '.join(args)}") from exc
    except FileNotFoundError as exc:
        raise RuntimeError(
            "docker CLI not found in the Homelab Watcher image. Rebuild the image "
            "so the Docker CLI and Compose plugin are installed."
        ) from exc

    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    for line in (out.splitlines() + err.splitlines()):
        line = line.strip()
        if line:
            _log(job_id, line)
    if proc.returncode != 0:
        raise RuntimeError(
            f"docker compose {' '.join(args)} failed (exit {proc.returncode})"
            + (f": {err or out}" if (err or out) else "")
        )


def _get_container(client: Any, container_ref: str) -> Any:
    try:
        return client.containers.get(container_ref)
    except NotFound:
        matches = [
            c
            for c in client.containers.list(all=True)
            if c.id.startswith(container_ref)
            or (c.name or "").lstrip("/") == container_ref
        ]
        if not matches:
            raise NotFound(f"Container {container_ref} not found")
        return matches[0]


def _container_status(container: Any) -> str:
    return (container.status or "").lower()


def _compose_cli_for_lifecycle(
    labels: dict[str, str],
) -> tuple[str, ComposeTarget] | None:
    """
    Soft Compose resolve for stop/start/restart/kill.
    Returns None when not Compose-managed or project dir / CLI unavailable
    (caller falls back to Engine API).
    """
    if not parse_compose_labels(labels):
        return None
    try:
        target = resolve_compose_target(labels)
    except RuntimeError:
        return None
    docker_bin = _docker_compose_available()
    if not docker_bin:
        return None
    return docker_bin, target


def _log_compose_target(job_id: str, target: ComposeTarget, name: str, status: str) -> None:
    _log(
        job_id,
        f"Compose service {target.project}/{target.service} "
        f"(container {name}, state={status})",
    )
    _log(job_id, f"Project dir: {target.label_workdir} → {target.working_dir}")
    if target.config_files:
        _log(
            job_id,
            "Config files: "
            + ", ".join(
                f"{a} → {b}"
                for a, b in zip(target.label_config_files, target.config_files)
            ),
        )


def _start_lifecycle_job(kind: str, container_ref: str, runner: Any) -> dict[str, Any]:
    job_id = f"{kind}-{container_ref[:12]}-{int(datetime.now(timezone.utc).timestamp())}"
    _set_job(
        job_id,
        kind=kind,
        status="queued",
        container_ref=container_ref,
        logs=[],
        message="Queued",
    )

    def run() -> None:
        try:
            runner(job_id, container_ref)
        except Exception as exc:
            logger.exception("%s job failed", kind)
            _set_job(job_id, status="error", message=str(exc), error=str(exc))

    threading.Thread(target=run, daemon=True).start()
    return get_job(job_id) or {"id": job_id, "status": "queued"}


def _do_compose_start(
    job_id: str,
    docker_bin: str,
    target: ComposeTarget,
) -> str:
    """Prefer compose start; fall back to up -d. Returns method label."""
    try:
        _run_compose(
            job_id,
            docker_bin,
            target,
            ["start", target.service],
            status="starting",
        )
        return "compose start"
    except RuntimeError as start_exc:
        _log(
            job_id,
            f"compose start failed ({start_exc}); trying up -d {target.service}",
        )
        _run_compose(
            job_id,
            docker_bin,
            target,
            ["up", "-d", target.service],
            status="starting",
        )
        return "compose up -d"


def start_update_job(container_ref: str) -> dict[str, Any]:
    job_id = f"update-{container_ref[:12]}-{int(datetime.now(timezone.utc).timestamp())}"
    _set_job(
        job_id,
        kind="update",
        status="queued",
        container_ref=container_ref,
        logs=[],
        message="Queued",
    )

    def run() -> None:
        try:
            _do_update(job_id, container_ref)
        except Exception as exc:
            logger.exception("Update job failed")
            _set_job(job_id, status="error", message=str(exc), error=str(exc))

    threading.Thread(target=run, daemon=True).start()
    return get_job(job_id) or {"id": job_id, "status": "queued"}


def _do_update(job_id: str, container_ref: str) -> None:
    _set_job(job_id, status="running", message="Inspecting container")
    _log(job_id, f"Inspecting {container_ref}")
    client = _client()
    try:
        container = _get_container(client, container_ref)
        container.reload()
        labels = compose_labels_from_attrs(container.attrs)
        name = (container.name or "").lstrip("/")

        target = resolve_compose_target(labels)
        _log(
            job_id,
            f"Compose service {target.project}/{target.service} "
            f"(container {name})",
        )
        _log(
            job_id,
            f"Project dir: {target.label_workdir} → {target.working_dir}",
        )
        if target.config_files:
            _log(
                job_id,
                "Config files: "
                + ", ".join(
                    f"{a} → {b}"
                    for a, b in zip(target.label_config_files, target.config_files)
                ),
            )
        else:
            _log(
                job_id,
                "No config_files label — compose will use default file names in "
                "the project directory",
            )

        docker_bin = _docker_compose_available()
        if not docker_bin:
            raise RuntimeError(
                "docker compose is not available in this Homelab Watcher container. "
                "Rebuild the image (Dockerfile installs the Docker CLI + Compose "
                "plugin) and redeploy."
            )

        _run_compose(
            job_id,
            docker_bin,
            target,
            ["pull", target.service],
            status="pulling",
        )
        _run_compose(
            job_id,
            docker_bin,
            target,
            ["up", "-d", target.service],
            status="updating",
        )

        _set_job(
            job_id,
            status="done",
            message="Update complete (compose pull + up -d)",
            error=None,
        )
        _log(
            job_id,
            f"Done — Compose reconciled {target.project}/{target.service} "
            "(networks, depends_on, restart policy from the compose file)",
        )
    finally:
        try:
            client.close()
        except Exception:
            pass


def start_stop_job(container_ref: str) -> dict[str, Any]:
    return _start_lifecycle_job("stop", container_ref, _do_stop)


def start_start_job(container_ref: str) -> dict[str, Any]:
    return _start_lifecycle_job("start", container_ref, _do_start)


def start_restart_job(container_ref: str) -> dict[str, Any]:
    return _start_lifecycle_job("restart", container_ref, _do_restart)


def start_pause_job(container_ref: str) -> dict[str, Any]:
    return _start_lifecycle_job("pause", container_ref, _do_pause)


def start_unpause_job(container_ref: str) -> dict[str, Any]:
    return _start_lifecycle_job("unpause", container_ref, _do_unpause)


def start_kill_job(container_ref: str) -> dict[str, Any]:
    return _start_lifecycle_job("kill", container_ref, _do_kill)


def _do_stop(job_id: str, container_ref: str) -> None:
    _set_job(job_id, status="running", message="Inspecting container")
    _log(job_id, f"Inspecting {container_ref}")
    client = _client()
    try:
        container = _get_container(client, container_ref)
        container.reload()
        name = (container.name or "").lstrip("/")
        status = _container_status(container)
        if status in _STOPPED_STATES:
            raise RuntimeError(f"Container {name} is already stopped ({status})")
        if status not in _ACTIVE_STATES:
            raise RuntimeError(f"Cannot stop container {name} in state {status}")

        labels = compose_labels_from_attrs(container.attrs)
        compose = _compose_cli_for_lifecycle(labels)
        if compose:
            docker_bin, target = compose
            _log_compose_target(job_id, target, name, status)
            _run_compose(
                job_id,
                docker_bin,
                target,
                ["stop", target.service],
                status="stopping",
            )
            _set_job(
                job_id,
                status="done",
                message="Stop complete (compose stop)",
                error=None,
            )
            _log(job_id, f"Done — stopped Compose service {target.project}/{target.service}")
            return

        _set_job(job_id, status="stopping", message="Stopping container")
        _log(job_id, f"Stopping {name} via Docker API (timeout=20)")
        try:
            container.stop(timeout=20)
        except APIError as exc:
            raise RuntimeError(f"docker stop failed: {exc}") from exc
        _set_job(job_id, status="done", message="Stop complete (docker stop)", error=None)
        _log(job_id, f"Done — stopped {name}")
    finally:
        try:
            client.close()
        except Exception:
            pass


def _do_start(job_id: str, container_ref: str) -> None:
    _set_job(job_id, status="running", message="Inspecting container")
    _log(job_id, f"Inspecting {container_ref}")
    client = _client()
    try:
        container = _get_container(client, container_ref)
        container.reload()
        name = (container.name or "").lstrip("/")
        status = _container_status(container)
        if status in _RUNNING_STATES:
            raise RuntimeError(f"Container {name} is already running")
        if status in _PAUSED_STATES:
            raise RuntimeError(
                f"Container {name} is paused — use Unpause instead of Start"
            )
        if status == "restarting":
            raise RuntimeError(f"Container {name} is already restarting")

        labels = compose_labels_from_attrs(container.attrs)
        compose = _compose_cli_for_lifecycle(labels)
        if compose:
            docker_bin, target = compose
            _log_compose_target(job_id, target, name, status)
            method = _do_compose_start(job_id, docker_bin, target)
            _set_job(
                job_id,
                status="done",
                message=f"Start complete ({method})",
                error=None,
            )
            _log(
                job_id,
                f"Done — started Compose service {target.project}/{target.service}",
            )
            return

        _set_job(job_id, status="starting", message="Starting container")
        _log(
            job_id,
            f"Standalone container {name} (state={status}) — docker start "
            "(existing container; not recreate-from-inspect)",
        )
        try:
            container.start()
        except APIError as exc:
            raise RuntimeError(f"docker start failed: {exc}") from exc
        _set_job(job_id, status="done", message="Start complete (docker start)", error=None)
        _log(job_id, f"Done — started {name}")
    finally:
        try:
            client.close()
        except Exception:
            pass


def _do_restart(job_id: str, container_ref: str) -> None:
    _set_job(job_id, status="running", message="Inspecting container")
    _log(job_id, f"Inspecting {container_ref}")
    client = _client()
    try:
        container = _get_container(client, container_ref)
        container.reload()
        name = (container.name or "").lstrip("/")
        status = _container_status(container)

        labels = compose_labels_from_attrs(container.attrs)
        compose = _compose_cli_for_lifecycle(labels)

        # Stopped / created / dead (and similar) → start existing container
        if status not in {"running", "paused", "restarting"}:
            if compose:
                docker_bin, target = compose
                _log_compose_target(job_id, target, name, status)
                method = _do_compose_start(job_id, docker_bin, target)
                _set_job(
                    job_id,
                    status="done",
                    message=f"Restart complete ({method})",
                    error=None,
                )
                _log(
                    job_id,
                    f"Done — started Compose service {target.project}/{target.service}",
                )
                return
            _set_job(job_id, status="starting", message="Starting container")
            _log(
                job_id,
                f"Standalone container {name} (state={status}) — docker start",
            )
            try:
                container.start()
            except APIError as exc:
                raise RuntimeError(f"docker start failed: {exc}") from exc
            _set_job(
                job_id,
                status="done",
                message="Restart complete (docker start)",
                error=None,
            )
            _log(job_id, f"Done — started {name}")
            return

        # running / paused / restarting → true restart
        if compose:
            docker_bin, target = compose
            _log_compose_target(job_id, target, name, status)
            _run_compose(
                job_id,
                docker_bin,
                target,
                ["restart", target.service],
                status="restarting",
            )
            _set_job(
                job_id,
                status="done",
                message="Restart complete (compose restart)",
                error=None,
            )
            _log(
                job_id,
                f"Done — restarted Compose service {target.project}/{target.service}",
            )
            return

        _set_job(job_id, status="restarting", message="Restarting container")
        _log(job_id, f"Restarting {name} via Docker API")
        try:
            container.restart(timeout=20)
        except APIError as exc:
            raise RuntimeError(f"docker restart failed: {exc}") from exc
        _set_job(
            job_id,
            status="done",
            message="Restart complete (docker restart)",
            error=None,
        )
        _log(job_id, f"Done — restarted {name}")
    finally:
        try:
            client.close()
        except Exception:
            pass


def _do_pause(job_id: str, container_ref: str) -> None:
    _set_job(job_id, status="running", message="Inspecting container")
    _log(job_id, f"Inspecting {container_ref}")
    client = _client()
    try:
        container = _get_container(client, container_ref)
        container.reload()
        name = (container.name or "").lstrip("/")
        status = _container_status(container)
        if status not in _RUNNING_STATES:
            raise RuntimeError(
                f"Cannot pause container {name} in state {status} (need running)"
            )
        _set_job(job_id, status="pausing", message="Pausing container")
        _log(job_id, f"Pausing {name} via Docker API")
        try:
            container.pause()
        except APIError as exc:
            raise RuntimeError(f"docker pause failed: {exc}") from exc
        _set_job(job_id, status="done", message="Pause complete", error=None)
        _log(job_id, f"Done — paused {name}")
    finally:
        try:
            client.close()
        except Exception:
            pass


def _do_unpause(job_id: str, container_ref: str) -> None:
    _set_job(job_id, status="running", message="Inspecting container")
    _log(job_id, f"Inspecting {container_ref}")
    client = _client()
    try:
        container = _get_container(client, container_ref)
        container.reload()
        name = (container.name or "").lstrip("/")
        status = _container_status(container)
        if status not in _PAUSED_STATES:
            raise RuntimeError(
                f"Cannot unpause container {name} in state {status} (need paused)"
            )
        _set_job(job_id, status="unpausing", message="Unpausing container")
        _log(job_id, f"Unpausing {name} via Docker API")
        try:
            container.unpause()
        except APIError as exc:
            raise RuntimeError(f"docker unpause failed: {exc}") from exc
        _set_job(job_id, status="done", message="Unpause complete", error=None)
        _log(job_id, f"Done — unpaused {name}")
    finally:
        try:
            client.close()
        except Exception:
            pass


def _do_kill(job_id: str, container_ref: str) -> None:
    _set_job(job_id, status="running", message="Inspecting container")
    _log(job_id, f"Inspecting {container_ref}")
    client = _client()
    try:
        container = _get_container(client, container_ref)
        container.reload()
        name = (container.name or "").lstrip("/")
        status = _container_status(container)
        if status in _STOPPED_STATES:
            raise RuntimeError(f"Container {name} is already stopped ({status})")
        if status not in _ACTIVE_STATES:
            raise RuntimeError(f"Cannot kill container {name} in state {status}")

        labels = compose_labels_from_attrs(container.attrs)
        compose = _compose_cli_for_lifecycle(labels)
        if compose:
            docker_bin, target = compose
            _log_compose_target(job_id, target, name, status)
            _run_compose(
                job_id,
                docker_bin,
                target,
                ["kill", target.service],
                status="killing",
            )
            _set_job(
                job_id,
                status="done",
                message="Kill complete (compose kill)",
                error=None,
            )
            _log(
                job_id,
                f"Done — killed Compose service {target.project}/{target.service}",
            )
            return

        _set_job(job_id, status="killing", message="Killing container")
        _log(job_id, f"Killing {name} via Docker API (SIGKILL)")
        try:
            container.kill()
        except APIError as exc:
            raise RuntimeError(f"docker kill failed: {exc}") from exc
        _set_job(job_id, status="done", message="Kill complete (docker kill)", error=None)
        _log(job_id, f"Done — killed {name}")
    finally:
        try:
            client.close()
        except Exception:
            pass


def start_teardown_job(
    container_ref: str,
    *,
    remove_container: bool = True,
    remove_image: bool = False,
    remove_volumes: bool = False,
) -> dict[str, Any]:
    job_id = f"teardown-{container_ref[:12]}-{int(datetime.now(timezone.utc).timestamp())}"
    _set_job(
        job_id,
        kind="teardown",
        status="queued",
        container_ref=container_ref,
        options={
            "remove_container": remove_container,
            "remove_image": remove_image,
            "remove_volumes": remove_volumes,
        },
        logs=[],
        message="Queued",
    )

    def run() -> None:
        try:
            _do_teardown(
                job_id,
                container_ref,
                remove_container=remove_container,
                remove_image=remove_image,
                remove_volumes=remove_volumes,
            )
        except Exception as exc:
            logger.exception("Teardown job failed")
            _set_job(job_id, status="error", message=str(exc), error=str(exc))

    threading.Thread(target=run, daemon=True).start()
    return get_job(job_id) or {"id": job_id, "status": "queued"}


def _do_teardown(
    job_id: str,
    container_ref: str,
    *,
    remove_container: bool,
    remove_image: bool,
    remove_volumes: bool,
) -> None:
    _set_job(job_id, status="running", message="Inspecting container")
    client = _client()
    try:
        container = _get_container(client, container_ref)
        container.reload()
        name = (container.name or "").lstrip("/")
        labels = compose_labels_from_attrs(container.attrs)
        parsed = parse_compose_labels(labels)

        image_id = None
        image_tags: list[str] = []
        try:
            image_id = container.image.id
            image_tags = list(container.image.tags or [])
        except Exception:
            image_id = container.attrs.get("Image") or None

        _log(
            job_id,
            f"Teardown {name}: container={remove_container} "
            f"image={remove_image} volumes={remove_volumes}",
        )

        if parsed and remove_container:
            project, service, workdir, files = parsed
            _log(
                job_id,
                f"Compose-managed ({project}/{service}). Preferring "
                "`docker compose stop/rm` for this service only — not a full "
                "`compose down` of the project (other services and shared "
                "networks/volumes stay).",
            )
            try:
                target = resolve_compose_target(labels)
            except RuntimeError as exc:
                _log(
                    job_id,
                    f"Compose project dir not visible ({exc}); "
                    "falling back to Docker API remove for this container.",
                )
                target = None

            docker_bin = _docker_compose_available() if target else None
            if target and docker_bin:
                _run_compose(
                    job_id,
                    docker_bin,
                    target,
                    ["stop", target.service],
                    status="stopping",
                )
                rm_args = ["rm", "-f"]
                if remove_volumes:
                    rm_args.append("-v")
                rm_args.append(target.service)
                _run_compose(
                    job_id,
                    docker_bin,
                    target,
                    rm_args,
                    status="removing",
                )
                _log(
                    job_id,
                    "Compose service removed"
                    + (" (volumes flag set on rm)" if remove_volumes else ""),
                )
            else:
                if not docker_bin and target:
                    _log(
                        job_id,
                        "docker compose unavailable — falling back to Docker API",
                    )
                _teardown_via_api(
                    job_id,
                    container,
                    name,
                    remove_container=True,
                    remove_volumes=remove_volumes,
                )
        elif remove_container:
            _log(
                job_id,
                "Not a Compose service — removing via Docker API "
                "(stop + delete). This does not touch compose project state.",
            )
            _teardown_via_api(
                job_id,
                container,
                name,
                remove_container=True,
                remove_volumes=remove_volumes,
            )

        if remove_image and image_id:
            _set_job(job_id, status="removing_image", message="Removing image")
            try:
                ref = image_tags[0] if image_tags else image_id
                _log(job_id, f"Removing image {ref}")
                client.images.remove(image=ref, force=True, noprune=False)
                _log(job_id, "Image removed")
            except ImageNotFound:
                _log(job_id, "Image already gone")
            except APIError as exc:
                raise RuntimeError(f"Image remove failed: {exc}") from exc

        _set_job(job_id, status="done", message="Teardown complete", error=None)
        _log(job_id, "Done")
    finally:
        try:
            client.close()
        except Exception:
            pass


def _teardown_via_api(
    job_id: str,
    container: Any,
    name: str,
    *,
    remove_container: bool,
    remove_volumes: bool,
) -> None:
    if not remove_container:
        return
    _set_job(job_id, status="removing", message="Stopping container")
    try:
        container.stop(timeout=20)
    except Exception as exc:
        _log(job_id, f"Stop warning: {exc}")
    _log(job_id, f"Removing container {name}")
    container.remove(force=True, v=bool(remove_volumes))
    _log(
        job_id,
        "Container removed"
        + (" (volumes flag set)" if remove_volumes else " (volumes kept)"),
    )


def _reclaimed_bytes(result: Any) -> int:
    if not isinstance(result, dict):
        return 0
    for key in ("SpaceReclaimed", "space_reclaimed"):
        try:
            return max(0, int(result.get(key) or 0))
        except (TypeError, ValueError):
            continue
    return 0


def start_docker_prune_job(
    *,
    containers: bool = False,
    images: bool = False,
    images_all_unused: bool = False,
    build_cache: bool = False,
    build_cache_all: bool = False,
    volumes: bool = False,
    networks: bool = False,
) -> dict[str, Any]:
    """
    Prune Docker disk usage via Engine API.

    images_all_unused=False → dangling (untagged) only; True → all unused images.
    build_cache_all → prune_builds(all=True); otherwise dangling/default builder cache.
    volumes → unused volumes (destructive if data lives only on the volume).
    """
    if not any(
        (containers, images, build_cache, volumes, networks)
    ):
        raise ValueError("Nothing selected to prune")

    job_id = f"prune-{int(datetime.now(timezone.utc).timestamp())}"
    options = {
        "containers": containers,
        "images": images,
        "images_all_unused": images_all_unused,
        "build_cache": build_cache,
        "build_cache_all": build_cache_all,
        "volumes": volumes,
        "networks": networks,
    }
    _set_job(
        job_id,
        kind="docker_prune",
        status="queued",
        options=options,
        logs=[],
        message="Queued",
        space_reclaimed_bytes=0,
    )

    def run() -> None:
        try:
            _do_docker_prune(job_id, **options)
        except Exception as exc:
            logger.exception("Docker prune job failed")
            _set_job(job_id, status="error", message=str(exc), error=str(exc))

    threading.Thread(target=run, daemon=True).start()
    return get_job(job_id) or {"id": job_id, "status": "queued"}


def _do_docker_prune(
    job_id: str,
    *,
    containers: bool,
    images: bool,
    images_all_unused: bool,
    build_cache: bool,
    build_cache_all: bool,
    volumes: bool,
    networks: bool,
) -> None:
    _set_job(job_id, status="running", message="Connecting to Docker")
    _log(
        job_id,
        "Prune options: "
        + ", ".join(
            f"{k}={v}"
            for k, v in {
                "containers": containers,
                "images": images,
                "images_all_unused": images_all_unused,
                "build_cache": build_cache,
                "build_cache_all": build_cache_all,
                "volumes": volumes,
                "networks": networks,
            }.items()
        ),
    )
    client = _client()
    total = 0
    try:
        if containers:
            _set_job(job_id, status="pruning_containers", message="Pruning stopped containers")
            _log(job_id, "Pruning stopped containers…")
            result = client.containers.prune()
            got = _reclaimed_bytes(result)
            total += got
            deleted = result.get("ContainersDeleted") or []
            _log(
                job_id,
                f"Containers: removed {len(deleted) if isinstance(deleted, list) else 0}, "
                f"reclaimed {got} bytes",
            )

        if images:
            _set_job(job_id, status="pruning_images", message="Pruning images")
            dangling_only = not images_all_unused
            _log(
                job_id,
                "Pruning images "
                + ("(dangling/untagged only)…" if dangling_only else "(all unused)…"),
            )
            result = client.images.prune(filters={"dangling": dangling_only})
            got = _reclaimed_bytes(result)
            total += got
            deleted = result.get("ImagesDeleted") or []
            _log(
                job_id,
                f"Images: deleted {len(deleted) if isinstance(deleted, list) else 0}, "
                f"reclaimed {got} bytes",
            )

        if build_cache:
            _set_job(job_id, status="pruning_build_cache", message="Pruning build cache")
            _log(
                job_id,
                "Pruning build cache"
                + (" (all)…" if build_cache_all else "…"),
            )
            try:
                if build_cache_all:
                    result = client.images.prune_builds(all=True)
                else:
                    result = client.images.prune_builds()
            except TypeError:
                # Older docker-py without all=
                result = client.images.prune_builds()
            got = _reclaimed_bytes(result)
            total += got
            _log(job_id, f"Build cache: reclaimed {got} bytes")

        if networks:
            _set_job(job_id, status="pruning_networks", message="Pruning unused networks")
            _log(job_id, "Pruning unused networks…")
            result = client.networks.prune()
            got = _reclaimed_bytes(result)
            total += got
            deleted = result.get("NetworksDeleted") or []
            _log(
                job_id,
                f"Networks: removed {len(deleted) if isinstance(deleted, list) else 0}, "
                f"reclaimed {got} bytes",
            )

        if volumes:
            _set_job(job_id, status="pruning_volumes", message="Pruning unused volumes")
            _log(
                job_id,
                "Pruning unused volumes — may delete data not referenced by a container",
            )
            result = client.volumes.prune()
            got = _reclaimed_bytes(result)
            total += got
            deleted = result.get("VolumesDeleted") or []
            _log(
                job_id,
                f"Volumes: removed {len(deleted) if isinstance(deleted, list) else 0}, "
                f"reclaimed {got} bytes",
            )

        msg = f"Prune complete — reclaimed {total} bytes"
        _set_job(
            job_id,
            status="done",
            message=msg,
            error=None,
            space_reclaimed_bytes=total,
        )
        _log(job_id, msg)
    finally:
        try:
            client.close()
        except Exception:
            pass
