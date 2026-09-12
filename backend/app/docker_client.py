"""Docker inventory + mutations (update / tear down). List/inspect always; writes gated by settings."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import docker
from docker.errors import DockerException, ImageNotFound, NotFound

logger = logging.getLogger(__name__)

_last_docker_error: str | None = None
_last_docker_endpoint: str | None = None
_last_docker_tried: list[str] = []


def get_docker_error() -> str | None:
    """User-facing reason Docker inventory is unavailable, or None if OK."""
    return _last_docker_error


def get_docker_endpoint() -> str | None:
    """Human label for the Docker API endpoint currently in use."""
    return _last_docker_endpoint


def get_docker_tried() -> list[str]:
    return list(_last_docker_tried)


def get_docker_status() -> dict[str, Any]:
    return {
        "available": _last_docker_error is None and _last_docker_endpoint is not None,
        "error": _last_docker_error,
        "endpoint": _last_docker_endpoint,
        "tried": list(_last_docker_tried),
    }


def _colima_home() -> Path:
    env = (os.environ.get("COLIMA_HOME") or "").strip()
    if env:
        return Path(env).expanduser()
    return Path.home() / ".colima"


def _socket_candidates() -> list[tuple[str, str]]:
    """
    Ordered (label, docker base_url) candidates.

    Prefer explicit DOCKER_HOST, then common sockets (Colima, Desktop, OrbStack).
    Only includes unix sockets that exist on disk (except DOCKER_HOST, always tried).
    """
    out: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(label: str, url: str) -> None:
        key = url.strip()
        if not key or key in seen:
            return
        seen.add(key)
        out.append((label, key))

    env_host = (os.environ.get("DOCKER_HOST") or "").strip()
    if env_host:
        add(f"DOCKER_HOST ({env_host})", env_host)

    home = Path.home()
    colima = _colima_home()
    path_labels: list[tuple[str, Path]] = [
        ("/var/run/docker.sock", Path("/var/run/docker.sock")),
        ("Colima default", colima / "default" / "docker.sock"),
        ("Colima", colima / "docker.sock"),
        ("~/.colima/default/docker.sock", home / ".colima" / "default" / "docker.sock"),
        ("Docker Desktop", home / ".docker" / "run" / "docker.sock"),
        ("OrbStack", home / ".orbstack" / "run" / "docker.sock"),
    ]
    # Deduplicate path entries that resolve the same
    for label, path in path_labels:
        try:
            resolved = path.expanduser()
            if resolved.is_socket() or resolved.exists():
                add(label, f"unix://{resolved}")
        except OSError:
            continue

    return out


def _format_unavailable(tried: list[str], last_exc: BaseException | None) -> str:
    tried_txt = ", ".join(tried) if tried else "(none found on disk)"
    detail = f" Last error: {last_exc}" if last_exc else ""
    return (
        "Could not reach the Docker API. "
        f"Tried: {tried_txt}.{detail} "
        "If you use Colima, run `colima start` and set "
        "`DOCKER_HOST=unix://$HOME/.colima/default/docker.sock` "
        "(or mount that socket into Watcher). "
        "On a home server, mount the host’s docker.sock via Compose."
    )


def _connect_client() -> docker.DockerClient:
    """Connect using discovery order; set module endpoint/error state."""
    global _last_docker_error, _last_docker_endpoint, _last_docker_tried

    candidates = _socket_candidates()
    tried: list[str] = []
    last_exc: BaseException | None = None

    if not candidates:
        # Still attempt from_env — may use TCP or other env
        tried.append("docker.from_env()")
        try:
            client = docker.from_env()
            client.ping()
            _last_docker_endpoint = "docker.from_env()"
            _last_docker_error = None
            _last_docker_tried = tried
            return client
        except Exception as exc:
            last_exc = exc
            _last_docker_tried = tried
            _last_docker_endpoint = None
            _last_docker_error = _format_unavailable(tried, last_exc)
            raise DockerException(_last_docker_error) from exc

    for label, url in candidates:
        tried.append(label)
        try:
            client = docker.DockerClient(base_url=url)
            client.ping()
            _last_docker_endpoint = label
            _last_docker_error = None
            _last_docker_tried = tried
            logger.info("Docker connected via %s", label)
            return client
        except Exception as exc:
            last_exc = exc
            logger.debug("Docker candidate failed (%s): %s", label, exc)
            try:
                client.close()  # type: ignore[name-defined]
            except Exception:
                pass

    # Last resort: from_env if DOCKER_HOST wasn't already the only attempt
    if not (os.environ.get("DOCKER_HOST") or "").strip():
        tried.append("docker.from_env()")
        try:
            client = docker.from_env()
            client.ping()
            _last_docker_endpoint = "docker.from_env()"
            _last_docker_error = None
            _last_docker_tried = tried
            return client
        except Exception as exc:
            last_exc = exc

    _last_docker_tried = tried
    _last_docker_endpoint = None
    _last_docker_error = _format_unavailable(tried, last_exc)
    raise DockerException(_last_docker_error)


def _client() -> docker.DockerClient:
    return _connect_client()


def _parse_started(state: dict[str, Any]) -> str | None:
    started = state.get("StartedAt") or ""
    if not started or started.startswith("0001"):
        return None
    return started


def _uptime_seconds(started_at: str | None) -> int | None:
    if not started_at:
        return None
    try:
        cleaned = started_at.replace("Z", "+00:00")
        if "." in cleaned:
            head, rest = cleaned.split(".", 1)
            frac = ""
            tz = ""
            for i, ch in enumerate(rest):
                if ch.isdigit():
                    frac += ch
                else:
                    tz = rest[i:]
                    break
            frac = (frac + "000000")[:6]
            cleaned = f"{head}.{frac}{tz}"
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0, int((datetime.now(timezone.utc) - dt).total_seconds()))
    except Exception:
        return None


def _slim_inspect(attrs: dict[str, Any]) -> dict[str, Any]:
    """Keep HostConfig / Config / Mounts / NetworkSettings needed for posture."""
    ns = attrs.get("NetworkSettings") or {}
    state = attrs.get("State") or {}
    health = state.get("Health") or {}
    return {
        "Id": attrs.get("Id"),
        "Name": attrs.get("Name"),
        "Created": attrs.get("Created"),
        "Config": attrs.get("Config") or {},
        "HostConfig": attrs.get("HostConfig") or {},
        "Mounts": attrs.get("Mounts") or [],
        "State": {
            "Status": state.get("Status"),
            "StartedAt": state.get("StartedAt"),
            "FinishedAt": state.get("FinishedAt"),
            "Health": {"Status": health.get("Status")} if health else None,
            "RestartCount": state.get("RestartCount"),
        },
        "NetworkSettings": {
            "Networks": ns.get("Networks") or {},
            "Ports": ns.get("Ports") or {},
        },
        "Image": attrs.get("Image"),
    }


def _parse_container_port_key(cport: str) -> tuple[int | None, str]:
    """Parse ``80/tcp`` → (80, ``tcp``)."""
    raw = str(cport or "").strip().lower()
    if "/" in raw:
        port_s, proto = raw.split("/", 1)
    else:
        port_s, proto = raw, "tcp"
    proto = (proto or "tcp").strip() or "tcp"
    try:
        return int(port_s), proto
    except ValueError:
        return None, proto


def _classify_host_bind(host_ip: str) -> str:
    a = (host_ip or "").lower().strip() or "0.0.0.0"
    if a in ("0.0.0.0", "*", "::", "::0"):
        return "all"
    if a in ("127.0.0.1", "::1") or a.startswith("127."):
        return "localhost"
    return "lan"


def _published_port_bindings(attrs: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Structured host-published bindings from NetworkSettings.Ports
    (and HostConfig.PortBindings as a fallback).

    Only rows with a real host port — not bare Dockerfile EXPOSE.
    """
    ns_ports = ((attrs.get("NetworkSettings") or {}).get("Ports") or {}) or {}
    hc_bindings = ((attrs.get("HostConfig") or {}).get("PortBindings") or {}) or {}

    # Prefer live NetworkSettings.Ports; fall back to configured PortBindings.
    keys = sorted(set(str(k) for k in ns_ports.keys()) | set(str(k) for k in hc_bindings.keys()))
    rows: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()

    for cport_key in keys:
        cport, proto = _parse_container_port_key(cport_key)
        if cport is None:
            continue
        bindings = ns_ports.get(cport_key)
        if not bindings:
            bindings = hc_bindings.get(cport_key)
        if not bindings:
            continue
        if not isinstance(bindings, list):
            continue
        for b in bindings:
            if not isinstance(b, dict):
                continue
            hip = (b.get("HostIp") or "0.0.0.0").strip() or "0.0.0.0"
            hport_s = str(b.get("HostPort") or "").strip()
            if not hport_s:
                continue
            try:
                hport = int(hport_s)
            except ValueError:
                continue
            key = (hip, hport, cport, proto)
            if key in seen:
                continue
            seen.add(key)
            scope = _classify_host_bind(hip)
            rows.append(
                {
                    "host_ip": hip,
                    "host_port": hport,
                    "container_port": cport,
                    "protocol": proto,
                    "bind_scope": scope,
                    "mapping": f"{hip}:{hport}->{cport}/{proto}",
                }
            )
    return rows


def _published_ports(attrs: dict[str, Any]) -> list[str]:
    """Human-readable published ports like ``0.0.0.0:8080->80/tcp``."""
    rows = _published_port_bindings(attrs)
    if rows:
        return [str(r["mapping"]) for r in rows]
    # Preserve prior behavior: show EXPOSE-only keys when nothing is published.
    ports = ((attrs.get("NetworkSettings") or {}).get("Ports") or {}) or {}
    lines: list[str] = []
    for cport, bindings in sorted(ports.items(), key=lambda x: str(x[0])):
        if not bindings:
            lines.append(str(cport))
    return lines


def collect_docker_published_ports(
    containers: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Flatten published host bindings across the container inventory
    (running and stopped/exited).

    Source: inspect NetworkSettings.Ports / HostConfig.PortBindings already
    summarized on each container (and re-parsed from inspect when present).
    For stopped containers, configured PortBindings are included when present;
    live NetworkSettings.Ports are preferred when the container is running.
    """
    rows: list[dict[str, Any]] = []
    if not containers:
        return {
            "docker_published_ports": [],
            "docker_published_ports_count": 0,
            "docker_published_ports_exposed_count": 0,
            "docker_published_ports_note": None,
        }

    for c in containers:
        name = str(c.get("name") or "").lstrip("/") or None
        cid = str(c.get("container_id") or "") or None
        state = str(c.get("state") or c.get("status") or "").lower()
        inspect = c.get("inspect") if isinstance(c.get("inspect"), dict) else None
        bindings: list[dict[str, Any]] = []
        if inspect:
            bindings = _published_port_bindings(inspect)
        if not bindings:
            # Fall back to parsing human-readable published_ports strings.
            for line in c.get("published_ports") or []:
                text = str(line).strip()
                if "->" not in text:
                    continue
                left, right = text.split("->", 1)
                left, right = left.strip(), right.strip()
                hip = "0.0.0.0"
                hport_s = left
                if ":" in left:
                    hip, hport_s = left.rsplit(":", 1)
                cport, proto = _parse_container_port_key(right)
                try:
                    hport = int(hport_s)
                except ValueError:
                    continue
                if cport is None:
                    continue
                bindings.append(
                    {
                        "host_ip": hip or "0.0.0.0",
                        "host_port": hport,
                        "container_port": cport,
                        "protocol": proto,
                        "bind_scope": _classify_host_bind(hip or "0.0.0.0"),
                        "mapping": f"{hip or '0.0.0.0'}:{hport}->{cport}/{proto}",
                    }
                )
        for b in bindings:
            rows.append(
                {
                    **b,
                    "container": name,
                    "container_id": cid,
                    "container_state": state or None,
                }
            )

    scope_rank = {"all": 0, "lan": 1, "localhost": 2}

    def sort_key(r: dict[str, Any]) -> tuple:
        return (
            scope_rank.get(str(r.get("bind_scope") or ""), 9),
            str(r.get("protocol") or ""),
            int(r.get("host_port") or 0),
            str(r.get("container") or ""),
        )

    rows.sort(key=sort_key)
    exposed = sum(1 for r in rows if r.get("bind_scope") in ("all", "lan"))
    return {
        "docker_published_ports": rows,
        "docker_published_ports_count": len(rows),
        "docker_published_ports_exposed_count": exposed,
        "docker_published_ports_note": None,
    }


def _networks_list(attrs: dict[str, Any]) -> list[str]:
    nets = ((attrs.get("NetworkSettings") or {}).get("Networks") or {}) or {}
    return sorted(str(k) for k in nets.keys())


def _mounts_summary(attrs: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in attrs.get("Mounts") or []:
        if not isinstance(m, dict):
            continue
        out.append(
            {
                "type": m.get("Type") or "bind",
                "source": m.get("Source") or m.get("Name") or "",
                "destination": m.get("Destination") or "",
                "mode": "rw" if m.get("RW", True) else "ro",
            }
        )
    return out


def _health_status(state: dict[str, Any]) -> str | None:
    health = state.get("Health")
    if isinstance(health, dict):
        status = (health.get("Status") or "").strip()
        return status or None
    return None


def _parse_created(attrs: dict[str, Any]) -> str | None:
    created = attrs.get("Created") or ""
    if not created or str(created).startswith("0001"):
        return None
    return str(created)


def list_containers() -> list[dict[str, Any]]:
    """Return inventory of all containers (running and stopped).

    On Docker connection failure, returns [] and sets get_docker_error().
    """
    global _last_docker_error
    try:
        client = _client()
    except Exception as exc:
        if not _last_docker_error:
            _last_docker_error = _format_unavailable(_last_docker_tried, exc)
        logger.error("Docker unavailable: %s", exc)
        return []

    out: list[dict[str, Any]] = []
    try:
        for c in client.containers.list(all=True):
            try:
                c.reload()
                attrs = c.attrs
                state = attrs.get("State") or {}
                config = attrs.get("Config") or {}
                started_at = _parse_started(state)
                status = state.get("Status") or c.status
                image = config.get("Image") or (c.image.tags[0] if c.image.tags else "")
                image_id = ""
                try:
                    image_id = c.image.id or ""
                except Exception:
                    image_id = attrs.get("Image") or ""

                local_digest = None
                try:
                    repo_digests = c.image.attrs.get("RepoDigests") or []
                    if repo_digests:
                        local_digest = repo_digests[0].split("@", 1)[-1]
                except Exception:
                    pass

                running = (status or "").lower() == "running"
                labels = dict(config.get("Labels") or {})
                out.append(
                    {
                        "container_id": c.id[:12],
                        "container_id_full": c.id,
                        "name": (c.name or "").lstrip("/"),
                        "image": image,
                        "image_id": image_id,
                        "status": c.status,
                        "state": status,
                        "created_at": _parse_created(attrs),
                        "started_at": started_at,
                        "uptime_seconds": _uptime_seconds(started_at) if running else None,
                        "restart_count": int(state.get("RestartCount") or 0),
                        "health": _health_status(state),
                        "networks": _networks_list(attrs),
                        "published_ports": _published_ports(attrs),
                        "mounts": _mounts_summary(attrs),
                        "local_digest": local_digest,
                        "update_available": False,
                        "remote_digest": None,
                        "labels": labels,
                        "access_url": None,
                        "access_url_source": None,
                        "pihole_matched": False,
                        "pihole_hostnames": [],
                        "proxy_matched": False,
                        "networking": {"mapped": False, "entries": []},
                        "inspect": _slim_inspect(attrs),
                        "compose_project": labels.get("com.docker.compose.project"),
                        "compose_service": labels.get("com.docker.compose.service"),
                        "compose_workdir": labels.get(
                            "com.docker.compose.project.working_dir"
                        ),
                        "compose_config_files": labels.get(
                            "com.docker.compose.project.config_files"
                        )
                        or labels.get("com.docker.compose.project.config_file"),
                    }
                )
            except Exception as exc:
                logger.warning("Failed to inspect container: %s", exc)
        _last_docker_error = None
    except DockerException as exc:
        _last_docker_error = _format_unavailable(_last_docker_tried or [str(exc)], exc)
        logger.error("Failed to list containers: %s", exc)
    finally:
        try:
            client.close()
        except Exception:
            pass
    return out


def get_container_by_id_or_name(ref: str) -> Any:
    client = _client()
    try:
        return client.containers.get(ref)
    except NotFound:
        for c in client.containers.list(all=True):
            if c.id.startswith(ref) or (c.name or "").lstrip("/") == ref:
                return c
        raise


def get_container_logs(ref: str, *, tail: int = 150) -> dict[str, Any]:
    """Fetch recent container logs. Fail-soft — never raises."""
    try:
        n = int(tail)
    except (TypeError, ValueError):
        n = 150
    n = max(1, min(n, 500))
    client = None
    try:
        client = _client()
        try:
            container = client.containers.get(ref)
        except NotFound:
            container = None
            for c in client.containers.list(all=True):
                if c.id.startswith(ref) or (c.name or "").lstrip("/") == ref:
                    container = c
                    break
            if container is None:
                return {
                    "ok": False,
                    "logs": "",
                    "error": "Container not found",
                    "tail": n,
                }
        raw = container.logs(tail=n, stdout=True, stderr=True)
        if isinstance(raw, (bytes, bytearray)):
            text = raw.decode("utf-8", errors="replace")
        else:
            text = str(raw)
        return {"ok": True, "logs": text, "error": None, "tail": n}
    except Exception as exc:
        logger.warning("Failed to read logs for %s: %s", ref, exc)
        return {
            "ok": False,
            "logs": "",
            "error": str(exc) or "Logs unavailable",
            "tail": n,
        }
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
