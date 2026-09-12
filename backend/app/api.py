"""REST API for the dashboard, Settings, and container actions."""

from __future__ import annotations

import json
import logging
import threading
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app import db
from app.config import TargetConfig
from app.container_actions import (
    get_job,
    start_docker_prune_job,
    start_kill_job,
    start_pause_job,
    start_restart_job,
    start_start_job,
    start_stop_job,
    start_teardown_job,
    start_unpause_job,
    start_update_job,
)
from app.docker_disk import get_docker_disk_usage
from app.digest import collect_notable, next_cron_fire, send_digest
from app.runtime_settings import (
    actions_enabled,
    apply_container_notes,
    apply_watched,
    digest_public_view,
    effective_yaml_overlay,
    get_speed_test_last,
    networking_public_view,
    pihole_public_view,
    plex_as_target,
    resolve_general,
    resolve_listening_ports,
    resolve_networking,
    resolve_pihole,
    resolve_plex,
    resolve_security,
    resolve_speed_test,
    resolve_targets,
    resolve_thresholds,
    save_check_targets,
    security_public_view,
    watched_key_for_container,
)
from app.docker_client import get_container_logs, get_docker_error
from app.scheduler import (
    apply_pihole_result,
    get_last_dns,
    get_last_networking,
    get_last_pihole,
    get_poll_status,
    poll_once,
    refresh_pihole_dns_snapshot,
    reschedule_digest,
    reschedule_poll,
    reschedule_speed_test,
    speed_test_once,
)
from app.checks import check_http
from app.host_metrics import discover_disks, host_root_available
from app.pihole import fetch_pihole_dns
from app.security_opensca import opensca_available
from app.security_trivy import trivy_available
from app.speed_test import clear_speed_test_pending, mark_speed_test_pending, speed_test_busy

router = APIRouter(prefix="/api")
logger = logging.getLogger(__name__)


def _parse_raw(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    raw = out.get("raw_json")
    if isinstance(raw, str):
        try:
            out["raw"] = json.loads(raw)
        except Exception:
            out["raw"] = {}
    elif isinstance(raw, dict):
        out["raw"] = raw
    else:
        out["raw"] = {}
    detail = out.get("detail_json")
    if isinstance(detail, str):
        try:
            out["detail"] = json.loads(detail)
        except Exception:
            out["detail"] = {}
    return out


def _container_item(r: dict[str, Any]) -> dict[str, Any]:
    raw = r.get("raw") or {}
    security = raw.get("security") or {"enabled": False}
    return {
        "container_id": r.get("container_id"),
        "name": r.get("name"),
        "image": r.get("image"),
        "image_id": r.get("image_id") or raw.get("image_id"),
        "status": r.get("status"),
        "state": r.get("state"),
        "created_at": raw.get("created_at"),
        "started_at": r.get("started_at"),
        "uptime_seconds": raw.get("uptime_seconds"),
        "restart_count": r.get("restart_count"),
        "health": raw.get("health"),
        "networks": raw.get("networks") or [],
        "published_ports": raw.get("published_ports") or [],
        "mounts": raw.get("mounts") or [],
        "update_available": bool(r.get("update_available")),
        "update_bump": raw.get("update_bump"),
        "update_from": raw.get("update_from"),
        "update_to": raw.get("update_to"),
        "local_digest": r.get("local_digest"),
        "remote_digest": r.get("remote_digest"),
        "taken_at": r.get("taken_at"),
        "access_url": raw.get("access_url"),
        "access_url_source": raw.get("access_url_source"),
        "pihole_matched": bool(raw.get("pihole_matched")),
        "pihole_hostnames": raw.get("pihole_hostnames") or [],
        "proxy_matched": bool(raw.get("proxy_matched")),
        "networking": raw.get("networking")
        or {"mapped": False, "entries": []},
        "watched": bool(raw.get("watched", raw.get("vital"))),
        "watched_key": raw.get("watched_key") or raw.get("vital_key"),
        # One-release dual-read aliases (prefer watched / watched_key).
        "vital": bool(raw.get("watched", raw.get("vital"))),
        "vital_key": raw.get("watched_key") or raw.get("vital_key"),
        "description": raw.get("description") or "",
        "notes": raw.get("notes") or "",
        "compose_project": raw.get("compose_project"),
        "compose_service": raw.get("compose_service"),
        "compose_workdir": raw.get("compose_workdir"),
        "compose_config_files": raw.get("compose_config_files"),
        "security": security,
        "labels": raw.get("labels") or {},
    }


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/status")
def status() -> dict[str, Any]:
    digest_view = digest_public_view()
    digest_state = db.get_digest_state()
    general, _ = resolve_general()
    profiles = digest_view.get("profiles") or []
    next_candidates: list[str] = []
    for p in profiles:
        if not p.get("enabled"):
            continue
        cron = (p.get("digest_cron") or "").strip()
        if not cron:
            continue
        nxt = next_cron_fire(cron, p.get("tz") or digest_view.get("tz") or "UTC")
        if nxt:
            next_candidates.append(nxt)
    next_at = min(next_candidates) if next_candidates else None
    enabled_summaries = [
        f"{p.get('name') or 'Digest'}: {p.get('schedule_summary') or 'Not scheduled'}"
        for p in profiles
        if p.get("enabled")
    ]
    return {
        "poll": get_poll_status(),
        "digest": {
            **digest_state,
            "tz": digest_view["tz"],
            "send_all_clear": digest_view["digest_send_all_clear"],
            "next_at": next_at,
            "configured": digest_view["configured"],
            "enabled": digest_view["enabled"],
            "scheduled": any(p.get("scheduled") and p.get("enabled") for p in profiles),
            "schedule_summary": (
                "; ".join(enabled_summaries)
                if enabled_summaries
                else digest_view.get("schedule_summary") or "Not scheduled yet"
            ),
            "profiles": [
                {
                    "id": p.get("id"),
                    "name": p.get("name"),
                    "enabled": p.get("enabled"),
                    "scheduled": p.get("scheduled"),
                    "schedule_summary": p.get("schedule_summary"),
                    "next_at": (
                        next_cron_fire(
                            (p.get("digest_cron") or "").strip(),
                            p.get("tz") or "UTC",
                        )
                        if p.get("enabled") and (p.get("digest_cron") or "").strip()
                        else None
                    ),
                }
                for p in profiles
            ],
        },
        "actions_enabled": bool(general.get("actions_enabled", True)),
        "security_enabled": resolve_security()[0].enabled,
        "trivy_available": trivy_available(),
        "opensca_available": opensca_available(),
    }


@router.get("/containers")
def containers() -> dict[str, Any]:
    rows = [_parse_raw(r) for r in db.latest_containers()]
    # Re-apply watched flags from live DB (in case star toggled since poll)
    items_raw = []
    for r in rows:
        raw = dict(r.get("raw") or {})
        raw["name"] = r.get("name") or raw.get("name")
        raw["labels"] = raw.get("labels") or {}
        items_raw.append(raw)
    apply_watched(items_raw)
    try:
        apply_container_notes(items_raw)
    except Exception:
        pass
    by_name = {c.get("name"): c for c in items_raw}

    items = []
    for r in rows:
        parsed = _container_item(r)
        live = by_name.get(parsed["name"]) or {}
        watched = bool(live.get("watched", live.get("vital")))
        watched_key = (
            live.get("watched_key")
            or live.get("vital_key")
            or parsed.get("watched_key")
            or parsed.get("vital_key")
        )
        parsed["watched"] = watched
        parsed["watched_key"] = watched_key
        parsed["vital"] = watched
        parsed["vital_key"] = watched_key
        parsed["description"] = live.get("description") or ""
        parsed["notes"] = live.get("notes") or ""
        items.append(parsed)

    pihole = get_last_pihole() or {
        "configured": False,
        "ok": None,
        "version": None,
        "message": "Pi-hole not configured",
        "record_count": 0,
    }
    networking = get_last_networking() or {
        "proxy_type": "none",
        "configured": False,
        "ok": None,
        "route_count": 0,
        "mapped_count": 0,
        "message": None,
        "errors": [],
        "sources_tried": [],
    }
    return {
        "items": items,
        "taken_at": items[0]["taken_at"] if items else None,
        "pihole": pihole,
        "networking": networking,
        "actions_enabled": actions_enabled(),
        "docker_available": get_docker_error() is None,
        "docker_error": get_docker_error(),
    }


@router.get("/dns")
def dns_records() -> dict[str, Any]:
    """Local DNS inventory from last poll (Pi-hole + Caddy/container join)."""
    return get_last_dns()


@router.get("/caddy")
def caddy_records() -> dict[str, Any]:
    """Discovered Caddy site routes from last poll (Admin API / Caddyfile / labels)."""
    from app.scheduler import get_last_caddy

    return get_last_caddy()


# ----- per-container description / notes (before /containers/{id}) -----

class ContainerNotesBody(BaseModel):
    watched_key: str | None = None
    name: str | None = None
    compose_project: str | None = None
    compose_service: str | None = None
    description: str | None = None
    notes: str | None = None

    def key(self) -> str | None:
        if self.watched_key and self.watched_key.strip():
            return self.watched_key.strip()
        return None


def _resolve_notes_key(body: ContainerNotesBody) -> str:
    key = body.key()
    if key:
        return key
    return watched_key_for_container(
        {
            "name": body.name or "",
            "labels": {
                "com.docker.compose.project": body.compose_project or "",
                "com.docker.compose.service": body.compose_service or "",
            },
        }
    )


def _upsert_container_notes(body: ContainerNotesBody) -> dict[str, Any]:
    key = _resolve_notes_key(body)
    if not key or key in ("compose:/", "name:"):
        raise HTTPException(status_code=400, detail="watched_key or name required")
    try:
        existing = db.get_container_notes(key) or {
            "description": "",
            "notes": "",
        }
    except Exception:
        existing = {"description": "", "notes": ""}
    description = (
        body.description if body.description is not None else existing.get("description") or ""
    )
    notes = body.notes if body.notes is not None else existing.get("notes") or ""
    try:
        row = db.upsert_container_notes(key, description=description, notes=notes)
    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
            "watched_key": key,
            "description": description,
            "notes": notes,
            "updated_at": None,
        }
    return {"ok": True, **row}


@router.get("/containers/notes")
def list_container_notes() -> dict[str, Any]:
    """List all user description/notes (fail soft)."""
    try:
        return {"ok": True, "items": db.list_container_notes()}
    except Exception as exc:
        return {"ok": False, "items": [], "error": str(exc)}


@router.put("/containers/notes")
@router.patch("/containers/notes")
def put_container_notes(body: ContainerNotesBody) -> dict[str, Any]:
    """Create/update description and notes for a stable watched_key."""
    return _upsert_container_notes(body)


@router.get("/containers/{container_id}")
def container_detail(container_id: str) -> dict[str, Any]:
    rows = [_parse_raw(r) for r in db.latest_containers()]
    for r in rows:
        item = _container_item(r)
        if item["container_id"] == container_id or (
            item["name"] and item["name"] == container_id
        ):
            raw = r.get("raw") or {}
            apply_watched([raw])
            try:
                apply_container_notes([raw])
            except Exception:
                pass
            watched = bool(raw.get("watched", raw.get("vital")))
            watched_key = raw.get("watched_key") or raw.get("vital_key")
            item["watched"] = watched
            item["watched_key"] = watched_key
            item["vital"] = watched
            item["vital_key"] = watched_key
            item["description"] = raw.get("description") or ""
            item["notes"] = raw.get("notes") or ""
            item["security"] = raw.get("security") or item.get("security")
            item["inspect_summary"] = {
                "privileged": bool((raw.get("inspect") or {}).get("HostConfig", {}).get("Privileged")),
                "network_mode": ((raw.get("inspect") or {}).get("HostConfig") or {}).get(
                    "NetworkMode"
                ),
                "user": ((raw.get("inspect") or {}).get("Config") or {}).get("User") or "",
            }
            return item
    raise HTTPException(status_code=404, detail="Container not found in latest snapshot")


@router.get("/containers/{container_id}/logs")
def container_logs(container_id: str, tail: int = 150) -> dict[str, Any]:
    """Recent container logs via Docker API. Fail-soft (ok=false + error)."""
    return get_container_logs(container_id, tail=tail)


def _speed_test_payload() -> dict[str, Any]:
    cfg, src = resolve_speed_test()
    last = get_speed_test_last() or {}
    return {
        "enabled": bool(cfg.enabled),
        "interval_hours": float(cfg.interval_hours),
        "source": src,
        "busy": speed_test_busy(),
        "last": {
            "ok": last.get("ok"),
            "provider": last.get("provider"),
            "taken_at": last.get("taken_at"),
            "download_mbps": last.get("download_mbps"),
            "upload_mbps": last.get("upload_mbps"),
            "ping_ms": last.get("ping_ms"),
            "error": last.get("error"),
        }
        if last
        else None,
    }


@router.get("/host")
def host() -> dict[str, Any]:
    row = db.latest_host()
    speed = _speed_test_payload()
    if not row:
        return {"metrics": None, "taken_at": None, "speed_test": speed}
    parsed = _parse_raw(row)
    raw = parsed.get("raw") or {}
    return {
        "taken_at": parsed.get("taken_at"),
        "cpu_percent": parsed.get("cpu_percent"),
        "mem_percent": parsed.get("mem_percent"),
        "mem_used_bytes": parsed.get("mem_used_bytes"),
        "mem_total_bytes": parsed.get("mem_total_bytes"),
        "disk_percent": parsed.get("disk_percent"),
        "disk_used_bytes": parsed.get("disk_used_bytes"),
        "disk_total_bytes": parsed.get("disk_total_bytes"),
        # Empty list means "none selected" — do not fall back to fake "/".
        "disks": (
            raw["disks"]
            if isinstance(raw.get("disks"), list)
            else (
                [
                    {
                        "path": "/",
                        "mountpoint": "/",
                        "percent": parsed.get("disk_percent"),
                        "used_bytes": parsed.get("disk_used_bytes"),
                        "total_bytes": parsed.get("disk_total_bytes"),
                        "free_bytes": None,
                        "avail_bytes": None,
                        "mounted": True,
                    }
                ]
                if parsed.get("disk_percent") is not None
                else []
            )
        ),
        "disk_warn_percent": raw.get("disk_warn_percent", 85),
        "disk_source": raw.get("disk_source"),
        "disk_selection_needed": raw.get("disk_selection_needed"),
        "host_note": raw.get("host_note"),
        "host_root_mounted": raw.get("host_root_mounted"),
        "uptime_seconds": raw.get("uptime_seconds"),
        "load_avg": raw.get("load_avg") if isinstance(raw.get("load_avg"), list) else None,
        "network_interfaces": (
            raw["network_interfaces"]
            if isinstance(raw.get("network_interfaces"), list)
            else []
        ),
        "network_source": raw.get("network_source"),
        "network_note": raw.get("network_note"),
        "listening_ports": (
            raw["listening_ports"]
            if isinstance(raw.get("listening_ports"), list)
            else []
        ),
        "listening_ports_source": raw.get("listening_ports_source"),
        "listening_ports_note": raw.get("listening_ports_note"),
        "listening_ports_exposed_count": raw.get("listening_ports_exposed_count"),
        "listening_ports_enabled": raw.get("listening_ports_enabled"),
        "docker_published_ports": (
            raw["docker_published_ports"]
            if isinstance(raw.get("docker_published_ports"), list)
            else []
        ),
        "docker_published_ports_count": raw.get("docker_published_ports_count"),
        "docker_published_ports_exposed_count": raw.get(
            "docker_published_ports_exposed_count"
        ),
        "docker_published_ports_note": raw.get("docker_published_ports_note"),
        "speed_test": speed,
    }


@router.post("/host/speed-test")
def run_host_speed_test() -> dict[str, Any]:
    """Kick off an on-demand speed check in a background thread (non-blocking)."""
    if not mark_speed_test_pending():
        return {"ok": False, "started": False, "busy": True, "speed_test": _speed_test_payload()}

    def _run() -> None:
        try:
            speed_test_once(force=True)
        except Exception:
            clear_speed_test_pending()

    threading.Thread(target=_run, daemon=True, name="speed-test").start()
    return {"ok": True, "started": True, "busy": True, "speed_test": _speed_test_payload()}


def _check_results_payload() -> dict[str, Any]:
    """Latest custom/Plex HTTP/ping/DNS check results (not container stars)."""
    rows = [_parse_raw(r) for r in db.latest_checks()]
    items = []
    for r in rows:
        history = db.recent_check_history(r["name"], limit=12)
        items.append(
            {
                "name": r.get("name"),
                "check_type": r.get("check_type"),
                "ok": bool(r.get("ok")),
                "latency_ms": r.get("latency_ms"),
                "message": r.get("message"),
                "detail": r.get("detail") or {},
                "taken_at": r.get("taken_at"),
                "recent": [
                    {
                        "ok": bool(h.get("ok")),
                        "taken_at": h.get("taken_at"),
                        "message": h.get("message"),
                    }
                    for h in history
                ],
            }
        )
    targets, source = resolve_targets()
    return {
        "items": items,
        "taken_at": items[0]["taken_at"] if items else None,
        "config_source": source,
        "configured_targets": [t.model_dump() for t in targets],
    }


@router.get("/checks")
def checks() -> dict[str, Any]:
    return _check_results_payload()


# ----- starred containers (importance flag; formerly "vital") -----

class WatchedBody(BaseModel):
    watched_key: str | None = None
    vital_key: str | None = None  # one-release alias
    name: str | None = None
    compose_project: str | None = None
    compose_service: str | None = None
    watched: bool | None = None
    vital: bool | None = None  # one-release alias

    def starred(self) -> bool:
        if self.watched is not None:
            return bool(self.watched)
        if self.vital is not None:
            return bool(self.vital)
        return True

    def key(self) -> str | None:
        return self.watched_key or self.vital_key


def _set_starred_container(body: WatchedBody) -> dict[str, Any]:
    key = body.key()
    if not key:
        key = watched_key_for_container(
            {
                "name": body.name or "",
                "labels": {
                    "com.docker.compose.project": body.compose_project or "",
                    "com.docker.compose.service": body.compose_service or "",
                },
            }
        )
    starred = body.starred()
    if starred:
        db.set_watched_container(
            key,
            name=body.name,
            compose_project=body.compose_project,
            compose_service=body.compose_service,
        )
    else:
        db.clear_watched_container(key)
    return {
        "ok": True,
        "watched_key": key,
        "watched": starred,
        # One-release aliases
        "vital_key": key,
        "vital": starred,
    }


@router.get("/watched")
def get_watched() -> dict[str, Any]:
    """List starred (important) containers."""
    return {"items": db.list_watched_containers()}


@router.post("/watched")
def set_watched(body: WatchedBody) -> dict[str, Any]:
    """Star or unstar a container (digest when starred and not running)."""
    return _set_starred_container(body)


@router.get("/vitals")
def get_vitals() -> dict[str, Any]:
    """Deprecated alias for GET /api/watched."""
    return get_watched()


@router.post("/vitals")
def set_vital(body: WatchedBody) -> dict[str, Any]:
    """Deprecated alias for POST /api/watched."""
    return _set_starred_container(body)


@router.get("/notable")
def notable() -> dict[str, Any]:
    return collect_notable()


@router.post("/poll")
def trigger_poll() -> dict[str, Any]:
    poll_once()
    return {"ok": True, **get_poll_status()}


@router.post("/digest/test")
def test_digest(profile_id: str | None = None) -> dict[str, Any]:
    result = send_digest(force=True, profile_id=profile_id)
    if not result.get("sent") and "not configured" in str(result.get("reason", "")).lower():
        raise HTTPException(status_code=400, detail=result)
    if not result.get("sent") and "not found" in str(result.get("reason", "")).lower():
        raise HTTPException(status_code=404, detail=result)
    return result


# ----- container actions -----

class UpdateBody(BaseModel):
    confirm: bool = False


class ActionConfirmBody(BaseModel):
    """Shared confirm body for stop / start / restart / pause / unpause / kill."""

    confirm: bool = False


class RestartBody(BaseModel):
    confirm: bool = False


class TeardownBody(BaseModel):
    confirm: bool = False
    remove_container: bool = True
    remove_image: bool = False
    remove_volumes: bool = False


class DockerPruneBody(BaseModel):
    confirm: bool = False
    containers: bool = False
    images: bool = False
    images_all_unused: bool = False
    build_cache: bool = False
    build_cache_all: bool = False
    volumes: bool = False
    volumes_confirm: bool = False
    networks: bool = False


def _require_actions() -> None:
    if not actions_enabled():
        raise HTTPException(
            status_code=403,
            detail="Container actions are disabled in Settings → General",
        )


def _require_action_confirm(confirm: bool) -> None:
    _require_actions()
    if not confirm:
        raise HTTPException(status_code=400, detail="confirm must be true")


@router.get("/docker/df")
def docker_df() -> dict[str, Any]:
    """Disk usage snapshot (images, containers, volumes, build cache). Fail-soft."""
    return get_docker_disk_usage()


@router.post("/docker/prune")
def docker_prune(body: DockerPruneBody) -> dict[str, Any]:
    _require_actions()
    if not body.confirm:
        raise HTTPException(status_code=400, detail="confirm must be true")
    if body.volumes and not body.volumes_confirm:
        raise HTTPException(
            status_code=400,
            detail="volumes_confirm must be true to prune unused volumes",
        )
    if not any(
        (
            body.containers,
            body.images,
            body.build_cache,
            body.volumes,
            body.networks,
        )
    ):
        raise HTTPException(status_code=400, detail="Nothing selected to prune")
    try:
        job = start_docker_prune_job(
            containers=body.containers,
            images=body.images,
            images_all_unused=body.images_all_unused,
            build_cache=body.build_cache,
            build_cache_all=body.build_cache_all,
            volumes=body.volumes,
            networks=body.networks,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"ok": True, "job": job}


@router.post("/containers/{container_id}/update")
def update_container(container_id: str, body: UpdateBody) -> dict[str, Any]:
    _require_action_confirm(body.confirm)
    job = start_update_job(container_id)
    return {"ok": True, "job": job}


@router.post("/containers/{container_id}/stop")
def stop_container(container_id: str, body: ActionConfirmBody) -> dict[str, Any]:
    _require_action_confirm(body.confirm)
    job = start_stop_job(container_id)
    return {"ok": True, "job": job}


@router.post("/containers/{container_id}/start")
def start_container(container_id: str, body: ActionConfirmBody) -> dict[str, Any]:
    _require_action_confirm(body.confirm)
    job = start_start_job(container_id)
    return {"ok": True, "job": job}


@router.post("/containers/{container_id}/restart")
def restart_container(container_id: str, body: RestartBody) -> dict[str, Any]:
    _require_action_confirm(body.confirm)
    job = start_restart_job(container_id)
    return {"ok": True, "job": job}


@router.post("/containers/{container_id}/pause")
def pause_container(container_id: str, body: ActionConfirmBody) -> dict[str, Any]:
    _require_action_confirm(body.confirm)
    job = start_pause_job(container_id)
    return {"ok": True, "job": job}


@router.post("/containers/{container_id}/unpause")
def unpause_container(container_id: str, body: ActionConfirmBody) -> dict[str, Any]:
    _require_action_confirm(body.confirm)
    job = start_unpause_job(container_id)
    return {"ok": True, "job": job}


@router.post("/containers/{container_id}/kill")
def kill_container(container_id: str, body: ActionConfirmBody) -> dict[str, Any]:
    _require_action_confirm(body.confirm)
    job = start_kill_job(container_id)
    return {"ok": True, "job": job}


@router.post("/containers/{container_id}/teardown")
def teardown_container(container_id: str, body: TeardownBody) -> dict[str, Any]:
    _require_action_confirm(body.confirm)
    if not body.remove_container and not body.remove_image:
        raise HTTPException(status_code=400, detail="Nothing selected to remove")
    job = start_teardown_job(
        container_id,
        remove_container=body.remove_container,
        remove_image=body.remove_image,
        remove_volumes=body.remove_volumes,
    )
    return {"ok": True, "job": job}


@router.get("/jobs/{job_id}")
def job_status(job_id: str) -> dict[str, Any]:
    job = get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job

# ----- settings -----

@router.get("/settings")
def get_all_settings() -> dict[str, Any]:
    general, gsrc = resolve_general()
    targets, tsrc = resolve_targets()
    thresholds, dsrc = resolve_thresholds()
    security, ssrc = resolve_security()
    listening_ports, lpsrc = resolve_listening_ports()
    speed_test, stsrc = resolve_speed_test()
    plex, psrc = resolve_plex()
    return {
        "general": {**general, "source": gsrc},
        "plex": {**plex, "source": psrc},
        # Custom HTTP/ping/DNS targets (not container stars; no Settings "Watched" brand).
        "checks": {
            "targets": [t.model_dump() for t in targets],
            "source": tsrc,
        },
        # One-release alias for older clients still reading settings.watched
        "watched": {
            "targets": [t.model_dump() for t in targets],
            "source": tsrc,
        },
        "pihole": pihole_public_view(),
        "networking": networking_public_view(),
        "digest": digest_public_view(),
        "security": security_public_view(security, ssrc),
        "listening_ports": {
            **listening_ports.model_dump(),
            "source": lpsrc,
        },
        "speed_test": {
            **speed_test.model_dump(),
            "source": stsrc,
            "last": get_speed_test_last(),
            "busy": speed_test_busy(),
        },
        "disks": {
            **thresholds.model_dump(),
            "source": dsrc,
        },
        "notes": {
            "secrets_in_db": (
                "Pi-hole password/token, Resend API key, and optional SCM/OpenSCA "
                "tokens may be stored in the SQLite DB on the watcher-data volume. "
                "Treat that volume as sensitive."
            ),
            "socket": (
                "Update / lifecycle (stop, start, restart, pause, kill) / tear-down / "
                "Docker reclaim need a writable docker.sock mount (not :ro). Disable "
                "actions in General if you prefer read-only."
            ),
            "compose_updates": (
                "Update only works for Docker Compose services via "
                "`docker compose pull` + `up -d`. Stop / start / restart prefer "
                "`compose stop|start|restart` when the project directory is visible; "
                "otherwise the Docker Engine API is used. Pause / unpause use the "
                "Engine API; kill prefers `compose kill` when possible. Standalone "
                "containers support lifecycle actions but cannot be updated from the UI."
            ),
            "host_disks": (
                "Watcher discovers mounts like df; you pick which ones to monitor. "
                "Compose mounts /:/host:ro (read-only) so usage comes from the real "
                "host. That exposes mount paths and capacity — lower risk than a "
                "writable docker.sock, but still private homelab detail."
            ),
            "listening_ports": (
                "Listening ports are read from host /proc/net (via HOST_PROC) when "
                "/:/host:ro is mounted — an inventory of sockets already listening, "
                "not a network scan. Process/container names are best-effort."
            ),
            "speed_test": (
                "Optional Internet speed check uses Cloudflare’s public "
                "speed.cloudflare.com endpoints (no API key). Downloads ~5 MiB and "
                "uploads ~2 MiB; keep the interval infrequent or use Run now."
            ),
            "trivy": (
                "Image vulnerability scanning needs the Docker image (includes Trivy). "
                "A local venv will not have Trivy unless you install it yourself."
            ),
            "opensca": (
                "SCM/OpenSCA scans need the Docker image (includes git + OpenSCA-cli). "
                "A local venv will not have them unless you install them yourself. "
                "Optional GIT_TOKEN/SCM_TOKEN (or Settings) for private repos."
            ),
            "starred": (
                "Star a container on the Containers page to mark it important. "
                "Digests call out starred containers that are not running."
            ),
        },
    }


class GeneralSettingsBody(BaseModel):
    poll_interval_seconds: int | None = None
    registry_cache_hours: float | None = None
    actions_enabled: bool | None = None


@router.put("/settings/general")
def put_general(body: GeneralSettingsBody) -> dict[str, Any]:
    cur = db.get_setting("general") or {}
    if not isinstance(cur, dict):
        cur = {}
    data = {**cur, "configured": True}
    for k, v in body.model_dump(exclude_none=True).items():
        data[k] = v
    if "poll_interval_seconds" in data:
        data["poll_interval_seconds"] = max(60, int(data["poll_interval_seconds"]))
    db.set_setting("general", data)
    reschedule_poll()
    general, source = resolve_general()
    return {"ok": True, "general": {**general, "source": source}}


class ChecksSettingsBody(BaseModel):
    targets: list[dict[str, Any]] = Field(default_factory=list)


def _put_check_targets(body: ChecksSettingsBody) -> dict[str, Any]:
    validated = [TargetConfig.model_validate(t).model_dump() for t in body.targets]
    save_check_targets(validated)
    targets, source = resolve_targets()
    payload = {"targets": [t.model_dump() for t in targets], "source": source}
    return {
        "ok": True,
        "checks": payload,
        # One-release alias
        "watched": payload,
    }


@router.put("/settings/checks")
def put_checks(body: ChecksSettingsBody) -> dict[str, Any]:
    """Save custom HTTP/ping/DNS check targets."""
    return _put_check_targets(body)


@router.put("/settings/watched")
def put_watched(body: ChecksSettingsBody) -> dict[str, Any]:
    """Deprecated alias for PUT /api/settings/checks."""
    return _put_check_targets(body)


class PlexSettingsBody(BaseModel):
    enabled: bool = True
    url: str = ""
    verify_tls: bool = True


@router.put("/settings/plex")
def put_plex(body: PlexSettingsBody) -> dict[str, Any]:
    data = {
        "configured": True,
        "enabled": body.enabled,
        "url": (body.url or "").strip(),
        "verify_tls": body.verify_tls,
    }
    db.set_setting("plex", data)
    plex, source = resolve_plex()
    return {"ok": True, "plex": {**plex, "source": source}}


@router.post("/settings/plex/test")
def test_plex(body: PlexSettingsBody | None = None) -> dict[str, Any]:
    """One-shot HTTP check against the Plex identity URL (draft or saved)."""
    if body and (body.url or "").strip():
        target = TargetConfig(
            name="Plex",
            type="http",
            url=body.url.strip(),
            verify_tls=body.verify_tls,
        )
    else:
        target = plex_as_target()
    if not target:
        return {
            "ok": False,
            "message": "Set a Plex URL first (e.g. http://host.docker.internal:32400/identity).",
        }
    result = check_http(target)
    return {
        "ok": bool(result.get("ok")),
        "message": result.get("message"),
        "latency_ms": result.get("latency_ms"),
        "detail": result.get("detail") or {},
    }


class PiHoleSettingsBody(BaseModel):
    url: str = ""
    version: str = "auto"
    verify_tls: bool = True
    password: str | None = None  # None = leave unchanged; "" = clear
    api_token: str | None = None
    clear_password: bool = False
    clear_api_token: bool = False


@router.put("/settings/pihole")
def put_pihole(body: PiHoleSettingsBody) -> dict[str, Any]:
    cur = db.get_setting("pihole") or {}
    if not isinstance(cur, dict):
        cur = {}
    data = {
        **cur,
        "url": (body.url or "").strip(),
        "version": body.version if body.version in ("auto", "5", "6") else "auto",
        "verify_tls": body.verify_tls,
    }
    if body.clear_password:
        data["password"] = ""
    elif body.password is not None and body.password != "":
        data["password"] = body.password
    if body.clear_api_token:
        data["api_token"] = ""
    elif body.api_token is not None and body.api_token != "":
        data["api_token"] = body.api_token
    db.set_setting("pihole", data)
    # Keep Local DNS page in sync with saved settings (same fetch as Test).
    try:
        if (data.get("url") or "").strip():
            refresh_pihole_dns_snapshot()
    except Exception as exc:
        logger.warning("Pi-hole save snapshot refresh skipped: %s", exc)
    return {"ok": True, "pihole": pihole_public_view()}


@router.post("/settings/pihole/test")
def test_pihole() -> dict[str, Any]:
    """Fetch DNS records with saved credentials — confirms discovery works.

    Always returns a clear message: record count on success, or why it failed.
    Never a silent zero without explanation.
    Also updates the /api/dns snapshot so Local DNS matches this Test.
    """
    cfg, password, token, _src = resolve_pihole()
    if not (cfg.url or "").strip():
        return {
            "ok": False,
            "configured": False,
            "message": "Set a Pi-hole URL and save first.",
            "record_count": 0,
            "version": None,
        }
    if not (password or "").strip() and not (token or "").strip():
        return {
            "ok": False,
            "configured": True,
            "message": "Save a password (v6) or API token (v5) first.",
            "record_count": 0,
            "version": cfg.version,
        }
    result = fetch_pihole_dns(
        cfg, password_override=password, token_override=token
    )
    # Same records the DNS page shows — do not leave a stale poll error.
    apply_pihole_result(result)
    count = len(result.records)
    if result.ok:
        msg = result.message or (
            f"OK — {count} local/custom DNS records"
            if count
            else (
                "Connected — 0 Local DNS records "
                "(API list empty; not an auth/endpoint failure)"
            )
        )
    else:
        msg = result.message or "Failed to fetch Pi-hole DNS records"
    return {
        "ok": bool(result.ok),
        "configured": bool(result.configured),
        "version": result.version,
        "message": msg,
        "record_count": count,
    }


class NetworkingSettingsBody(BaseModel):
    proxy_type: str = "none"
    caddy_use_admin_api: bool = False
    caddy_admin_url: str = "http://host.docker.internal:2019"
    caddy_use_caddyfile: bool = False
    caddy_caddyfile_path: str = "/config/Caddyfile"
    caddy_use_labels: bool = True
    verify_tls: bool = True
    timeout_seconds: float = 5.0


@router.put("/settings/networking")
def put_networking(body: NetworkingSettingsBody) -> dict[str, Any]:
    proxy = (body.proxy_type or "none").lower().strip()
    if proxy not in ("none", "caddy", "traefik"):
        proxy = "none"
    data = {
        "proxy_type": proxy,
        "caddy_use_admin_api": bool(body.caddy_use_admin_api),
        "caddy_admin_url": (body.caddy_admin_url or "").strip()
        or "http://host.docker.internal:2019",
        "caddy_use_caddyfile": bool(body.caddy_use_caddyfile),
        "caddy_caddyfile_path": (body.caddy_caddyfile_path or "").strip()
        or "/config/Caddyfile",
        "caddy_use_labels": bool(body.caddy_use_labels),
        "verify_tls": bool(body.verify_tls),
        "timeout_seconds": float(body.timeout_seconds or 5.0),
    }
    db.set_setting("networking", data)
    return {"ok": True, "networking": networking_public_view()}


@router.post("/settings/networking/test")
def test_networking() -> dict[str, Any]:
    """Discover proxy routes with saved settings — read-only."""
    from app.docker_client import list_containers
    from app.networking import discover_and_enrich
    from app.scheduler import get_last_caddy, store_networking_result

    cfg, _ = resolve_networking()
    if cfg.proxy_type == "none":
        return {
            "ok": False,
            "configured": False,
            "message": "Set proxy type to Caddy (or Traefik) and save first.",
            "route_count": 0,
            "mapped_count": 0,
            "errors": [],
            "sources_tried": [],
        }
    if cfg.proxy_type == "traefik":
        return {
            "ok": False,
            "configured": True,
            "message": "Traefik route discovery is coming soon.",
            "route_count": 0,
            "mapped_count": 0,
            "errors": [],
            "sources_tried": [],
            "proxy_type": "traefik",
        }
    try:
        containers = list_containers()
    except Exception:
        containers = []
    status = discover_and_enrich(
        containers,
        proxy_type=cfg.proxy_type,
        use_admin_api=cfg.caddy_use_admin_api,
        admin_url=cfg.caddy_admin_url,
        use_caddyfile=cfg.caddy_use_caddyfile,
        caddyfile_path=cfg.caddy_caddyfile_path,
        use_labels=cfg.caddy_use_labels,
        verify_tls=cfg.verify_tls,
        timeout=cfg.timeout_seconds,
        pihole=None,
    )
    # Refresh Caddy page snapshot immediately after Test
    try:
        store_networking_result(dict(status))
    except Exception:
        pass
    ok = bool(status.get("ok")) and int(status.get("route_count") or 0) > 0
    if status.get("ok") and int(status.get("route_count") or 0) == 0:
        ok = False
    msg = status.get("message")
    if ok:
        msg = f"OK — {status.get('route_count', 0)} routes discovered"
    elif status.get("errors"):
        msg = "; ".join(status.get("errors") or [])
    snap = get_last_caddy()
    return {
        "ok": ok,
        "configured": bool(status.get("configured")),
        "proxy_type": status.get("proxy_type"),
        "message": msg or "Failed",
        "route_count": int(status.get("route_count") or 0),
        "mapped_count": int(status.get("mapped_count") or 0),
        "errors": status.get("errors") or [],
        "sources_tried": status.get("sources_tried") or [],
        "records": snap.get("records") or [],
    }


@router.get("/disks/discover")
def disks_discover() -> dict[str, Any]:
    """df-style mount list for Settings checkboxes (not yet filtered by selection)."""
    disks, note, source = discover_disks()
    thresholds, _ = resolve_thresholds()
    return {
        "disks": disks,
        "note": note,
        "source": source,
        "selected": list(thresholds.disks or []),
        "disk_warn_percent": thresholds.disk_warn_percent,
        "host_root_mounted": host_root_available(),
    }


@router.get("/files/browse")
def files_browse(path: str = "/") -> dict[str, Any]:
    """
    Read-only directory listing under HOST_ROOT (same mount as disk discover).

    ``path`` is a host path (e.g. /etc/caddy). Cannot escape the host mount.
    """
    from app.file_browse import browse_host_path

    return browse_host_path(path)


@router.get("/settings/disks")
def get_disks() -> dict[str, Any]:
    """Selected mounts + warn threshold (empty selected = monitor nothing)."""
    thresholds, source = resolve_thresholds()
    return {
        "disk_warn_percent": thresholds.disk_warn_percent,
        "disks": list(thresholds.disks or []),
        "alert_on_exited": thresholds.alert_on_exited,
        "source": source,
    }


class DigestProfileBody(BaseModel):
    id: str | None = None
    name: str | None = None
    enabled: bool | None = None
    digest_from: str | None = None
    digest_to: str | None = None
    digest_send_all_clear: bool | None = None
    tz: str | None = None
    schedule_frequency: str | None = None  # daily | weekly | "" to clear
    schedule_weekday: str | None = None
    schedule_hour: int | None = None
    schedule_minute: int | None = None


class DigestSettingsBody(BaseModel):
    resend_api_key: str | None = None  # None leave; "" clear via clear flag
    clear_resend_api_key: bool = False
    profiles: list[DigestProfileBody] | None = None
    # Legacy single-digest fields (still accepted → one profile on save)
    enabled: bool | None = None
    digest_from: str | None = None
    digest_to: str | None = None
    digest_send_all_clear: bool | None = None
    tz: str | None = None
    schedule_frequency: str | None = None
    schedule_weekday: str | None = None
    schedule_hour: int | None = None
    schedule_minute: int | None = None


@router.put("/settings/digest")
def put_digest(body: DigestSettingsBody) -> dict[str, Any]:
    from app.digest_schedule import schedule_to_cron
    from app.runtime_settings import _new_digest_profile_id, resolve_digest_settings

    cur = db.get_setting("digest") or {}
    if not isinstance(cur, dict):
        cur = {}
    # Ensure migration ran so we start from profiles shape
    resolved, _ = resolve_digest_settings()
    cur = db.get_setting("digest") or cur
    if not isinstance(cur, dict):
        cur = {}
    existing_profiles = list(resolved.get("profiles") or [])
    existing_by_id = {str(p.get("id")): p for p in existing_profiles}

    data: dict[str, Any] = {
        "configured": True,
        "resend_api_key": cur.get("resend_api_key")
        if isinstance(cur.get("resend_api_key"), str)
        else (cur.get("resend_api_key") or ""),
    }

    if body.clear_resend_api_key:
        data["resend_api_key"] = ""
    elif body.resend_api_key is not None and body.resend_api_key != "":
        data["resend_api_key"] = body.resend_api_key

    def _finalize_profile(raw: dict[str, Any]) -> dict[str, Any]:
        freq = raw.get("schedule_frequency")
        if freq == "" or freq is None:
            raw["schedule_frequency"] = None
            raw["schedule_weekday"] = None
            raw["schedule_hour"] = None
            raw["schedule_minute"] = None
            raw["digest_cron"] = ""
        derived = schedule_to_cron(
            raw.get("schedule_frequency"),
            weekday=raw.get("schedule_weekday"),
            hour=raw.get("schedule_hour"),
            minute=raw.get("schedule_minute"),
        )
        if derived:
            raw["digest_cron"] = derived
        elif raw.get("schedule_frequency") in ("daily", "weekly"):
            raise HTTPException(
                status_code=400,
                detail="Pick a complete schedule (frequency, time, and day if weekly).",
            )
        else:
            raw["digest_cron"] = ""
        pid = str(raw.get("id") or "").strip() or _new_digest_profile_id()
        name = str(raw.get("name") or "Digest").strip() or "Digest"
        return {
            "id": pid,
            "name": name,
            "enabled": bool(raw.get("enabled", False)),
            "digest_from": raw.get("digest_from") or "",
            "digest_to": raw.get("digest_to") or "",
            "digest_send_all_clear": bool(raw.get("digest_send_all_clear", True)),
            "tz": (raw.get("tz") or "UTC").strip() or "UTC",
            "schedule_frequency": raw.get("schedule_frequency"),
            "schedule_weekday": (
                str(raw["schedule_weekday"])
                if raw.get("schedule_weekday") is not None
                and raw.get("schedule_weekday") != ""
                else None
            ),
            "schedule_hour": raw.get("schedule_hour"),
            "schedule_minute": raw.get("schedule_minute"),
            "digest_cron": raw.get("digest_cron") or "",
        }

    if body.profiles is not None:
        profiles_out: list[dict[str, Any]] = []
        for item in body.profiles:
            payload = item.model_dump(exclude_none=False)
            pid = str(payload.get("id") or "").strip()
            base = dict(existing_by_id.get(pid) or {})
            for k, v in payload.items():
                if k == "id" and not v:
                    continue
                if v is not None:
                    base[k] = v
                elif k in (
                    "schedule_frequency",
                    "schedule_weekday",
                    "schedule_hour",
                    "schedule_minute",
                ):
                    base[k] = None
            if not base.get("id"):
                base["id"] = _new_digest_profile_id()
            profiles_out.append(_finalize_profile(base))
        if not profiles_out:
            raise HTTPException(status_code=400, detail="Keep at least one digest profile.")
        data["profiles"] = profiles_out
    else:
        # Legacy single-digest PUT → upsert first/Default profile
        base = dict(existing_profiles[0]) if existing_profiles else {
            "id": _new_digest_profile_id(),
            "name": "Default",
            "enabled": False,
            "digest_from": "",
            "digest_to": "",
            "digest_send_all_clear": True,
            "tz": "UTC",
        }
        legacy = body.model_dump(exclude_none=True)
        for k in (
            "enabled",
            "digest_from",
            "digest_to",
            "digest_send_all_clear",
            "tz",
            "schedule_frequency",
            "schedule_weekday",
            "schedule_hour",
            "schedule_minute",
        ):
            if k in legacy:
                base[k] = legacy[k]
        if "schedule_frequency" in legacy and legacy.get("schedule_frequency") in ("", None):
            base["schedule_frequency"] = None
            base["schedule_weekday"] = None
            base["schedule_hour"] = None
            base["schedule_minute"] = None
        rest = [p for p in existing_profiles[1:]] if existing_profiles else []
        data["profiles"] = [_finalize_profile(base), *rest]

    db.set_setting("digest", data)
    reschedule_digest()
    return {"ok": True, "digest": digest_public_view()}


class SecuritySettingsBody(BaseModel):
    enabled: bool | None = None
    notable_severity: str | None = None
    notable_posture_severity: str | None = None
    trivy: dict[str, Any] | None = None
    posture: dict[str, Any] | None = None
    opensca: dict[str, Any] | None = None


@router.put("/settings/security")
def put_security(body: SecuritySettingsBody) -> dict[str, Any]:
    cur = db.get_setting("security") or {}
    if not isinstance(cur, dict):
        cur = {}
    data = {**cur, "configured": True}
    if body.enabled is not None:
        data["enabled"] = body.enabled
    if body.notable_severity is not None:
        data["notable_severity"] = body.notable_severity.upper()
    if body.notable_posture_severity is not None:
        data["notable_posture_severity"] = body.notable_posture_severity.lower()
    if body.trivy is not None:
        data["trivy"] = {**(cur.get("trivy") or {}), **body.trivy}
    if body.posture is not None:
        data["posture"] = {**(cur.get("posture") or {}), **body.posture}
    if body.opensca is not None:
        prev = dict(cur.get("opensca") or {})
        incoming = dict(body.opensca)
        # Empty token fields mean "leave unchanged"
        if incoming.get("git_token") == "":
            incoming.pop("git_token", None)
        if incoming.get("opensca_token") == "":
            incoming.pop("opensca_token", None)
        # Drop UI-only flags
        for k in (
            "has_git_token",
            "has_opensca_token",
            "git_token_in_db",
            "opensca_token_in_db",
            "opensca_available",
        ):
            incoming.pop(k, None)
        data["opensca"] = {**prev, **incoming}
    db.set_setting("security", data)
    security, source = resolve_security()
    return {
        "ok": True,
        "security": security_public_view(security, source),
    }


class DisksSettingsBody(BaseModel):
    disk_warn_percent: float | None = None
    disks: list[str] | None = None
    alert_on_exited: bool | None = None


@router.put("/settings/disks")
def put_disks(body: DisksSettingsBody) -> dict[str, Any]:
    cur = db.get_setting("disks") or {}
    if not isinstance(cur, dict):
        cur = {}
    data = {**cur, "configured": True}
    for k, v in body.model_dump(exclude_none=True).items():
        data[k] = v
    if "disks" in data and isinstance(data["disks"], list):
        # Normalize mount paths; preserve order; empty list = monitor nothing.
        seen: set[str] = set()
        cleaned: list[str] = []
        for p in data["disks"]:
            s = str(p).strip()
            if not s or s in seen:
                continue
            seen.add(s)
            cleaned.append(s)
        data["disks"] = cleaned
    db.set_setting("disks", data)
    thresholds, source = resolve_thresholds()
    return {"ok": True, "disks": {**thresholds.model_dump(), "source": source}}


class ListeningPortsSettingsBody(BaseModel):
    enabled: bool | None = None


@router.put("/settings/listening_ports")
def put_listening_ports(body: ListeningPortsSettingsBody) -> dict[str, Any]:
    cur = db.get_setting("listening_ports") or {}
    if not isinstance(cur, dict):
        cur = {}
    data = {**cur, "configured": True}
    if body.enabled is not None:
        data["enabled"] = body.enabled
    db.set_setting("listening_ports", data)
    cfg, source = resolve_listening_ports()
    return {"ok": True, "listening_ports": {**cfg.model_dump(), "source": source}}


class SpeedTestSettingsBody(BaseModel):
    enabled: bool | None = None
    interval_hours: float | None = None


@router.put("/settings/speed_test")
def put_speed_test(body: SpeedTestSettingsBody) -> dict[str, Any]:
    cur = db.get_setting("speed_test") or {}
    if not isinstance(cur, dict):
        cur = {}
    data = {**cur, "configured": True}
    if body.enabled is not None:
        data["enabled"] = body.enabled
    if body.interval_hours is not None:
        data["interval_hours"] = max(0.0, float(body.interval_hours))
    db.set_setting("speed_test", data)
    reschedule_speed_test()
    cfg, source = resolve_speed_test()
    return {
        "ok": True,
        "speed_test": {
            **cfg.model_dump(),
            "source": source,
            "last": get_speed_test_last(),
            "busy": speed_test_busy(),
        },
    }


@router.get("/config/targets")
def config_targets() -> dict[str, Any]:
    cfg = effective_yaml_overlay()
    return {
        "targets": [t.model_dump() for t in cfg.targets],
        "thresholds": cfg.thresholds.model_dump(),
        "container_urls": dict(cfg.container_urls),
        "pihole": pihole_public_view(),
        "networking": networking_public_view(),
        "security": cfg.security.model_dump(),
        "listening_ports": cfg.listening_ports.model_dump(),
        "speed_test": cfg.speed_test.model_dump(),
    }
