"""Per-container Compose auto-update policies and scheduled runs."""

from __future__ import annotations

import json
import logging
from typing import Any

from app import db
from app.container_actions import start_update_job
from app.digest import next_cron_fire
from app.digest_schedule import (
    is_schedule_complete,
    schedule_summary,
    schedule_to_cron,
)
from app.docker_client import list_containers
from app.runtime_settings import actions_enabled, watched_key_for_container

logger = logging.getLogger(__name__)


def policy_public_view(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize a DB/API policy row for the UI (includes schedule summary)."""
    freq = row.get("schedule_frequency")
    weekday = row.get("schedule_weekday")
    hour = row.get("schedule_hour")
    minute = row.get("schedule_minute")
    tz = (row.get("tz") or "UTC").strip() or "UTC"
    cron = (row.get("cron") or "").strip()
    if not cron:
        cron = (
            schedule_to_cron(
                freq,
                weekday=weekday,
                hour=hour,
                minute=minute,
            )
            or ""
        )
    scheduled = bool(
        is_schedule_complete(
            {
                "digest_cron": cron,
                "schedule_frequency": freq,
                "schedule_weekday": weekday,
                "schedule_hour": hour,
                "schedule_minute": minute,
            }
        )
    )
    enabled = bool(row.get("enabled"))
    next_at = next_cron_fire(cron, tz) if enabled and scheduled and cron else None
    return {
        "watched_key": row.get("watched_key"),
        "enabled": enabled,
        "schedule_frequency": freq,
        "schedule_weekday": weekday,
        "schedule_hour": hour,
        "schedule_minute": minute,
        "cron": cron or None,
        "tz": tz,
        "only_when_available": bool(row.get("only_when_available", True)),
        "name": row.get("name"),
        "compose_project": row.get("compose_project"),
        "compose_service": row.get("compose_service"),
        "scheduled": scheduled,
        "schedule_summary": schedule_summary(
            frequency=freq if isinstance(freq, str) else None,
            weekday=str(weekday) if weekday is not None else None,
            hour=int(hour) if hour is not None else None,
            minute=int(minute) if minute is not None else None,
            tz=tz,
        ),
        "next_at": next_at,
        "last_run_at": row.get("last_run_at"),
        "last_status": row.get("last_status"),
        "last_message": row.get("last_message"),
        "last_job_id": row.get("last_job_id"),
        "updated_at": row.get("updated_at"),
    }


def normalize_policy_input(data: dict[str, Any]) -> dict[str, Any]:
    """Validate UI fields and derive cron. Raises ValueError on bad input."""
    freq = data.get("schedule_frequency") or None
    if freq == "":
        freq = None
    weekday = data.get("schedule_weekday")
    if weekday is not None and str(weekday).strip() == "":
        weekday = None
    hour = data.get("schedule_hour")
    minute = data.get("schedule_minute")
    if hour is not None:
        try:
            hour = int(hour)
        except (TypeError, ValueError) as exc:
            raise ValueError("schedule_hour must be an integer 0–23") from exc
    if minute is not None:
        try:
            minute = int(minute)
        except (TypeError, ValueError) as exc:
            raise ValueError("schedule_minute must be an integer 0–59") from exc

    enabled = bool(data.get("enabled"))
    only_when_available = data.get("only_when_available")
    if only_when_available is None:
        only_when_available = True
    else:
        only_when_available = bool(only_when_available)

    tz = (data.get("tz") or "UTC").strip() or "UTC"
    cron = schedule_to_cron(freq, weekday=weekday, hour=hour, minute=minute)

    if enabled and cron is None:
        raise ValueError(
            "Enabled auto-update requires a complete schedule "
            "(daily or weekly with a time)"
        )

    return {
        "enabled": enabled,
        "schedule_frequency": freq,
        "schedule_weekday": str(weekday) if weekday is not None else None,
        "schedule_hour": hour,
        "schedule_minute": minute,
        "cron": cron,
        "tz": tz,
        "only_when_available": only_when_available,
        "name": (data.get("name") or None),
        "compose_project": data.get("compose_project"),
        "compose_service": data.get("compose_service"),
    }


def _parse_snapshot_raw(row: dict[str, Any]) -> dict[str, Any]:
    raw = row.get("raw")
    if isinstance(raw, dict):
        return raw
    raw_json = row.get("raw_json")
    if isinstance(raw_json, str):
        try:
            parsed = json.loads(raw_json)
            return parsed if isinstance(parsed, dict) else {}
        except Exception:
            return {}
    if isinstance(raw_json, dict):
        return raw_json
    return {}


def _snapshot_update_available(watched_key: str) -> bool | None:
    """Return update_available from the latest poll snapshot, if found."""
    try:
        rows = db.latest_containers()
    except Exception as exc:
        logger.warning("Auto-update: snapshot lookup failed: %s", exc)
        return None
    for r in rows:
        raw = _parse_snapshot_raw(r)
        labels = dict(raw.get("labels") or {})
        project = (
            labels.get("com.docker.compose.project")
            or raw.get("compose_project")
            or ""
        )
        service = (
            labels.get("com.docker.compose.service")
            or raw.get("compose_service")
            or ""
        )
        if project and service:
            labels["com.docker.compose.project"] = str(project)
            labels["com.docker.compose.service"] = str(service)
        probe = {
            "name": r.get("name") or raw.get("name") or "",
            "labels": labels,
        }
        if watched_key_for_container(probe) != watched_key:
            continue
        return bool(r.get("update_available") or raw.get("update_available"))
    return None


def _find_live_container(watched_key: str) -> dict[str, Any] | None:
    try:
        containers = list_containers()
    except Exception as exc:
        logger.warning("Auto-update: Docker list failed: %s", exc)
        return None
    for c in containers:
        if watched_key_for_container(c) == watched_key:
            return c
    return None


def run_scheduled_auto_update(watched_key: str) -> dict[str, Any]:
    """
    Execute one auto-update tick for a watched_key.

    Respects Settings → General actions_enabled, Compose-only updates, and
    optional “only when update available” gating from the last poll.
    """
    key = (watched_key or "").strip()
    if not key:
        return {"ok": False, "status": "error", "message": "Missing watched_key"}

    policy = db.get_container_auto_update(key)
    if not policy or not policy.get("enabled"):
        return {"ok": False, "status": "skipped", "message": "Policy disabled"}

    if not actions_enabled():
        msg = "Container actions are disabled in Settings → General"
        db.record_container_auto_update_run(key, status="skipped", message=msg)
        logger.info("Auto-update skipped for %s — actions disabled", key)
        return {"ok": False, "status": "skipped", "message": msg}

    live = _find_live_container(key)
    if not live:
        msg = "Container not found on this host"
        db.record_container_auto_update_run(key, status="skipped", message=msg)
        logger.info("Auto-update skipped for %s — not found", key)
        return {"ok": False, "status": "skipped", "message": msg}

    project = (live.get("compose_project") or "").strip()
    service = (live.get("compose_service") or "").strip()
    labels = live.get("labels") or {}
    if not project:
        project = (labels.get("com.docker.compose.project") or "").strip()
    if not service:
        service = (labels.get("com.docker.compose.service") or "").strip()
    if not project or not service:
        msg = "Auto-update requires a Compose-managed container"
        db.record_container_auto_update_run(key, status="skipped", message=msg)
        logger.info("Auto-update skipped for %s — not Compose", key)
        return {"ok": False, "status": "skipped", "message": msg}

    if policy.get("only_when_available", True):
        available = _snapshot_update_available(key)
        if available is False:
            msg = "No image update available (last poll)"
            db.record_container_auto_update_run(key, status="skipped", message=msg)
            logger.info("Auto-update skipped for %s — no update", key)
            return {"ok": False, "status": "skipped", "message": msg}
        if available is None:
            # Fail soft: proceed with pull so a missing snapshot doesn't block forever
            logger.info(
                "Auto-update for %s — update_available unknown; proceeding with pull",
                key,
            )

    container_ref = (
        live.get("container_id_full")
        or live.get("container_id")
        or live.get("name")
        or ""
    )
    if not container_ref:
        msg = "Could not resolve container id"
        db.record_container_auto_update_run(key, status="error", message=msg)
        return {"ok": False, "status": "error", "message": msg}

    try:
        job = start_update_job(str(container_ref))
    except Exception as exc:
        msg = str(exc)
        db.record_container_auto_update_run(key, status="error", message=msg)
        logger.exception("Auto-update failed to start for %s", key)
        return {"ok": False, "status": "error", "message": msg}

    job_id = (job or {}).get("id")
    msg = f"Started Compose update job for {project}/{service}"
    db.record_container_auto_update_run(
        key, status="started", message=msg, job_id=job_id
    )
    logger.info("Auto-update started for %s (job %s)", key, job_id)
    return {
        "ok": True,
        "status": "started",
        "message": msg,
        "job": job,
    }
