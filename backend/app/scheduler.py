"""Background poll loop and digest scheduler."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger

from app import db
from app.access_urls import enrich_container_access
from app.checks import run_all_checks
from app.config import get_settings
from app.digest import run_scheduled_digest
from app.docker_client import get_docker_error, get_docker_endpoint, get_docker_status, list_containers
from app.host_metrics import collect_host_metrics
from app.networking import build_dns_inventory, discover_and_enrich
from app.pihole import PiHoleResult, fetch_pihole_dns
from app.runtime_settings import (
    apply_watched,
    effective_poll_interval,
    effective_yaml_overlay,
    get_speed_test_last,
    resolve_digest_settings,
    resolve_networking,
    resolve_pihole,
    resolve_speed_test,
    save_speed_test_last,
)
from app.security import enrich_security
from app.speed_test import run_speed_test, should_run_scheduled
from app.updates import enrich_with_updates

logger = logging.getLogger(__name__)

scheduler = BackgroundScheduler()
_last_poll_at: str | None = None
_last_poll_error: str | None = None
_last_pihole: dict | None = None
_last_networking: dict | None = None
_last_dns_records: list | None = None
_last_caddy_records: list | None = None


def get_poll_status() -> dict:
    docker_error = get_docker_error()
    return {
        "last_poll_at": _last_poll_at,
        "last_poll_error": _last_poll_error,
        "poll_interval_seconds": effective_poll_interval(),
        "pihole": _last_pihole,
        "networking": _last_networking,
        "docker_available": docker_error is None and get_docker_endpoint() is not None,
        "docker_error": docker_error,
        "docker_endpoint": get_docker_endpoint(),
        "docker": get_docker_status(),
    }


def get_last_pihole() -> dict | None:
    return _last_pihole


def get_last_networking() -> dict | None:
    return _last_networking


def _networking_public(status: dict | None) -> dict:
    raw = dict(status or {})
    raw.pop("route_rows", None)
    return raw or {
        "proxy_type": "none",
        "configured": False,
        "ok": None,
        "route_count": 0,
        "mapped_count": 0,
        "message": None,
        "errors": [],
        "sources_tried": [],
    }


def get_last_dns() -> dict:
    """Snapshot for GET /api/dns — Local DNS rows + Pi-hole / networking status."""
    return {
        "taken_at": _last_poll_at,
        "pihole": _last_pihole
        or {
            "configured": False,
            "ok": None,
            "version": None,
            "message": "Pi-hole not configured",
            "record_count": 0,
        },
        "networking": _networking_public(_last_networking),
        "records": list(_last_dns_records or []),
    }


def get_last_caddy() -> dict:
    """Snapshot for GET /api/caddy — discovered Caddy site routes + container join."""
    return {
        "taken_at": _last_poll_at,
        "networking": _networking_public(_last_networking),
        "records": list(_last_caddy_records or []),
    }


def store_networking_result(status: dict) -> None:
    global _last_networking, _last_caddy_records
    rows = status.pop("route_rows", None)
    _last_caddy_records = list(rows or [])
    _last_networking = status


def _pihole_status_dict(result: PiHoleResult) -> dict:
    return {
        "configured": result.configured,
        "ok": result.ok if result.configured else None,
        "version": result.version,
        "message": result.message,
        "record_count": len(result.records),
    }


def apply_pihole_result(result: PiHoleResult) -> dict:
    """
    Push a live Pi-hole fetch into the DNS page snapshot.

    Settings → Test / Save call this so /api/dns matches the Test result
    immediately (not the previous poll's stale customdns error).
    """
    global _last_pihole, _last_dns_records, _last_poll_at

    containers: list = []
    try:
        containers = list_containers()
    except Exception as exc:
        logger.debug("Pi-hole snapshot: containers unavailable: %s", exc)

    try:
        net_cfg, _ = resolve_networking()
        status = discover_and_enrich(
            containers,
            proxy_type=net_cfg.proxy_type,
            use_admin_api=net_cfg.caddy_use_admin_api,
            admin_url=net_cfg.caddy_admin_url,
            use_caddyfile=net_cfg.caddy_use_caddyfile,
            caddyfile_path=net_cfg.caddy_caddyfile_path,
            use_labels=net_cfg.caddy_use_labels,
            verify_tls=net_cfg.verify_tls,
            timeout=net_cfg.timeout_seconds,
            pihole=result,
        )
        store_networking_result(status)
    except Exception as exc:
        logger.warning("Pi-hole snapshot: networking join skipped: %s", exc)
        try:
            from app.container_enrich import clear_pihole_fields

            clear_pihole_fields(containers)
        except Exception:
            pass

    _last_pihole = _pihole_status_dict(result)
    _last_dns_records = build_dns_inventory(containers, result)
    _last_poll_at = datetime.now(timezone.utc).isoformat()
    return get_last_dns()


def refresh_pihole_dns_snapshot() -> PiHoleResult:
    """Re-fetch Pi-hole Local DNS with saved settings and update /api/dns."""
    cfg, password, token, _src = resolve_pihole()
    result = fetch_pihole_dns(
        cfg,
        password_override=password,
        token_override=token,
    )
    apply_pihole_result(result)
    return result


def poll_once() -> None:
    global _last_poll_at, _last_poll_error, _last_pihole, _last_networking
    global _last_dns_records, _last_caddy_records
    try:
        yaml_cfg = effective_yaml_overlay()
        containers = list_containers()
        containers = enrich_with_updates(containers, yaml_cfg)
        enrich_container_access(containers, yaml_cfg.container_urls)
        apply_watched(containers)

        try:
            enrich_security(containers, yaml_cfg.security)
        except Exception as exc:
            logger.warning("Security enrichment skipped: %s", exc)

        pihole_result = None
        try:
            ph_cfg, password, token, _src = resolve_pihole()
            pihole_result = fetch_pihole_dns(
                ph_cfg,
                password_override=password,
                token_override=token,
            )
            _last_pihole = {
                "configured": pihole_result.configured,
                "ok": pihole_result.ok if pihole_result.configured else None,
                "version": pihole_result.version,
                "message": pihole_result.message,
                "record_count": len(pihole_result.records),
            }
        except Exception as exc:
            logger.warning("Pi-hole fetch skipped: %s", exc)
            _last_pihole = {
                "configured": bool((resolve_pihole()[0].url or "").strip()),
                "ok": False,
                "version": None,
                "message": str(exc),
                "record_count": 0,
            }
            for c in containers:
                c.setdefault("pihole_matched", False)
                c.setdefault("pihole_hostnames", [])

        try:
            net_cfg, _ = resolve_networking()
            status = discover_and_enrich(
                containers,
                proxy_type=net_cfg.proxy_type,
                use_admin_api=net_cfg.caddy_use_admin_api,
                admin_url=net_cfg.caddy_admin_url,
                use_caddyfile=net_cfg.caddy_use_caddyfile,
                caddyfile_path=net_cfg.caddy_caddyfile_path,
                use_labels=net_cfg.caddy_use_labels,
                verify_tls=net_cfg.verify_tls,
                timeout=net_cfg.timeout_seconds,
                pihole=pihole_result,
            )
            store_networking_result(status)
            # Refresh pihole status record_count / matched after join
            if pihole_result is not None:
                _last_pihole = {
                    "configured": pihole_result.configured,
                    "ok": pihole_result.ok if pihole_result.configured else None,
                    "version": pihole_result.version,
                    "message": pihole_result.message,
                    "record_count": len(pihole_result.records),
                }
            _last_dns_records = build_dns_inventory(containers, pihole_result)
        except Exception as exc:
            logger.warning("Networking enrichment skipped: %s", exc)
            _last_networking = {
                "proxy_type": "none",
                "configured": False,
                "ok": False,
                "route_count": 0,
                "mapped_count": 0,
                "message": str(exc),
                "errors": [str(exc)],
                "sources_tried": [],
            }
            _last_caddy_records = []
            # No fuzzy hostname fallback — clear badges until a real Caddy join runs
            if pihole_result is not None:
                from app.container_enrich import clear_pihole_fields, pihole_status_dict

                clear_pihole_fields(containers)
                _last_pihole = pihole_status_dict(pihole_result)
            _last_dns_records = build_dns_inventory(containers, pihole_result)

        db.save_container_snapshots(containers)

        host = collect_host_metrics(yaml_cfg, containers=containers)
        db.save_host_snapshot(host)

        checks = run_all_checks(yaml_cfg)
        db.save_check_results(checks)

        db.prune_old_rows(14)
        _last_poll_at = datetime.now(timezone.utc).isoformat()
        _last_poll_error = None
        logger.info(
            "Poll complete: %d containers, %d checks",
            len(containers),
            len(checks),
        )
    except Exception as exc:
        _last_poll_error = str(exc)
        logger.exception("Poll failed")


def speed_test_once(*, force: bool = False) -> dict:
    """
    Run Internet speed check outside poll_once so transfers never block the poll loop.
    force=True skips the interval gate (manual Run now).
    """
    cfg, _ = resolve_speed_test()
    last = get_speed_test_last()
    if not force:
        if not should_run_scheduled(
            enabled=bool(cfg.enabled),
            interval_hours=float(cfg.interval_hours),
            last=last,
        ):
            return last or {
                "ok": False,
                "skipped": True,
                "error": "Not due yet.",
            }

    try:
        result = run_speed_test()
        if not result.get("busy"):
            save_speed_test_last(result)
        return result
    except Exception as exc:
        logger.warning("Speed test job failed: %s", exc)
        fail = {
            "ok": False,
            "provider": "cloudflare",
            "taken_at": datetime.now(timezone.utc).isoformat(),
            "download_mbps": None,
            "upload_mbps": None,
            "ping_ms": None,
            "error": "Speed check failed.",
        }
        save_speed_test_last(fail)
        return fail


def _speed_test_tick() -> None:
    """Periodic gate — only runs the heavy transfer when due."""
    try:
        speed_test_once(force=False)
    except Exception as exc:
        logger.warning("Speed test tick skipped: %s", exc)


def reschedule_poll() -> None:
    """Refresh poll interval from Settings."""
    if not scheduler.running:
        return
    seconds = effective_poll_interval()
    scheduler.add_job(
        poll_once,
        IntervalTrigger(seconds=seconds),
        id="poll",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )


def reschedule_speed_test() -> None:
    """Refresh speed-test tick from Settings (lightweight gate every 15m)."""
    if not scheduler.running:
        return
    cfg, _ = resolve_speed_test()
    if not cfg.enabled or float(cfg.interval_hours or 0) <= 0:
        try:
            scheduler.remove_job("speed_test")
        except Exception:
            pass
        return
    # Tick often; should_run_scheduled decides whether to transfer.
    scheduler.add_job(
        _speed_test_tick,
        IntervalTrigger(minutes=15),
        id="speed_test",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )


def reschedule_digest() -> None:
    if not scheduler.running:
        return
    # Drop legacy single job and all per-profile digest jobs.
    for job in list(scheduler.get_jobs()):
        jid = job.id or ""
        if jid == "digest" or jid.startswith("digest:"):
            try:
                scheduler.remove_job(jid)
            except Exception:
                pass

    digest, _ = resolve_digest_settings()
    profiles = digest.get("profiles") or []
    scheduled_n = 0
    for profile in profiles:
        if not isinstance(profile, dict) or not profile.get("enabled"):
            continue
        cron = (profile.get("digest_cron") or "").strip()
        parts = cron.split()
        pid = str(profile.get("id") or "").strip()
        if not pid or len(parts) != 5:
            if cron:
                logger.warning(
                    "Digest “%s” enabled but schedule incomplete — not scheduled",
                    profile.get("name") or pid or "?",
                )
            continue
        tz = profile.get("tz") or get_settings().tz or "UTC"
        minute, hour, day, month, day_of_week = parts
        scheduler.add_job(
            run_scheduled_digest,
            CronTrigger(
                minute=minute,
                hour=hour,
                day=day,
                month=month,
                day_of_week=day_of_week,
                timezone=tz,
            ),
            id=f"digest:{pid}",
            kwargs={"profile_id": pid},
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        scheduled_n += 1
    if scheduled_n:
        logger.info("Scheduled %d digest profile(s)", scheduled_n)


def start_scheduler() -> None:
    if scheduler.running:
        return

    seconds = effective_poll_interval()
    scheduler.add_job(
        poll_once,
        IntervalTrigger(seconds=seconds),
        id="poll",
        replace_existing=True,
        max_instances=1,
        coalesce=True,
    )

    scheduler.start()
    # Only schedule digest when enabled + complete (no silent Sunday 9am default)
    reschedule_digest()
    reschedule_speed_test()
    scheduler.add_job(poll_once, id="poll_now", replace_existing=True)


def shutdown_scheduler() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
