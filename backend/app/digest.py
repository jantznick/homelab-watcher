"""Notable-event detection and Resend digest emails."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo

import resend
from apscheduler.triggers.cron import CronTrigger

from app import db
from app.config import AppYamlConfig
from app.runtime_settings import (
    apply_watched,
    effective_yaml_overlay,
    get_digest_profile,
    resolve_security,
)
from app.security_posture import severity_at_least
from app.security_trivy import notable_vuln_count

logger = logging.getLogger(__name__)


def _parse_raw_container(row: dict[str, Any]) -> dict[str, Any]:
    raw = row.get("raw_json")
    parsed: dict[str, Any] = {}
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = {}
    elif isinstance(raw, dict):
        parsed = raw
    merged = {**row, **parsed}
    return merged


def collect_notable(yaml_cfg: AppYamlConfig | None = None) -> dict[str, Any]:
    """Build a snapshot of things that need attention from latest polls."""
    cfg = yaml_cfg or effective_yaml_overlay()
    warn = cfg.thresholds.disk_warn_percent
    security, _ = resolve_security()

    containers_raw = db.latest_containers()
    containers = [_parse_raw_container(c) for c in containers_raw]
    # Re-apply star flags from live DB (toggle since last poll).
    apply_watched(containers)
    host = db.latest_host()
    checks = db.latest_checks()

    updates = [c for c in containers if c.get("update_available")]
    exited: list[dict[str, Any]] = []
    if cfg.thresholds.alert_on_exited:
        exited = [
            c
            for c in containers
            if (c.get("state") or c.get("status") or "").lower() not in ("running",)
        ]

    def _is_starred(c: dict[str, Any]) -> bool:
        return bool(c.get("watched", c.get("vital")))

    watched_down = [
        c
        for c in containers
        if _is_starred(c)
        and (c.get("state") or c.get("status") or "").lower() not in ("running",)
    ]

    downs = [c for c in checks if not c.get("ok")]

    disk_pressure: list[dict[str, Any]] = []
    disks: list[dict[str, Any]] = []
    if host:
        raw = host.get("raw_json")
        parsed: dict[str, Any] = {}
        if isinstance(raw, str):
            try:
                loaded = json.loads(raw)
                if isinstance(loaded, dict):
                    parsed = loaded
            except Exception:
                parsed = {}
        if isinstance(parsed.get("disks"), list):
            disks = parsed["disks"]
        elif (
            "disks" not in parsed
            and not parsed.get("disk_selection_needed")
            and host.get("disk_percent") is not None
        ):
            # Legacy snapshot without disks array — approximate from root %.
            disks = [{"path": "/", "percent": host["disk_percent"], "mounted": True}]
        for d in disks:
            pct = d.get("percent")
            if pct is not None and pct >= warn:
                disk_pressure.append(d)
            elif d.get("error") or d.get("mounted") is False:
                disk_pressure.append(d)

    security_issues: list[dict[str, Any]] = []
    if security.enabled:
        for c in containers:
            sec = c.get("security") or {}
            if not sec.get("enabled"):
                continue
            name = c.get("name")
            sev = sec.get("severity") or {}
            # Prefer per-scanner counts so digests don't double-count SCM in "CVEs"
            if "image_vuln_notable_count" in sec:
                vuln_n = int(sec.get("image_vuln_notable_count") or 0)
            else:
                vuln_n = notable_vuln_count(sev, security.notable_severity)
            posture = sec.get("posture") or []
            posture_hits = [
                f
                for f in posture
                if severity_at_least(
                    str(f.get("severity") or ""),
                    security.notable_posture_severity,
                )
            ]
            scm = sec.get("scm") or {}
            if not security.opensca.enabled:
                scm = {}
                scm_n = 0
            elif "scm_vuln_notable_count" in sec:
                scm_n = int(sec.get("scm_vuln_notable_count") or 0)
            else:
                scm_n = int(scm.get("notable_count") or 0) if isinstance(scm, dict) else 0
            if not security.trivy.enabled:
                vuln_n = 0
            starred = _is_starred(c)
            if vuln_n or posture_hits or scm_n or (starred and sec.get("notable")):
                if vuln_n or posture_hits or scm_n:
                    security_issues.append(
                        {
                            "name": name,
                            "watched": starred,
                            "vital": starred,  # one-release alias
                            "vuln_notable": vuln_n,
                            "scm_notable": scm_n,
                            "severity": sev,
                            "posture": posture_hits[:5],
                            "max_severity": sec.get("max_severity"),
                            "scm_repo": (scm.get("repo_url") if isinstance(scm, dict) else None),
                        }
                    )

    notable = bool(
        updates
        or exited
        or downs
        or disk_pressure
        or watched_down
        or security_issues
    )
    return {
        "notable": notable,
        "updates": updates,
        "exited": exited,
        "watched_down": watched_down,
        "vital_down": watched_down,  # one-release alias
        "downs": downs,
        "disk_pressure": disk_pressure,
        "security_issues": security_issues,
        "host": host,
        "containers": containers,
        "checks": checks,
        "disk_warn_percent": warn,
    }


def render_digest_html(payload: dict[str, Any], *, all_clear: bool) -> str:
    starred_down = payload.get("watched_down") or payload.get("vital_down") or []
    if all_clear and not payload["notable"]:
        body = (
            "<p>Everything looks fine.</p>"
            "<ul>"
            f"<li>{len(payload.get('containers') or [])} containers inventoried</li>"
            f"<li>{len(payload.get('checks') or [])} checks OK</li>"
            "<li>No disk pressure on selected mounts</li>"
            "<li>No starred containers down</li>"
            "</ul>"
            "<p style='color:#64748b;font-size:12px'>"
            "Tip: if a HTTPS check is down while its container is up, check "
            "the reverse proxy, certificates, or SSO in front of the app."
            "</p>"
        )
        title = "Homelab Watcher — all clear"
    else:
        sections: list[str] = []
        if starred_down:
            items = "".join(
                f"<li><strong>{_esc(c.get('name'))}</strong>: "
                f"{_esc(c.get('state'))}</li>"
                for c in starred_down
            )
            sections.append(f"<h3>Starred containers not running</h3><ul>{items}</ul>")
        if payload["updates"]:
            items = "".join(
                f"<li>{_esc(c.get('name'))} "
                f"<code>{_esc(c.get('image'))}</code></li>"
                for c in payload["updates"]
            )
            sections.append(f"<h3>Image updates available</h3><ul>{items}</ul>")
        if payload["downs"]:
            items = "".join(
                f"<li><strong>{_esc(c.get('name'))}</strong> "
                f"({_esc(c.get('check_type'))}): {_esc(c.get('message'))}</li>"
                for c in payload["downs"]
            )
            sections.append(f"<h3>Checks down</h3><ul>{items}</ul>")
        if payload["disk_pressure"]:
            items = "".join(
                f"<li><code>{_esc(d.get('path'))}</code>: "
                f"{d.get('percent', '?')}% "
                f"{_esc(d.get('error') or '')}</li>"
                for d in payload["disk_pressure"]
            )
            sections.append(
                f"<h3>Disk pressure (≥{payload['disk_warn_percent']}%)</h3>"
                f"<ul>{items}</ul>"
            )
        if payload.get("security_issues"):
            def _sec_li(s: dict[str, Any]) -> str:
                scm_bit = ""
                if s.get("scm_notable"):
                    scm_bit = f" · {s.get('scm_notable', 0)} SCM"
                max_bit = ""
                if s.get("max_severity"):
                    max_bit = " · " + _esc(s.get("max_severity"))
                star = " ★" if s.get("watched", s.get("vital")) else ""
                return (
                    f"<li><strong>{_esc(s.get('name'))}</strong>{star}: "
                    f"{s.get('vuln_notable', 0)} notable CVEs{scm_bit}{max_bit}</li>"
                )

            items = "".join(_sec_li(s) for s in payload["security_issues"])
            sections.append(f"<h3>Security (notable)</h3><ul>{items}</ul>")
        if payload["exited"]:
            items = "".join(
                f"<li>{_esc(c.get('name'))}: {_esc(c.get('state'))}</li>"
                for c in payload["exited"]
            )
            sections.append(f"<h3>Containers not running</h3><ul>{items}</ul>")
        if not sections:
            sections.append("<p>Notable events were flagged but details are empty.</p>")
        body = "".join(sections)
        title = "Homelab Watcher — attention needed"

    return f"""<!DOCTYPE html>
<html><body style="font-family:system-ui,sans-serif;color:#0f172a;line-height:1.5">
  <h2 style="color:#0f766e">{title}</h2>
  {body}
  <p style="color:#94a3b8;font-size:12px;margin-top:2rem">
    Sent by Homelab Watcher · open the dashboard for live status
  </p>
</body></html>"""


def _esc(value: Any) -> str:
    s = "" if value is None else str(value)
    return (
        s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def send_digest(
    *,
    force: bool = False,
    force_all_clear: bool = False,
    profile_id: str | None = None,
) -> dict[str, Any]:
    resolved = get_digest_profile(profile_id)
    if resolved is None:
        return {"sent": False, "reason": "digest profile not found"}
    digest_cfg, profile, _ = resolved
    pid = str(profile.get("id") or "")
    pname = profile.get("name") or "Digest"

    if not profile.get("enabled", True) and not force:
        return {
            "sent": False,
            "reason": f"digest “{pname}” disabled in Settings",
            "profile_id": pid,
            "profile_name": pname,
        }

    payload = collect_notable()

    if payload["notable"]:
        kind = "notable"
        all_clear = False
        subject = "Homelab Watcher: attention needed"
    elif force or force_all_clear:
        kind = "all_clear" if not force else "test"
        all_clear = True
        subject = (
            "Homelab Watcher: test digest (all clear)"
            if force
            else "Homelab Watcher: all clear"
        )
    else:
        return {
            "sent": False,
            "reason": "nothing notable to report",
            "profile_id": pid,
            "profile_name": pname,
        }

    if force_all_clear and not profile.get("digest_send_all_clear") and not force:
        return {
            "sent": False,
            "reason": "all-clear disabled",
            "profile_id": pid,
            "profile_name": pname,
        }

    api_key = (digest_cfg.get("resend_api_key") or "").strip()
    to_addr = (profile.get("digest_to") or "").strip()
    from_addr = profile.get("digest_from") or "Homelab Watcher <onboarding@resend.dev>"

    if not api_key or not to_addr:
        return {
            "sent": False,
            "reason": "Resend API key or digest To address not configured (Settings → Email)",
            "would_send": True,
            "kind": kind,
            "preview_subject": subject,
            "profile_id": pid,
            "profile_name": pname,
        }

    html = render_digest_html(payload, all_clear=all_clear)
    resend.api_key = api_key
    try:
        result = resend.Emails.send(
            {
                "from": from_addr,
                "to": [to_addr],
                "subject": subject,
                "html": html,
            }
        )
        db.set_digest_state(kind, f"{pname}: {subject}")
        return {
            "sent": True,
            "kind": kind,
            "subject": subject,
            "profile_id": pid,
            "profile_name": pname,
            "result": result if isinstance(result, dict) else {"id": str(result)},
            "notable_counts": {
                "updates": len(payload["updates"]),
                "downs": len(payload["downs"]),
                "disk_pressure": len(payload["disk_pressure"]),
                "watched_down": len(
                    payload.get("watched_down") or payload.get("vital_down") or []
                ),
                "vital_down": len(
                    payload.get("watched_down") or payload.get("vital_down") or []
                ),
                "security_issues": len(payload.get("security_issues") or []),
            },
        }
    except Exception as exc:
        logger.exception("Resend send failed")
        return {
            "sent": False,
            "reason": str(exc),
            "kind": kind,
            "profile_id": pid,
            "profile_name": pname,
        }


def run_scheduled_digest(profile_id: str | None = None) -> None:
    resolved = get_digest_profile(profile_id)
    if resolved is None:
        logger.info("Scheduled digest skipped — profile not found (%s)", profile_id)
        return
    _, profile, _ = resolved
    pname = profile.get("name") or profile_id or "Digest"
    if not profile.get("enabled", True):
        logger.info("Scheduled digest skipped — “%s” disabled", pname)
        return
    payload = collect_notable()
    if payload["notable"]:
        result = send_digest(force=False, profile_id=profile.get("id"))
        logger.info("Scheduled digest “%s” (notable): %s", pname, result)
    elif profile.get("digest_send_all_clear"):
        result = send_digest(
            force=False, force_all_clear=True, profile_id=profile.get("id")
        )
        logger.info("Scheduled digest “%s” (all-clear): %s", pname, result)
    else:
        logger.info("Scheduled digest “%s” skipped — nothing notable", pname)


def next_cron_fire(cron: str, tz_name: str) -> str | None:
    try:
        parts = cron.split()
        if len(parts) != 5:
            return None
        minute, hour, day, month, day_of_week = parts
        trigger = CronTrigger(
            minute=minute,
            hour=hour,
            day=day,
            month=month,
            day_of_week=day_of_week,
            timezone=ZoneInfo(tz_name),
        )
        nxt = trigger.get_next_fire_time(None, datetime.now(timezone.utc))
        return nxt.isoformat() if nxt else None
    except Exception as exc:
        logger.warning("Could not compute next digest time: %s", exc)
        return None
