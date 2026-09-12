"""
Resolve effective runtime config: SQLite Settings (primary) → YAML → env.

Secrets may live in the DB volume — treat watcher-data as sensitive.
"""

from __future__ import annotations

from typing import Any, Literal

from app import db
from app.config import (
    AppYamlConfig,
    ListeningPortsConfig,
    NetworkingConfig,
    PiHoleConfig,
    SecurityConfig,
    Settings,
    SpeedTestConfig,
    TargetConfig,
    Thresholds,
    get_settings,
    reload_yaml_config,
)

SettingSource = Literal["db", "yaml", "env", "default", "none"]


def watched_key_for_container(container: dict[str, Any]) -> str:
    """
    Stable key across container recreate for starred containers.

    Prefer compose project+service labels; else container name.
    Renaming the container or changing compose project/service → new key.
    """
    labels = container.get("labels") or {}
    project = (labels.get("com.docker.compose.project") or "").strip()
    service = (labels.get("com.docker.compose.service") or "").strip()
    if project and service:
        return f"compose:{project}/{service}"
    name = (container.get("name") or "").strip().lstrip("/")
    return f"name:{name}"


# One-release alias — prefer watched_key_for_container.
vital_key_for_container = watched_key_for_container


def list_watched_keys() -> set[str]:
    return {row["watched_key"] for row in db.list_watched_containers()}


def list_vital_keys() -> set[str]:
    """Deprecated alias for list_watched_keys."""
    return list_watched_keys()


def apply_watched(containers: list[dict[str, Any]]) -> None:
    """Apply starred (important) flags onto container dicts."""
    keys = list_watched_keys()
    for c in containers:
        wk = watched_key_for_container(c)
        watched = wk in keys
        c["watched_key"] = wk
        c["watched"] = watched
        # One-release dual-read aliases for older clients / snapshots.
        c["vital_key"] = wk
        c["vital"] = watched


def apply_container_notes(containers: list[dict[str, Any]]) -> None:
    """
    Attach user description/notes onto container dicts.

    Fail soft: DB errors leave empty fields so inventory still works.
    Keyed by the same watched_key as stars (compose project/service or name).
    """
    try:
        notes_by_key = db.container_notes_map()
    except Exception:
        notes_by_key = {}
    for c in containers:
        wk = c.get("watched_key") or c.get("vital_key") or watched_key_for_container(c)
        c["watched_key"] = wk
        row = notes_by_key.get(wk) or {}
        c["description"] = row.get("description") or ""
        c["notes"] = row.get("notes") or ""


def apply_vitals(containers: list[dict[str, Any]]) -> None:
    """Deprecated alias for apply_watched."""
    apply_watched(containers)


def resolve_targets() -> tuple[list[TargetConfig], SettingSource]:
    """Custom HTTP/ping/DNS check targets (Plex is separate)."""
    # Prefer "checks"; still read legacy "watched" setting key from older installs.
    for key in ("checks", "watched"):
        stored = db.get_setting(key)
        if isinstance(stored, dict) and "targets" in stored:
            raw = stored.get("targets") or []
            if isinstance(raw, list):
                return [TargetConfig.model_validate(t) for t in raw], "db"
        if isinstance(stored, list):
            return [TargetConfig.model_validate(t) for t in stored], "db"

    yaml_cfg = reload_yaml_config()
    if yaml_cfg.targets:
        return list(yaml_cfg.targets), "yaml"
    return [], "default"


def save_check_targets(targets: list[dict[str, Any]]) -> None:
    """Persist custom check targets under checks (+ legacy watched key)."""
    payload = {"configured": True, "targets": targets}
    db.set_setting("checks", payload)
    db.set_setting("watched", payload)


def resolve_plex() -> tuple[dict[str, Any], SettingSource]:
    """First-class Plex HTTP check settings (separate from custom probes)."""
    stored = db.get_setting("plex")
    defaults = {
        "enabled": False,
        "url": "",
        "verify_tls": True,
    }
    if isinstance(stored, dict) and (
        stored.get("url") is not None or stored.get("configured")
    ):
        return {**defaults, **{k: v for k, v in stored.items() if k != "configured"}}, "db"
    return defaults, "default"


def plex_as_target() -> TargetConfig | None:
    plex, _ = resolve_plex()
    url = (plex.get("url") or "").strip()
    if not url or plex.get("enabled") is False:
        return None
    return TargetConfig(
        name="Plex",
        type="http",
        url=url,
        verify_tls=bool(plex.get("verify_tls", True)),
    )


def resolve_check_targets() -> list[TargetConfig]:
    """Custom checks + optional first-class Plex probe."""
    targets, _ = resolve_targets()
    custom = [t for t in targets if t.name.strip().lower() != "plex"]
    plex = plex_as_target()
    if plex:
        return [plex, *custom]
    return custom


def resolve_thresholds() -> tuple[Thresholds, SettingSource]:
    stored = db.get_setting("disks")
    yaml_cfg = reload_yaml_config()
    if isinstance(stored, dict) and (
        stored.get("configured")
        or stored.get("disks") is not None
        or stored.get("disk_warn_percent") is not None
    ):
        base = yaml_cfg.thresholds.model_dump()
        # Start from empty selection unless DB/YAML explicitly set disks.
        # Settings UI default is none selected until the user checks mounts.
        base["disks"] = list(yaml_cfg.thresholds.disks or [])
        base.update(
            {k: v for k, v in stored.items() if v is not None and k != "configured"}
        )
        if "disks" in stored and stored["disks"] is not None:
            base["disks"] = [
                str(p).strip() for p in (stored["disks"] or []) if str(p).strip()
            ]
        return Thresholds.model_validate(base), "db"
    # YAML may list paths; otherwise empty = selection needed in UI.
    return (
        yaml_cfg.thresholds,
        "yaml" if yaml_cfg.thresholds.disks or yaml_cfg.thresholds.disk_warn_percent != 85.0 else "default",
    )


def resolve_listening_ports() -> tuple[ListeningPortsConfig, SettingSource]:
    """Return listening-ports Settings overlay."""
    stored = db.get_setting("listening_ports")
    yaml_cfg = reload_yaml_config()
    if isinstance(stored, dict) and (
        stored.get("configured") or stored.get("enabled") is not None
    ):
        base = yaml_cfg.listening_ports.model_dump()
        base.update(
            {k: v for k, v in stored.items() if v is not None and k != "configured"}
        )
        return ListeningPortsConfig.model_validate(base), "db"
    cfg = yaml_cfg.listening_ports
    if not cfg.enabled:
        return cfg, "yaml"
    return cfg, "default"


def resolve_speed_test() -> tuple[SpeedTestConfig, SettingSource]:
    """Return Internet speed-check Settings overlay."""
    stored = db.get_setting("speed_test")
    yaml_cfg = reload_yaml_config()
    if isinstance(stored, dict) and (
        stored.get("configured")
        or stored.get("enabled") is not None
        or stored.get("interval_hours") is not None
    ):
        base = yaml_cfg.speed_test.model_dump()
        base.update(
            {k: v for k, v in stored.items() if v is not None and k != "configured"}
        )
        try:
            base["interval_hours"] = max(0.0, float(base.get("interval_hours") or 12.0))
        except (TypeError, ValueError):
            base["interval_hours"] = 12.0
        return SpeedTestConfig.model_validate(base), "db"
    cfg = yaml_cfg.speed_test
    if cfg.enabled or cfg.interval_hours != 12.0:
        return cfg, "yaml"
    return cfg, "default"


def get_speed_test_last() -> dict[str, Any] | None:
    stored = db.get_setting("speed_test_last")
    return stored if isinstance(stored, dict) else None


def save_speed_test_last(result: dict[str, Any]) -> None:
    slim = {
        "ok": bool(result.get("ok")),
        "provider": result.get("provider") or "cloudflare",
        "taken_at": result.get("taken_at"),
        "download_mbps": result.get("download_mbps"),
        "upload_mbps": result.get("upload_mbps"),
        "ping_ms": result.get("ping_ms"),
        "error": result.get("error"),
    }
    db.set_setting("speed_test_last", slim)


def resolve_security() -> tuple[SecurityConfig, SettingSource]:
    stored = db.get_setting("security")
    yaml_cfg = reload_yaml_config()
    if isinstance(stored, dict) and stored.get("configured"):
        base = yaml_cfg.security.model_dump()
        for k, v in stored.items():
            if k == "configured":
                continue
            if k == "trivy" and isinstance(v, dict):
                base["trivy"] = {**base.get("trivy", {}), **v}
            elif k == "posture" and isinstance(v, dict):
                base["posture"] = {**base.get("posture", {}), **v}
            elif k == "opensca" and isinstance(v, dict):
                prev = base.get("opensca") or {}
                merged = {**prev, **v}
                # Keep prior secrets when incoming omits or blanks them
                if not str(v.get("git_token") or "").strip():
                    merged["git_token"] = prev.get("git_token") or ""
                if not str(v.get("opensca_token") or "").strip():
                    merged["opensca_token"] = prev.get("opensca_token") or ""
                base["opensca"] = merged
            else:
                base[k] = v

        # Migrate legacy master → independent scanner enables (in-memory).
        # Old UI: security.enabled gated all scans; trivy was always saved
        # enabled=true; opensca.enabled was optional.
        master = bool(base.get("enabled"))
        stored_trivy = stored.get("trivy") if isinstance(stored.get("trivy"), dict) else {}
        stored_osca = stored.get("opensca") if isinstance(stored.get("opensca"), dict) else {}
        trivy_cfg = dict(base.get("trivy") or {})
        osca_cfg = dict(base.get("opensca") or {})
        if not master:
            # Master off → scanners were effectively off (ignore stale nested true).
            trivy_cfg["enabled"] = False
            osca_cfg["enabled"] = False
        else:
            if "enabled" not in stored_trivy:
                trivy_cfg["enabled"] = True  # legacy: security on meant image scans
            if "enabled" not in stored_osca:
                osca_cfg["enabled"] = False  # avoid surprise SCM clones
            # else keep explicit nested enables (independent toggles)
        base["trivy"] = trivy_cfg
        base["opensca"] = osca_cfg
        posture_on = bool((base.get("posture") or {}).get("enabled", True))
        base["enabled"] = bool(
            trivy_cfg.get("enabled")
            or osca_cfg.get("enabled")
            or (master and posture_on)
        )

        return SecurityConfig.model_validate(base), "db"
    if yaml_cfg.security.enabled:
        return yaml_cfg.security, "yaml"
    return yaml_cfg.security, "default"


def security_public_view(security: SecurityConfig, source: SettingSource) -> dict[str, Any]:
    """Settings payload without secret token values."""
    from app.security_opensca import opensca_available
    from app.security_trivy import trivy_available

    data = security.model_dump()
    osca = dict(data.get("opensca") or {})
    stored = db.get_setting("security") or {}
    stored_osca = (stored.get("opensca") or {}) if isinstance(stored, dict) else {}
    git_tok = str(osca.pop("git_token", "") or "")
    osca_tok = str(osca.pop("opensca_token", "") or "")
    osca["has_git_token"] = bool(git_tok.strip()) or bool(
        (get_settings().git_token or get_settings().scm_token or "").strip()
    )
    osca["has_opensca_token"] = bool(osca_tok.strip())
    osca["git_token_in_db"] = bool(str(stored_osca.get("git_token") or "").strip())
    osca["opensca_token_in_db"] = bool(str(stored_osca.get("opensca_token") or "").strip())
    data["opensca"] = osca
    data["source"] = source
    data["trivy_available"] = trivy_available()
    data["opensca_available"] = opensca_available()
    return data


def resolve_pihole(
    settings: Settings | None = None,
) -> tuple[PiHoleConfig, str, str, SettingSource]:
    settings = settings or get_settings()
    stored = db.get_setting("pihole") or {}
    yaml_cfg = reload_yaml_config().pihole

    db_url = (stored.get("url") or "").strip() if isinstance(stored, dict) else ""
    if db_url:
        version = stored.get("version") or "auto"
        if version not in ("auto", "5", "6"):
            version = "auto"
        cfg = PiHoleConfig(
            url=db_url,
            version=version,
            verify_tls=bool(stored.get("verify_tls", True)),
            timeout_seconds=float(stored.get("timeout_seconds") or 5.0),
        )
        password = (stored.get("password") or "").strip() or settings.pihole_password
        token = (stored.get("api_token") or "").strip() or settings.pihole_api_token
        return cfg, password, token, "db"

    if (yaml_cfg.url or "").strip():
        return yaml_cfg, settings.pihole_password, settings.pihole_api_token, "yaml"

    return PiHoleConfig(), "", "", "none"


def pihole_public_view() -> dict[str, Any]:
    cfg, password, token, source = resolve_pihole()
    stored = db.get_setting("pihole") or {}
    # Last poll / fetch status (record count + error) for Settings UI
    last: dict[str, Any] = {}
    try:
        from app.scheduler import get_last_pihole

        last = get_last_pihole() or {}
    except Exception:
        last = {}
    return {
        "source": source,
        "configured": bool((cfg.url or "").strip()),
        "url": cfg.url or "",
        "version": cfg.version,
        "verify_tls": cfg.verify_tls,
        "has_password": bool((password or "").strip()),
        "has_api_token": bool((token or "").strip()),
        "password_in_db": bool((stored.get("password") or "").strip())
        if isinstance(stored, dict)
        else False,
        "api_token_in_db": bool((stored.get("api_token") or "").strip())
        if isinstance(stored, dict)
        else False,
        "ok": last.get("ok"),
        "message": last.get("message"),
        "record_count": last.get("record_count"),
        "detected_version": last.get("version"),
    }


def resolve_networking(
    settings: Settings | None = None,
) -> tuple[NetworkingConfig, SettingSource]:
    _ = settings  # reserved for future env overrides
    stored = db.get_setting("networking") or {}
    yaml_cfg = reload_yaml_config().networking

    if isinstance(stored, dict) and stored:
        proxy = str(stored.get("proxy_type") or "none").lower().strip()
        if proxy not in ("none", "caddy", "traefik"):
            proxy = "none"
        cfg = NetworkingConfig(
            proxy_type=proxy,  # type: ignore[arg-type]
            caddy_use_admin_api=bool(
                stored.get(
                    "caddy_use_admin_api", yaml_cfg.caddy_use_admin_api
                )
            ),
            caddy_admin_url=str(
                stored.get("caddy_admin_url")
                or yaml_cfg.caddy_admin_url
                or "http://host.docker.internal:2019"
            ).strip(),
            caddy_use_caddyfile=bool(
                stored.get(
                    "caddy_use_caddyfile", yaml_cfg.caddy_use_caddyfile
                )
            ),
            caddy_caddyfile_path=str(
                stored.get("caddy_caddyfile_path")
                or yaml_cfg.caddy_caddyfile_path
                or "/config/Caddyfile"
            ).strip(),
            caddy_use_labels=bool(
                stored.get("caddy_use_labels", yaml_cfg.caddy_use_labels)
            ),
            verify_tls=bool(stored.get("verify_tls", yaml_cfg.verify_tls)),
            timeout_seconds=float(
                stored.get("timeout_seconds") or yaml_cfg.timeout_seconds or 5.0
            ),
        )
        return cfg, "db"

    if yaml_cfg.proxy_type != "none":
        return yaml_cfg, "yaml"

    return NetworkingConfig(), "none"


def networking_public_view() -> dict[str, Any]:
    cfg, source = resolve_networking()
    return {
        "source": source,
        "proxy_type": cfg.proxy_type,
        "caddy_use_admin_api": cfg.caddy_use_admin_api,
        "caddy_admin_url": cfg.caddy_admin_url,
        "caddy_use_caddyfile": cfg.caddy_use_caddyfile,
        "caddy_caddyfile_path": cfg.caddy_caddyfile_path,
        "caddy_use_labels": cfg.caddy_use_labels,
        "verify_tls": cfg.verify_tls,
        "timeout_seconds": cfg.timeout_seconds,
        "configured": cfg.proxy_type != "none",
    }


def _new_digest_profile_id() -> str:
    import uuid

    return uuid.uuid4().hex[:12]


def _profile_schedule_fields(raw: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
    from app.digest_schedule import cron_to_schedule, schedule_to_cron

    freq = raw.get("schedule_frequency", fallback.get("schedule_frequency"))
    weekday = raw.get("schedule_weekday", fallback.get("schedule_weekday"))
    hour = raw.get("schedule_hour", fallback.get("schedule_hour"))
    minute = raw.get("schedule_minute", fallback.get("schedule_minute"))
    cron = (raw.get("digest_cron") or fallback.get("digest_cron") or "").strip()

    if freq is None and cron:
        parsed = cron_to_schedule(cron)
        freq = parsed.get("frequency")
        weekday = parsed.get("weekday")
        hour = parsed.get("hour")
        minute = parsed.get("minute")

    derived = schedule_to_cron(freq, weekday=weekday, hour=hour, minute=minute)
    if derived:
        cron = derived
    elif not cron:
        cron = ""

    return {
        "schedule_frequency": freq,
        "schedule_weekday": str(weekday) if weekday is not None and weekday != "" else None,
        "schedule_hour": hour,
        "schedule_minute": minute,
        "digest_cron": cron,
    }


def _normalize_digest_profile(
    raw: dict[str, Any] | None,
    *,
    defaults: dict[str, Any],
    fallback_name: str = "Default",
) -> dict[str, Any]:
    raw = raw if isinstance(raw, dict) else {}
    pid = str(raw.get("id") or "").strip() or _new_digest_profile_id()
    name = str(raw.get("name") or fallback_name).strip() or fallback_name
    sched = _profile_schedule_fields(raw, defaults)
    from_addr = raw.get("digest_from")
    if from_addr is None or from_addr == "":
        from_addr = defaults.get("digest_from") or ""
    to_addr = raw.get("digest_to")
    if to_addr is None or to_addr == "":
        to_addr = defaults.get("digest_to") or ""
    tz = raw.get("tz")
    if tz is None or str(tz).strip() == "":
        tz = defaults.get("tz") or "UTC"
    all_clear = raw.get("digest_send_all_clear")
    if all_clear is None:
        all_clear = defaults.get("digest_send_all_clear", True)
    enabled = raw.get("enabled")
    if enabled is None:
        enabled = defaults.get("enabled", False)
    return {
        "id": pid,
        "name": name,
        "enabled": bool(enabled),
        "digest_from": from_addr,
        "digest_to": to_addr,
        "digest_send_all_clear": bool(all_clear),
        "tz": str(tz).strip() or "UTC",
        **sched,
    }


def _legacy_digest_to_profiles(stored: dict[str, Any], defaults: dict[str, Any]) -> list[dict[str, Any]]:
    """Wrap pre-multi-profile flat digest settings into one profile."""
    flat = {**defaults}
    for k, v in stored.items():
        if k in ("configured", "profiles", "resend_api_key"):
            continue
        if v is not None and v != "":
            flat[k] = v
    return [
        _normalize_digest_profile(
            {
                "id": stored.get("id") or _new_digest_profile_id(),
                "name": stored.get("name") or "Default",
                "enabled": flat.get("enabled", False),
                "digest_from": flat.get("digest_from"),
                "digest_to": flat.get("digest_to"),
                "digest_send_all_clear": flat.get("digest_send_all_clear", True),
                "tz": flat.get("tz"),
                "schedule_frequency": flat.get("schedule_frequency"),
                "schedule_weekday": flat.get("schedule_weekday"),
                "schedule_hour": flat.get("schedule_hour"),
                "schedule_minute": flat.get("schedule_minute"),
                "digest_cron": flat.get("digest_cron"),
            },
            defaults=defaults,
        )
    ]


def _digest_env_defaults(settings: Settings) -> dict[str, Any]:
    from app.digest_schedule import cron_to_schedule

    env_cron = (settings.digest_cron or "").strip()
    defaults: dict[str, Any] = {
        "enabled": False,
        "digest_from": settings.digest_from,
        "digest_to": settings.digest_to,
        "digest_cron": env_cron,
        "digest_send_all_clear": settings.digest_send_all_clear,
        "tz": settings.tz or "UTC",
        "schedule_frequency": None,
        "schedule_weekday": None,
        "schedule_hour": None,
        "schedule_minute": None,
    }
    if env_cron:
        parsed = cron_to_schedule(env_cron)
        defaults.update(
            {
                "schedule_frequency": parsed.get("frequency"),
                "schedule_weekday": parsed.get("weekday"),
                "schedule_hour": parsed.get("hour"),
                "schedule_minute": parsed.get("minute"),
            }
        )
    return defaults


def resolve_digest_settings(
    settings: Settings | None = None,
) -> tuple[dict[str, Any], SettingSource]:
    """
    Digest config as shared Resend key + list of profiles.

    Migrates legacy single-object digest settings into one profile on read
    (persisted once). No silent schedule default — digests are not scheduled
    until a profile has a complete Daily/Weekly time (or DIGEST_CRON env).
    """
    settings = settings or get_settings()
    stored = db.get_setting("digest")
    defaults = _digest_env_defaults(settings)
    env_key = (settings.resend_api_key or "").strip()

    if isinstance(stored, dict) and stored.get("configured"):
        key = stored.get("resend_api_key")
        if key is None or key == "":
            key = env_key
        else:
            key = str(key).strip()

        raw_profiles = stored.get("profiles")
        migrated = False
        if isinstance(raw_profiles, list):
            profiles = [
                _normalize_digest_profile(p if isinstance(p, dict) else {}, defaults=defaults)
                for p in raw_profiles
            ]
            if not profiles:
                profiles = [
                    _normalize_digest_profile(
                        {"name": "Default", "enabled": False},
                        defaults=defaults,
                    )
                ]
                migrated = True
        else:
            profiles = _legacy_digest_to_profiles(stored, defaults)
            migrated = True

        result = {
            "configured": True,
            "resend_api_key": key,
            "profiles": profiles,
        }
        if migrated:
            # Persist new shape so nothing is lost and later reads stay consistent.
            to_store = {
                "configured": True,
                "resend_api_key": stored.get("resend_api_key")
                if stored.get("resend_api_key") is not None
                else "",
                "profiles": [
                    {k: v for k, v in p.items()}
                    for p in profiles
                ],
            }
            # Keep DB key as stored (may be empty → fall back to env at resolve time)
            if "resend_api_key" in stored:
                to_store["resend_api_key"] = stored.get("resend_api_key") or ""
            db.set_setting("digest", to_store)
        return result, "db"

    source: SettingSource = (
        "env"
        if env_key or settings.digest_to or (settings.digest_cron or "").strip()
        else "default"
    )
    return {
        "configured": False,
        "resend_api_key": env_key,
        "profiles": [
            _normalize_digest_profile(
                {
                    "id": "env-default",
                    "name": "Default",
                    "enabled": False,
                    "digest_from": defaults.get("digest_from"),
                    "digest_to": defaults.get("digest_to"),
                    "digest_send_all_clear": defaults.get("digest_send_all_clear", True),
                    "tz": defaults.get("tz"),
                    "schedule_frequency": defaults.get("schedule_frequency"),
                    "schedule_weekday": defaults.get("schedule_weekday"),
                    "schedule_hour": defaults.get("schedule_hour"),
                    "schedule_minute": defaults.get("schedule_minute"),
                    "digest_cron": defaults.get("digest_cron"),
                },
                defaults=defaults,
            )
        ],
    }, source


def get_digest_profile(
    profile_id: str | None = None,
    *,
    settings: Settings | None = None,
) -> tuple[dict[str, Any], dict[str, Any], SettingSource] | None:
    """
    Return (shared_cfg, profile, source) for a profile id.
    If profile_id is None, prefer the first enabled profile, else the first.
    """
    data, source = resolve_digest_settings(settings)
    profiles = data.get("profiles") or []
    if not profiles:
        return None
    if profile_id:
        for p in profiles:
            if str(p.get("id")) == str(profile_id):
                return data, p, source
        return None
    for p in profiles:
        if p.get("enabled"):
            return data, p, source
    return data, profiles[0], source


def _profile_public_view(profile: dict[str, Any], *, has_key: bool) -> dict[str, Any]:
    from app.digest_schedule import is_schedule_complete, schedule_summary

    scheduled = is_schedule_complete(profile)
    freq = profile.get("schedule_frequency")
    weekday = profile.get("schedule_weekday")
    hour = profile.get("schedule_hour")
    minute = profile.get("schedule_minute")
    tz = profile.get("tz") or "UTC"
    to_addr = (profile.get("digest_to") or "").strip()
    return {
        "id": profile.get("id"),
        "name": profile.get("name") or "Digest",
        "enabled": bool(profile.get("enabled", False)),
        "digest_from": profile.get("digest_from") or "",
        "digest_to": to_addr,
        "digest_send_all_clear": bool(profile.get("digest_send_all_clear", True)),
        "tz": tz,
        "schedule_frequency": freq,
        "schedule_weekday": str(weekday) if weekday is not None else None,
        "schedule_hour": hour,
        "schedule_minute": minute,
        "scheduled": scheduled,
        "schedule_summary": schedule_summary(
            frequency=freq,
            weekday=str(weekday) if weekday is not None else None,
            hour=hour if isinstance(hour, int) else (int(hour) if hour is not None else None),
            minute=minute
            if isinstance(minute, int)
            else (int(minute) if minute is not None else None),
            tz=tz,
        ),
        "digest_cron": (profile.get("digest_cron") or "") if scheduled else "",
        "configured": bool(has_key and to_addr and scheduled),
    }


def digest_public_view() -> dict[str, Any]:
    data, source = resolve_digest_settings()
    stored = db.get_setting("digest") or {}
    key = (data.get("resend_api_key") or "").strip()
    has_key = bool(key)
    profiles = [
        _profile_public_view(p, has_key=has_key) for p in (data.get("profiles") or [])
    ]

    # Aggregate fields for status footer / older clients (first enabled scheduled, else first).
    primary = next((p for p in profiles if p.get("enabled") and p.get("scheduled")), None)
    if primary is None:
        primary = next((p for p in profiles if p.get("enabled")), None)
    if primary is None and profiles:
        primary = profiles[0]
    primary = primary or {
        "enabled": False,
        "digest_from": "",
        "digest_to": "",
        "digest_send_all_clear": True,
        "tz": "UTC",
        "schedule_frequency": None,
        "schedule_weekday": None,
        "schedule_hour": None,
        "schedule_minute": None,
        "scheduled": False,
        "schedule_summary": "Not scheduled yet",
        "digest_cron": "",
        "configured": False,
    }

    any_enabled = any(p.get("enabled") for p in profiles)
    any_configured = any(p.get("configured") for p in profiles)

    return {
        "source": source,
        "has_resend_api_key": has_key,
        "resend_api_key_in_db": bool((stored.get("resend_api_key") or "").strip())
        if isinstance(stored, dict)
        else False,
        "profiles": profiles,
        # Aggregates / back-compat single-digest shape
        "enabled": any_enabled,
        "digest_from": primary.get("digest_from") or "",
        "digest_to": primary.get("digest_to") or "",
        "digest_send_all_clear": bool(primary.get("digest_send_all_clear", True)),
        "tz": primary.get("tz") or "UTC",
        "schedule_frequency": primary.get("schedule_frequency"),
        "schedule_weekday": primary.get("schedule_weekday"),
        "schedule_hour": primary.get("schedule_hour"),
        "schedule_minute": primary.get("schedule_minute"),
        "scheduled": bool(primary.get("scheduled")),
        "schedule_summary": primary.get("schedule_summary") or "Not scheduled yet",
        "digest_cron": primary.get("digest_cron") or "",
        "configured": any_configured,
    }


def resolve_general(
    settings: Settings | None = None,
) -> tuple[dict[str, Any], SettingSource]:
    settings = settings or get_settings()
    stored = db.get_setting("general")
    # actions_enabled defaults True for homelab convenience; risks shown in Settings UI.
    base = {
        "poll_interval_seconds": settings.poll_interval_seconds,
        "registry_cache_hours": reload_yaml_config().registry_cache_hours,
        "actions_enabled": True,
    }
    if isinstance(stored, dict) and stored.get("configured"):
        merged = {**base}
        for k, v in stored.items():
            if k == "configured":
                continue
            if v is not None:
                merged[k] = v
        return merged, "db"
    return base, "env"


def actions_enabled() -> bool:
    general, _ = resolve_general()
    return bool(general.get("actions_enabled", True))


def effective_yaml_overlay() -> AppYamlConfig:
    yaml_cfg = reload_yaml_config()
    targets = resolve_check_targets()
    thresholds, _ = resolve_thresholds()
    security, _ = resolve_security()
    listening_ports, _ = resolve_listening_ports()
    speed_test, _ = resolve_speed_test()
    general, _ = resolve_general()
    return AppYamlConfig(
        targets=targets,
        thresholds=thresholds,
        registry_cache_hours=float(
            general.get("registry_cache_hours") or yaml_cfg.registry_cache_hours
        ),
        container_urls=dict(yaml_cfg.container_urls),
        pihole=resolve_pihole()[0],
        networking=resolve_networking()[0],
        security=security,
        listening_ports=listening_ports,
        speed_test=speed_test,
    )


def effective_poll_interval() -> int:
    general, _ = resolve_general()
    try:
        return max(60, int(general.get("poll_interval_seconds") or 300))
    except Exception:
        return 300
