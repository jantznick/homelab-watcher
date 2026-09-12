"""Plain-language digest schedule ↔ internal cron (users never see cron)."""

from __future__ import annotations

from typing import Any, Literal

Frequency = Literal["daily", "weekly"]

WEEKDAYS = [
    ("0", "Sunday"),
    ("1", "Monday"),
    ("2", "Tuesday"),
    ("3", "Wednesday"),
    ("4", "Thursday"),
    ("5", "Friday"),
    ("6", "Saturday"),
]

_WEEKDAY_LABEL = {k: v for k, v in WEEKDAYS}


def schedule_to_cron(
    frequency: str | None,
    *,
    weekday: str | int | None = None,
    hour: int | None = None,
    minute: int | None = None,
) -> str | None:
    """Build a 5-field cron from UI fields. Returns None if incomplete."""
    if frequency not in ("daily", "weekly"):
        return None
    if hour is None or minute is None:
        return None
    try:
        h = int(hour)
        m = int(minute)
    except (TypeError, ValueError):
        return None
    if not (0 <= h <= 23 and 0 <= m <= 59):
        return None
    if frequency == "daily":
        return f"{m} {h} * * *"
    wd = str(weekday) if weekday is not None else ""
    if wd not in _WEEKDAY_LABEL:
        return None
    return f"{m} {h} * * {wd}"


def cron_to_schedule(cron: str | None) -> dict[str, Any]:
    """Best-effort parse of an existing cron into UI fields."""
    empty: dict[str, Any] = {
        "frequency": None,
        "weekday": None,
        "hour": None,
        "minute": None,
    }
    parts = str(cron or "").split()
    if len(parts) != 5:
        return empty
    minute, hour, day, month, dow = parts
    if day != "*" or month != "*":
        return empty
    try:
        mi = int(minute)
        ho = int(hour)
    except ValueError:
        return empty
    if dow == "*":
        return {"frequency": "daily", "weekday": None, "hour": ho, "minute": mi}
    if dow in _WEEKDAY_LABEL and "," not in dow and "-" not in dow:
        return {"frequency": "weekly", "weekday": dow, "hour": ho, "minute": mi}
    return empty


def schedule_summary(
    *,
    frequency: str | None,
    weekday: str | None,
    hour: int | None,
    minute: int | None,
    tz: str,
) -> str:
    if frequency not in ("daily", "weekly") or hour is None or minute is None:
        return "Not scheduled yet"
    time_s = f"{int(hour):02d}:{int(minute):02d}"
    tz_s = (tz or "UTC").strip() or "UTC"
    if frequency == "daily":
        return f"Every day at {time_s} ({tz_s})"
    label = _WEEKDAY_LABEL.get(str(weekday), "chosen day")
    return f"Every {label} at {time_s} ({tz_s})"


def is_schedule_complete(data: dict[str, Any]) -> bool:
    cron = (data.get("digest_cron") or "").strip()
    if cron and len(cron.split()) == 5:
        return True
    return (
        schedule_to_cron(
            data.get("schedule_frequency"),
            weekday=data.get("schedule_weekday"),
            hour=data.get("schedule_hour"),
            minute=data.get("schedule_minute"),
        )
        is not None
    )
