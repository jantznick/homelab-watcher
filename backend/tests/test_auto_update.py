"""Tests for per-container auto-update policy normalization and schedule."""

from __future__ import annotations

import pytest

from app.auto_update import normalize_policy_input, policy_public_view
from app.digest_schedule import schedule_to_cron


def test_schedule_to_cron_daily():
    assert schedule_to_cron("daily", hour=3, minute=15) == "15 3 * * *"


def test_schedule_to_cron_weekly():
    assert schedule_to_cron("weekly", weekday="1", hour=4, minute=0) == "0 4 * * 1"


def test_normalize_requires_schedule_when_enabled():
    with pytest.raises(ValueError, match="complete schedule"):
        normalize_policy_input({"enabled": True, "schedule_frequency": "daily"})


def test_normalize_allows_disabled_incomplete():
    out = normalize_policy_input(
        {
            "enabled": False,
            "schedule_frequency": "",
            "only_when_available": True,
            "tz": "America/Chicago",
        }
    )
    assert out["enabled"] is False
    assert out["cron"] is None
    assert out["only_when_available"] is True
    assert out["tz"] == "America/Chicago"


def test_normalize_daily_complete():
    out = normalize_policy_input(
        {
            "enabled": True,
            "schedule_frequency": "daily",
            "schedule_hour": 6,
            "schedule_minute": 30,
            "tz": "UTC",
            "only_when_available": False,
            "name": "plex",
        }
    )
    assert out["cron"] == "30 6 * * *"
    assert out["only_when_available"] is False
    assert out["name"] == "plex"


def test_policy_public_view_summary():
    view = policy_public_view(
        {
            "watched_key": "compose:stack/app",
            "enabled": True,
            "schedule_frequency": "weekly",
            "schedule_weekday": "1",
            "schedule_hour": 2,
            "schedule_minute": 0,
            "cron": "0 2 * * 1",
            "tz": "UTC",
            "only_when_available": True,
        }
    )
    assert view["scheduled"] is True
    assert "Monday" in (view["schedule_summary"] or "")
    assert view["enabled"] is True
    assert view["watched_key"] == "compose:stack/app"
