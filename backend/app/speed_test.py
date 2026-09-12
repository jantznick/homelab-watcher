"""
Lightweight Internet speed check via Cloudflare's public speed endpoints.

No API key. Uses the same hosts as https://speed.cloudflare.com:
  - GET  https://speed.cloudflare.com/__down?bytes=N  (download)
  - POST https://speed.cloudflare.com/__up            (upload)
  - GET  https://speed.cloudflare.com/__down?bytes=0  (latency)

Designed to be infrequent and fail-soft — never raises to callers.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_DOWN_URL = "https://speed.cloudflare.com/__down"
_UP_URL = "https://speed.cloudflare.com/__up"
_PROVIDER = "cloudflare"

# Keep transfers modest — this is a health snapshot, not a lab benchmark.
_DOWNLOAD_BYTES = 5 * 1024 * 1024  # 5 MiB
_UPLOAD_BYTES = 2 * 1024 * 1024  # 2 MiB
_LATENCY_SAMPLES = 3
_TIMEOUT = httpx.Timeout(connect=10.0, read=90.0, write=90.0, pool=10.0)

_lock = threading.Lock()
_running = False
_pending = False


def speed_test_busy() -> bool:
    return _running or _pending


def mark_speed_test_pending() -> bool:
    """Reserve a run slot before spawning a background thread. False if busy."""
    global _pending
    with _lock:
        if _running or _pending:
            return False
        _pending = True
        return True


def clear_speed_test_pending() -> None:
    global _pending
    _pending = False


def _mbps(nbytes: int, elapsed_s: float) -> float | None:
    if elapsed_s <= 0 or nbytes <= 0:
        return None
    return round((nbytes * 8) / (elapsed_s * 1_000_000), 2)


def _measure_latency(client: httpx.Client) -> float | None:
    samples: list[float] = []
    for _ in range(_LATENCY_SAMPLES):
        t0 = time.perf_counter()
        try:
            r = client.get(_DOWN_URL, params={"bytes": 0})
            r.raise_for_status()
            # Drain tiny body
            _ = r.content
        except Exception:
            continue
        samples.append((time.perf_counter() - t0) * 1000.0)
    if not samples:
        return None
    samples.sort()
    return round(samples[len(samples) // 2], 1)


def _measure_download(client: httpx.Client) -> float | None:
    t0 = time.perf_counter()
    try:
        with client.stream(
            "GET", _DOWN_URL, params={"bytes": _DOWNLOAD_BYTES}
        ) as r:
            r.raise_for_status()
            total = 0
            for chunk in r.iter_bytes():
                total += len(chunk)
        elapsed = time.perf_counter() - t0
        return _mbps(total, elapsed)
    except Exception as exc:
        logger.warning("Speed test download failed: %s", exc)
        return None


def _measure_upload(client: httpx.Client) -> float | None:
    payload = b"0" * _UPLOAD_BYTES
    t0 = time.perf_counter()
    try:
        r = client.post(
            _UP_URL,
            content=payload,
            headers={"Content-Type": "application/octet-stream"},
        )
        r.raise_for_status()
        elapsed = time.perf_counter() - t0
        return _mbps(len(payload), elapsed)
    except Exception as exc:
        logger.warning("Speed test upload failed: %s", exc)
        return None


def run_speed_test() -> dict[str, Any]:
    """
    Run one download/upload/latency check. Serialized with a process lock.

    Returns a result dict always (ok True/False). Does not raise.
    """
    global _running, _pending
    acquired = _lock.acquire(blocking=False)
    if not acquired:
        _pending = False
        return {
            "ok": False,
            "provider": _PROVIDER,
            "taken_at": datetime.now(timezone.utc).isoformat(),
            "download_mbps": None,
            "upload_mbps": None,
            "ping_ms": None,
            "error": "Speed test already running.",
            "busy": True,
        }

    _running = True
    _pending = False
    taken_at = datetime.now(timezone.utc).isoformat()
    result: dict[str, Any] = {
        "ok": False,
        "provider": _PROVIDER,
        "taken_at": taken_at,
        "download_mbps": None,
        "upload_mbps": None,
        "ping_ms": None,
        "error": None,
        "busy": False,
    }
    try:
        with httpx.Client(timeout=_TIMEOUT, follow_redirects=True) as client:
            ping = _measure_latency(client)
            down = _measure_download(client)
            up = _measure_upload(client)
        result["ping_ms"] = ping
        result["download_mbps"] = down
        result["upload_mbps"] = up
        if down is None and up is None and ping is None:
            result["error"] = "Speed check unreachable."
        else:
            result["ok"] = True
            if down is None or up is None:
                result["error"] = "Partial result (some legs failed)."
    except Exception as exc:
        logger.warning("Speed test failed: %s", exc)
        result["error"] = "Speed check failed."
    finally:
        _running = False
        _pending = False
        _lock.release()
    return result


def should_run_scheduled(
    *,
    enabled: bool,
    interval_hours: float,
    last: dict[str, Any] | None,
) -> bool:
    """True when a scheduled run is due (enabled + interval elapsed / never run)."""
    if not enabled:
        return False
    try:
        hours = float(interval_hours)
    except (TypeError, ValueError):
        hours = 12.0
    if hours <= 0:
        return False
    if _running:
        return False
    if not isinstance(last, dict) or not last.get("taken_at"):
        return True
    try:
        raw = str(last["taken_at"]).replace("Z", "+00:00")
        prev = datetime.fromisoformat(raw)
        if prev.tzinfo is None:
            prev = prev.replace(tzinfo=timezone.utc)
        age_h = (datetime.now(timezone.utc) - prev).total_seconds() / 3600.0
        return age_h >= hours
    except Exception:
        return True
