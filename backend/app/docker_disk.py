"""Docker disk usage (system df) — read-only; fail-soft when Docker is down."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from app.docker_client import _client, get_docker_error

logger = logging.getLogger(__name__)


def _utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def _i(val: Any) -> int:
    try:
        return max(0, int(val or 0))
    except (TypeError, ValueError):
        return 0


def _pct(reclaimable: int, size: int) -> float | None:
    if size <= 0:
        return 0.0 if reclaimable <= 0 else None
    return round(min(100.0, 100.0 * reclaimable / size), 1)


def _summarize_images(raw: dict[str, Any]) -> dict[str, Any]:
    images = raw.get("Images") or []
    size = _i(raw.get("LayersSize"))
    if size <= 0 and images:
        # Fallback when LayersSize is missing
        size = sum(max(0, _i(im.get("Size")) - _i(im.get("SharedSize"))) for im in images)
    active = sum(1 for im in images if _i(im.get("Containers")) > 0)
    reclaimable = 0
    for im in images:
        if _i(im.get("Containers")) > 0:
            continue
        # Unused image: prefer unique size (Size - SharedSize)
        sz = _i(im.get("Size"))
        shared = _i(im.get("SharedSize"))
        reclaimable += max(0, sz - shared) if shared else sz
    if size > 0:
        reclaimable = min(reclaimable, size)
    return {
        "type": "Images",
        "label": "Images",
        "total_count": len(images),
        "active_count": active,
        "size_bytes": size,
        "reclaimable_bytes": reclaimable,
        "reclaimable_percent": _pct(reclaimable, size),
    }


def _summarize_containers(raw: dict[str, Any]) -> dict[str, Any]:
    containers = raw.get("Containers") or []
    size = 0
    reclaimable = 0
    active = 0
    for c in containers:
        rw = _i(c.get("SizeRw"))
        size += rw
        state = (c.get("State") or c.get("Status") or "").lower()
        running = state == "running" or bool(c.get("Running"))
        if running:
            active += 1
        else:
            reclaimable += rw
    return {
        "type": "Containers",
        "label": "Containers",
        "total_count": len(containers),
        "active_count": active,
        "size_bytes": size,
        "reclaimable_bytes": reclaimable,
        "reclaimable_percent": _pct(reclaimable, size),
    }


def _summarize_volumes(raw: dict[str, Any]) -> dict[str, Any]:
    volumes = raw.get("Volumes") or []
    size = 0
    reclaimable = 0
    active = 0
    for v in volumes:
        usage = v.get("UsageData") or {}
        sz = _i(usage.get("Size"))
        ref = _i(usage.get("RefCount"))
        size += sz
        if ref > 0:
            active += 1
        else:
            reclaimable += sz
    return {
        "type": "Volumes",
        "label": "Local volumes",
        "total_count": len(volumes),
        "active_count": active,
        "size_bytes": size,
        "reclaimable_bytes": reclaimable,
        "reclaimable_percent": _pct(reclaimable, size),
    }


def _summarize_build_cache(raw: dict[str, Any]) -> dict[str, Any]:
    cache = raw.get("BuildCache") or []
    size = 0
    reclaimable = 0
    active = 0
    for entry in cache:
        sz = _i(entry.get("Size"))
        size += sz
        in_use = bool(entry.get("InUse"))
        if in_use:
            active += 1
        else:
            reclaimable += sz
    return {
        "type": "BuildCache",
        "label": "Build cache",
        "total_count": len(cache),
        "active_count": active,
        "size_bytes": size,
        "reclaimable_bytes": reclaimable,
        "reclaimable_percent": _pct(reclaimable, size),
    }


def get_docker_disk_usage() -> dict[str, Any]:
    """
    Snapshot equivalent to `docker system df` (+ counts like -v summary).

    Never raises to callers — returns available=False when Docker is unreachable.
    """
    try:
        client = _client()
    except Exception as exc:
        err = get_docker_error() or str(exc)
        logger.debug("Docker disk usage unavailable: %s", exc)
        return {
            "available": False,
            "error": err,
            "taken_at": None,
            "layers_size_bytes": None,
            "categories": [],
            "total_bytes": None,
            "reclaimable_bytes": None,
        }

    try:
        raw = client.df() or {}
        categories = [
            _summarize_images(raw),
            _summarize_containers(raw),
            _summarize_volumes(raw),
            _summarize_build_cache(raw),
        ]
        total = sum(_i(c.get("size_bytes")) for c in categories)
        reclaimable = sum(_i(c.get("reclaimable_bytes")) for c in categories)
        return {
            "available": True,
            "error": None,
            "taken_at": _utc(),
            "layers_size_bytes": _i(raw.get("LayersSize")),
            "categories": categories,
            "total_bytes": total,
            "reclaimable_bytes": reclaimable,
        }
    except Exception as exc:
        logger.warning("docker df failed: %s", exc)
        return {
            "available": False,
            "error": str(exc),
            "taken_at": None,
            "layers_size_bytes": None,
            "categories": [],
            "total_bytes": None,
            "reclaimable_bytes": None,
        }
    finally:
        try:
            client.close()
        except Exception:
            pass
