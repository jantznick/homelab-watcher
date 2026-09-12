"""Pi-hole status helpers for containers (no hostname≈name fuzzy matching)."""

from __future__ import annotations

from typing import Any

from app.pihole import PiHoleResult


def clear_pihole_fields(containers: list[dict[str, Any]]) -> None:
    """Reset Pi-hole badge fields — joins come only from networking.py."""
    for c in containers:
        c["pihole_matched"] = False
        c["pihole_hostnames"] = []


def pihole_status_dict(pihole: PiHoleResult) -> dict[str, Any]:
    """Serializable Pi-hole status for the API (no container correlation)."""
    return {
        "configured": pihole.configured,
        "ok": pihole.ok if pihole.configured else None,
        "version": pihole.version,
        "message": pihole.message,
        "record_count": len(pihole.records),
    }


def correlate_pihole(
    containers: list[dict[str, Any]],
    pihole: PiHoleResult,
) -> dict[str, Any]:
    """
    Clear leftover badge fields and return Pi-hole status.

    Domain ↔ container joins are never inferred from hostname text.
    Use networking.enrich_networking (Caddy port → domain → DNS IP → host IP).
    """
    clear_pihole_fields(containers)
    return pihole_status_dict(pihole)
