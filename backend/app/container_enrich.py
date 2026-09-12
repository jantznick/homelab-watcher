"""Correlate containers with Pi-hole local DNS hostnames."""

from __future__ import annotations

import re
from typing import Any

from app.access_urls import hostname_from_url
from app.pihole import DnsRecord, PiHoleResult


def _norm(s: str) -> str:
    return s.strip().lower().rstrip(".")


def _first_label(hostname: str) -> str:
    return _norm(hostname).split(".", 1)[0]


def _image_tokens(image: str) -> set[str]:
    """Extract rough service tokens from image refs like ghcr.io/org/app:tag."""
    if not image:
        return set()
    ref = image.split("@", 1)[0]
    parts = ref.split("/")
    if len(parts) >= 2 and ("." in parts[0] or parts[0] == "localhost"):
        parts = parts[1:]
    name = parts[-1] if parts else ref
    name = name.split(":", 1)[0]
    tokens = {_norm(name)}
    for piece in re.split(r"[-_]", name):
        if len(piece) >= 3:
            tokens.add(_norm(piece))
    return {t for t in tokens if t}


def _container_tokens(container: dict[str, Any]) -> set[str]:
    name = _norm(container.get("name") or "")
    labels = container.get("labels") or {}
    tokens: set[str] = set()
    if name:
        tokens.add(name)
        if "_" in name:
            tokens.add(name.split("_", 1)[-1])
            tokens.add(name.rsplit("_", 1)[-1])
        for piece in re.split(r"[-_]", name):
            if len(piece) >= 3:
                tokens.add(piece)

    service = labels.get("com.docker.compose.service")
    if service:
        tokens.add(_norm(service))

    tokens |= _image_tokens(container.get("image") or "")

    access_host = hostname_from_url(container.get("access_url"))
    if access_host:
        tokens.add(access_host)
        tokens.add(_first_label(access_host))

    return {t for t in tokens if t}


def _dns_matches_container(
    hostname: str, tokens: set[str], access_host: str | None
) -> bool:
    hn = _norm(hostname)
    if not hn:
        return False
    if access_host and (
        hn == access_host
        or hn.endswith("." + access_host)
        or access_host.endswith("." + hn)
    ):
        return True
    if access_host and _first_label(hn) == _first_label(access_host):
        return True

    label = _first_label(hn)
    if label in tokens or hn in tokens:
        return True

    for t in tokens:
        if len(t) < 3:
            continue
        if t == label or t == hn:
            return True
        if "." not in t and (hn.startswith(t + ".") or f".{t}." in f".{hn}."):
            return True
    return False


def correlate_pihole(
    containers: list[dict[str, Any]],
    pihole: PiHoleResult,
) -> dict[str, Any]:
    """
    Mutate containers with pihole_matched / pihole_hostnames.
    Returns a serializable pihole status dict for the API.
    """
    status: dict[str, Any] = {
        "configured": pihole.configured,
        "ok": pihole.ok if pihole.configured else None,
        "version": pihole.version,
        "message": pihole.message,
        "record_count": len(pihole.records),
    }

    if not pihole.configured or not pihole.ok or not pihole.records:
        for c in containers:
            c["pihole_matched"] = False
            c["pihole_hostnames"] = []
        return status

    by_host: dict[str, list[DnsRecord]] = {}
    for rec in pihole.records:
        by_host.setdefault(rec.hostname, []).append(rec)

    all_hosts = list(by_host.keys())

    for c in containers:
        tokens = _container_tokens(c)
        access_host = hostname_from_url(c.get("access_url"))
        matched = sorted(
            {
                hn
                for hn in all_hosts
                if _dns_matches_container(hn, tokens, access_host)
            }
        )
        c["pihole_matched"] = bool(matched)
        c["pihole_hostnames"] = matched

    return status
