"""Resolve browser access URLs for containers from labels and config."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

# Prefer explicit watcher labels, then common Caddy docker-proxy site labels.
_LABEL_URL_KEYS = (
    "homelab.watcher.url",
    "homelab.url",
)

# Bare `caddy` / `caddy_0` hold the site address; `caddy.reverse_proxy` etc. are directives.
_CADDY_SITE_KEY = re.compile(r"^caddy(?:_\d+)?$", re.IGNORECASE)

# Values that are clearly not hostnames / URLs
_SKIP_VALUE = re.compile(
    r"^(import|respond|redir|rewrite|reverse_proxy|handle|route|basicauth|"
    r"encode|header|log|tls|file_server|php_fastcgi|root|uri)\b",
    re.IGNORECASE,
)


def _looks_like_host_or_url(value: str) -> bool:
    v = value.strip()
    if not v or len(v) > 253:
        return False
    if _SKIP_VALUE.match(v):
        return False
    if " " in v or "{" in v or "}" in v:
        return False
    if v.startswith("/") or v.startswith("@"):
        return False
    # Hostname or URL with host
    if "://" in v:
        try:
            parsed = urlparse(v)
            return bool(parsed.hostname)
        except Exception:
            return False
    # hostname or hostname:port or host/path
    host_part = v.split("/", 1)[0].split(":", 1)[0]
    if "." not in host_part and host_part.lower() not in ("localhost",):
        # Allow single-label local names when they look like hostnames
        return bool(re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?", host_part))
    return bool(re.fullmatch(r"[A-Za-z0-9._:-]+", host_part))


def normalize_access_url(value: str) -> str | None:
    """Turn a hostname or URL into an https:// URL when possible."""
    v = (value or "").strip().rstrip("/")
    if not v or not _looks_like_host_or_url(v):
        return None
    if "://" not in v:
        v = f"https://{v}"
    try:
        parsed = urlparse(v)
        if not parsed.scheme or not parsed.netloc:
            return None
        # Drop path/query for display consistency unless path was intentional and non-root
        path = parsed.path or ""
        if path in ("", "/"):
            return f"{parsed.scheme}://{parsed.netloc}"
        return f"{parsed.scheme}://{parsed.netloc}{path}".rstrip("/")
    except Exception:
        return None


def hostname_from_url(url: str | None) -> str | None:
    if not url:
        return None
    try:
        host = urlparse(url).hostname
        return host.lower().rstrip(".") if host else None
    except Exception:
        return None


def url_from_labels(labels: dict[str, str] | None) -> tuple[str | None, str | None]:
    """
    Return (url, source) from Docker labels.
    source is 'label' (homelab.*) or 'caddy'.
    """
    if not labels:
        return None, None

    for key in _LABEL_URL_KEYS:
        raw = labels.get(key)
        if raw:
            url = normalize_access_url(raw)
            if url:
                return url, "label"

    # Collect caddy site addresses (may be comma-separated)
    candidates: list[str] = []
    for key, raw in labels.items():
        if not _CADDY_SITE_KEY.match(key):
            continue
        if not raw:
            continue
        for part in re.split(r"[\s,]+", raw.strip()):
            if _looks_like_host_or_url(part):
                candidates.append(part)

    for cand in candidates:
        url = normalize_access_url(cand)
        if url:
            return url, "caddy"

    return None, None


def resolve_access_url(
    container_name: str,
    labels: dict[str, str] | None,
    container_urls: dict[str, str] | None,
) -> tuple[str | None, str | None]:
    """
    Prefer explicit labels, then config mapping by container name.
    Config wins over Caddy-inferred URLs so operators can override.
    Order: homelab labels → config map → caddy labels.
    """
    labels = labels or {}
    container_urls = container_urls or {}

    for key in _LABEL_URL_KEYS:
        raw = labels.get(key)
        if raw:
            url = normalize_access_url(raw)
            if url:
                return url, "label"

    # Config mapping: exact name, then case-insensitive
    mapped = container_urls.get(container_name)
    if not mapped:
        lower = {k.lower(): v for k, v in container_urls.items()}
        mapped = lower.get(container_name.lower())
    if mapped:
        url = normalize_access_url(mapped)
        if url:
            return url, "config"

    return url_from_labels(labels)


def enrich_container_access(
    containers: list[dict[str, Any]],
    container_urls: dict[str, str] | None,
) -> None:
    """Mutate container dicts with access_url / access_url_source."""
    for c in containers:
        url, source = resolve_access_url(
            c.get("name") or "",
            c.get("labels") or {},
            container_urls,
        )
        c["access_url"] = url
        c["access_url_source"] = source
