"""Read-only directory browse under HOST_ROOT for Settings file pickers."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from app.config import get_settings
from app.host_metrics import _map_host_path, discover_disks, host_root_available

logger = logging.getLogger(__name__)

_NOTE = (
    "Read-only browse under the host mount (HOST_ROOT). "
    "Paths cannot escape that mount."
)


def _norm_host_path(path: str | None) -> str:
    raw = (path or "/").strip() or "/"
    if not raw.startswith("/"):
        raw = f"/{raw}"
    while "//" in raw:
        raw = raw.replace("//", "/")
    if raw != "/" and raw.endswith("/"):
        raw = raw.rstrip("/")
    return raw or "/"


def is_likely_caddy_file(name: str) -> bool:
    n = (name or "").strip()
    if not n:
        return False
    if n == "Caddyfile" or n.endswith(".Caddyfile"):
        return True
    lower = n.lower()
    return lower == "caddy.json" or lower.endswith(".caddyfile")


def _host_root_path() -> Path:
    return Path(get_settings().host_root)


def _is_under_root(candidate: Path, root: Path) -> bool:
    try:
        c = candidate.resolve(strict=False)
        r = root.resolve(strict=False)
    except OSError:
        return False
    if c == r:
        return True
    try:
        c.relative_to(r)
        return True
    except ValueError:
        return False


def _parent_host_path(host_path: str) -> str | None:
    if host_path == "/":
        return None
    parent = str(Path(host_path).parent)
    if parent == ".":
        return "/"
    return parent


def _quick_roots(root: Path) -> list[dict[str, str]]:
    roots: list[dict[str, str]] = [{"name": "Host /", "path": "/"}]
    seen = {"/"}
    try:
        disks, _, _ = discover_disks()
    except Exception as exc:
        logger.debug("browse roots: disk discover failed: %s", exc)
        disks = []
    for d in disks:
        mp = str(d.get("mountpoint") or d.get("path") or "").strip()
        if not mp or mp in seen:
            continue
        mapped = _map_host_path(mp)
        try:
            if mapped.is_dir() and _is_under_root(mapped, root):
                roots.append({"name": mp, "path": mp})
                seen.add(mp)
        except OSError:
            continue
    return roots


def browse_host_path(path: str | None = None) -> dict[str, Any]:
    """
    List directories/files under the host filesystem as seen via HOST_ROOT.

    ``path`` is a host path (e.g. ``/etc/caddy``). With Compose ``/:/host:ro``
    and ``HOST_ROOT=/host``, that maps to ``/host/etc/caddy`` inside Watcher.
    """
    host_path = _norm_host_path(path)
    root = _host_root_path()
    mounted = host_root_available()
    base: dict[str, Any] = {
        "ok": False,
        "path": host_path,
        "parent": _parent_host_path(host_path),
        "host_root": str(root),
        "host_root_mounted": mounted,
        "read_only": True,
        "entries": [],
        "roots": [{"name": "Host /", "path": "/"}],
        "note": _NOTE,
        "error": None,
    }

    if not mounted:
        base["error"] = (
            "Host root is not mounted. Set HOST_ROOT "
            "(Compose: /:/host:ro, HOST_ROOT=/host)."
        )
        return base

    mapped = _map_host_path(host_path)
    if not _is_under_root(mapped, root):
        base["error"] = "Path escapes the host mount."
        return base

    try:
        resolved = mapped.resolve(strict=False)
    except OSError as exc:
        base["error"] = f"Cannot resolve path: {exc}"
        return base

    if not _is_under_root(resolved, root):
        base["error"] = "Path escapes the host mount."
        return base

    if not mapped.exists():
        base["error"] = f"Path not found: {host_path}"
        return base
    if not mapped.is_dir():
        base["error"] = f"Not a directory: {host_path}"
        return base

    entries: list[dict[str, Any]] = []
    try:
        children = sorted(mapped.iterdir(), key=lambda p: p.name.lower())
    except OSError as exc:
        base["error"] = f"Cannot list directory: {exc}"
        return base

    for child in children:
        name = child.name
        if name in (".", "..") or name.startswith("."):
            continue
        child_host = (
            f"{host_path.rstrip('/')}/{name}" if host_path != "/" else f"/{name}"
        )
        try:
            child_res = child.resolve(strict=False)
        except OSError:
            continue
        if not _is_under_root(child_res, root):
            continue

        try:
            if child.is_dir():
                typ = "dir"
            elif child.is_file():
                typ = "file"
            else:
                continue
        except OSError:
            continue

        entries.append(
            {
                "name": name,
                "type": typ,
                "path": child_host,
                "likely": typ == "file" and is_likely_caddy_file(name),
            }
        )

    entries.sort(
        key=lambda e: (
            0 if e["type"] == "dir" else 1,
            0 if e.get("likely") else 1,
            str(e["name"]).lower(),
        )
    )

    base.update(
        {
            "ok": True,
            "entries": entries,
            "roots": _quick_roots(root),
            "error": None,
        }
    )
    return base
