"""Registry digest comparison with SQLite caching.

Also classifies update jumps (major / minor / patch) by comparing the
running image tag to the newest semver-ish tag on the registry when an
update is available. Failures parse soft — inventory never breaks.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import httpx

from app import db
from app.config import AppYamlConfig

logger = logging.getLogger(__name__)

# image:tag or registry/repo:tag or digest refs
_DIGEST_RE = re.compile(r"sha256:[a-f0-9]{64}", re.I)

# v1.2.3, 1.2.3, 1.2, optional -suffix / +build (docker variant tags)
_SEMVER_TAG_RE = re.compile(
    r"^v?(?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<patch>\d+))?(?P<suffix>[-+][0-9A-Za-z.-]*)?$",
)

BumpKind = str | None  # "major" | "minor" | "patch" | "unknown" | None


def _parse_image_ref(image: str) -> dict[str, str] | None:
    """Split image reference into registry, repository, tag."""
    if not image or image.startswith("sha256:"):
        return None
    # Strip digest suffix if present
    if "@" in image:
        image = image.split("@", 1)[0]

    tag = "latest"
    if ":" in image.rsplit("/", 1)[-1]:
        name, tag = image.rsplit(":", 1)
    else:
        name = image

    parts = name.split("/")
    if len(parts) == 1 or (
        len(parts) == 2 and "." not in parts[0] and ":" not in parts[0]
    ):
        # Docker Hub official or user image
        registry = "registry-1.docker.io"
        if len(parts) == 1:
            repository = f"library/{parts[0]}"
        else:
            repository = name
    else:
        registry = parts[0]
        repository = "/".join(parts[1:])

    return {"registry": registry, "repository": repository, "tag": tag}


def _auth_for_dockerhub(repository: str, tag: str) -> str | None:
    token_url = (
        "https://auth.docker.io/token"
        f"?service=registry.docker.io&scope=repository:{repository}:pull"
    )
    try:
        with httpx.Client(timeout=15.0) as client:
            r = client.get(token_url)
            r.raise_for_status()
            return r.json().get("token")
    except Exception as exc:
        logger.debug("Docker Hub token failed for %s: %s", repository, exc)
        return None


def _fetch_remote_digest(image: str) -> tuple[str | None, str | None]:
    """Return (digest, error)."""
    parsed = _parse_image_ref(image)
    if not parsed:
        return None, "unparsed image ref"

    registry = parsed["registry"]
    repository = parsed["repository"]
    tag = parsed["tag"]

    headers: dict[str, str] = {
        "Accept": (
            "application/vnd.docker.distribution.manifest.v2+json,"
            "application/vnd.oci.image.manifest.v1+json,"
            "application/vnd.oci.image.index.v1+json,"
            "application/vnd.docker.distribution.manifest.list.v2+json"
        )
    }

    if registry in ("registry-1.docker.io", "docker.io"):
        token = _auth_for_dockerhub(repository, tag)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        registry = "registry-1.docker.io"

    # GHCR often needs anonymous accept; private registries may fail — cache error
    url = f"https://{registry}/v2/{repository}/manifests/{quote(tag, safe='')}"

    try:
        with httpx.Client(timeout=20.0, follow_redirects=True) as client:
            r = client.get(url, headers=headers)
            if r.status_code == 401 and "www-authenticate" in r.headers:
                # Try Bearer challenge for GHCR / others
                auth_header = r.headers["www-authenticate"]
                token = _token_from_challenge(auth_header, repository)
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                    r = client.get(url, headers=headers)
            if r.status_code >= 400:
                return None, f"HTTP {r.status_code}"
            digest = r.headers.get("Docker-Content-Digest")
            if digest:
                return digest, None
            # Fallback: hash not available
            body = r.text
            m = _DIGEST_RE.search(body)
            if m:
                return m.group(0), None
            return None, "no digest in response"
    except Exception as exc:
        return None, str(exc)


def _token_from_challenge(www_auth: str, repository: str) -> str | None:
    # Bearer realm="...",service="...",scope="..."
    realm = re.search(r'realm="([^"]+)"', www_auth)
    service = re.search(r'service="([^"]+)"', www_auth)
    if not realm:
        return None
    params: dict[str, str] = {"scope": f"repository:{repository}:pull"}
    if service:
        params["service"] = service.group(1)
    try:
        with httpx.Client(timeout=15.0) as client:
            r = client.get(realm.group(1), params=params)
            r.raise_for_status()
            data = r.json()
            return data.get("token") or data.get("access_token")
    except Exception:
        return None


def _cache_fresh(checked_at: str, hours: float) -> bool:
    try:
        dt = datetime.fromisoformat(checked_at)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - dt).total_seconds()
        return age < hours * 3600
    except Exception:
        return False


def parse_semver_tag(tag: str) -> tuple[tuple[int, int, int], str] | None:
    """Parse a docker tag into ((major, minor, patch), suffix) or None.

    Accepts ``1.2.3``, ``v1.2.3``, ``1.2`` (patch=0), and optional
    ``-alpine`` / ``+build`` style suffixes. Non-version tags (``latest``,
    ``stable``, digests) return None.
    """
    if not tag or tag.startswith("sha256:"):
        return None
    m = _SEMVER_TAG_RE.match(tag.strip())
    if not m:
        return None
    try:
        major = int(m.group("major"))
        minor = int(m.group("minor"))
        patch = int(m.group("patch") or 0)
    except (TypeError, ValueError):
        return None
    suffix = (m.group("suffix") or "").lower()
    return (major, minor, patch), suffix


def classify_version_bump(
    current: tuple[int, int, int], newest: tuple[int, int, int]
) -> BumpKind:
    """Return major/minor/patch when newest > current; else None."""
    if newest <= current:
        return None
    if newest[0] != current[0]:
        return "major"
    if newest[1] != current[1]:
        return "minor"
    if newest[2] != current[2]:
        return "patch"
    return None


def _tags_cache_key(registry: str, repository: str) -> str:
    return f"tags://{registry}/{repository}"


def _auth_headers_for(
    registry: str, repository: str, tag: str = "latest"
) -> tuple[str, dict[str, str]]:
    """Return (normalized_registry, headers) for registry API calls."""
    headers: dict[str, str] = {
        "Accept": (
            "application/vnd.docker.distribution.manifest.v2+json,"
            "application/vnd.oci.image.manifest.v1+json,"
            "application/vnd.oci.image.index.v1+json,"
            "application/vnd.docker.distribution.manifest.list.v2+json"
        )
    }
    if registry in ("registry-1.docker.io", "docker.io"):
        token = _auth_for_dockerhub(repository, tag)
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return "registry-1.docker.io", headers
    return registry, headers


def _fetch_remote_tags(image: str) -> tuple[list[str], str | None]:
    """List tags for the image's repository. Returns (tags, error)."""
    parsed = _parse_image_ref(image)
    if not parsed:
        return [], "unparsed image ref"

    registry, headers = _auth_headers_for(parsed["registry"], parsed["repository"])
    repository = parsed["repository"]
    url = f"https://{registry}/v2/{repository}/tags/list?n=500"

    try:
        with httpx.Client(timeout=20.0, follow_redirects=True) as client:
            r = client.get(url, headers=headers)
            if r.status_code == 401 and "www-authenticate" in r.headers:
                token = _token_from_challenge(
                    r.headers["www-authenticate"], repository
                )
                if token:
                    headers["Authorization"] = f"Bearer {token}"
                    r = client.get(url, headers=headers)
            if r.status_code >= 400:
                return [], f"HTTP {r.status_code}"
            data = r.json()
            tags = data.get("tags") or []
            if not isinstance(tags, list):
                return [], "bad tags payload"
            return [str(t) for t in tags if t is not None], None
    except Exception as exc:
        return [], str(exc)


def _newest_semver_tag(
    tags: list[str], current_tag: str
) -> tuple[str | None, tuple[int, int, int] | None]:
    """Pick the highest semver tag, preferring the same suffix channel."""
    current_parsed = parse_semver_tag(current_tag)
    prefer_suffix = current_parsed[1] if current_parsed else None

    best_same: tuple[tuple[int, int, int], str] | None = None
    best_any: tuple[tuple[int, int, int], str] | None = None

    for tag in tags:
        parsed = parse_semver_tag(tag)
        if not parsed:
            continue
        ver, suffix = parsed
        if prefer_suffix is not None and suffix == prefer_suffix:
            if best_same is None or ver > best_same[0]:
                best_same = (ver, tag)
        if best_any is None or ver > best_any[0]:
            best_any = (ver, tag)

    chosen = best_same or best_any
    if not chosen:
        return None, None
    return chosen[1], chosen[0]


def _classify_update_jump(
    image: str, cache_hours: float
) -> tuple[BumpKind, str | None, str | None]:
    """Return (update_bump, update_from, update_to) for a versioned image.

    Soft-fails to (\"unknown\", current_tag, None) when tags cannot be listed
    or are not comparable semver.
    """
    parsed = _parse_image_ref(image)
    if not parsed:
        return "unknown", None, None

    current_tag = parsed["tag"]
    current_parsed = parse_semver_tag(current_tag)
    if not current_parsed:
        return "unknown", current_tag, None

    current_ver, _ = current_parsed
    registry, _headers = _auth_headers_for(parsed["registry"], parsed["repository"])
    cache_key = _tags_cache_key(registry, parsed["repository"])

    tags: list[str] = []
    cached = db.get_registry_cache(cache_key)
    if cached and _cache_fresh(cached["checked_at"], cache_hours):
        # Newest tag stored in remote_digest; full list not required when fresh
        cached_newest = cached.get("remote_digest")
        if cached_newest:
            tags = [cached_newest, current_tag]
        err = cached.get("error")
        if err and not cached_newest:
            return "unknown", current_tag, None
    else:
        tags, err = _fetch_remote_tags(image)
        newest_preview, _ = _newest_semver_tag(tags, current_tag)
        db.set_registry_cache(cache_key, newest_preview, err)
        if err and not tags:
            return "unknown", current_tag, None

    newest_tag, newest_ver = _newest_semver_tag(tags, current_tag)
    if not newest_tag or newest_ver is None:
        return "unknown", current_tag, None

    bump = classify_version_bump(current_ver, newest_ver)
    if bump is None:
        # Same (or older) semver — digest-only rebuild of this pin
        return None, current_tag, newest_tag
    return bump, current_tag, newest_tag


def enrich_with_updates(
    containers: list[dict[str, Any]], yaml_cfg: AppYamlConfig
) -> list[dict[str, Any]]:
    """Add update_available / remote_digest / update_bump using registry lookups."""
    cache_hours = yaml_cfg.registry_cache_hours
    for c in containers:
        image = c.get("image") or ""
        local = c.get("local_digest")
        # Defaults — fail soft
        c.setdefault("update_bump", None)
        c.setdefault("update_from", None)
        c.setdefault("update_to", None)

        if not image or image.startswith("sha256:"):
            continue

        try:
            cached = db.get_registry_cache(image)
            remote: str | None = None
            err: str | None = None

            if cached and _cache_fresh(cached["checked_at"], cache_hours):
                remote = cached.get("remote_digest")
                err = cached.get("error")
            else:
                remote, err = _fetch_remote_digest(image)
                db.set_registry_cache(image, remote, err)

            c["remote_digest"] = remote
            c["registry_error"] = err
            if local and remote and local != remote:
                c["update_available"] = True
            else:
                c["update_available"] = False

            if c.get("update_available"):
                try:
                    bump, frm, to = _classify_update_jump(image, cache_hours)
                    c["update_from"] = frm
                    c["update_to"] = to
                    if bump:
                        c["update_bump"] = bump
                    elif frm and to and parse_semver_tag(frm) and parse_semver_tag(to):
                        # Comparable semver but no upward jump (digest-only)
                        c["update_bump"] = None
                    else:
                        c["update_bump"] = "unknown"
                except Exception as exc:
                    logger.debug("update bump classify failed for %s: %s", image, exc)
                    c["update_bump"] = "unknown"
            else:
                c["update_bump"] = None
                c["update_from"] = None
                c["update_to"] = None
        except Exception as exc:
            logger.debug("update enrich failed for %s: %s", image, exc)
            c["update_available"] = bool(c.get("update_available"))
    return containers
