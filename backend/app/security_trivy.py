"""Trivy image SCA — fail-soft when binary missing or scan fails."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Any

from app import db
from app.config import SecurityConfig, TrivyConfig

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def trivy_available() -> bool:
    return shutil.which("trivy") is not None


def _cache_fresh(scanned_at: str, hours: float) -> bool:
    try:
        dt = datetime.fromisoformat(scanned_at)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - dt).total_seconds()
        return age < hours * 3600
    except Exception:
        return False


def _empty_counts() -> dict[str, int]:
    return {k: 0 for k in _SEVERITY_ORDER}


def _parse_trivy_json(
    payload: dict[str, Any], top_n: int
) -> tuple[dict[str, int], list[dict[str, Any]]]:
    counts = _empty_counts()
    findings: list[dict[str, Any]] = []

    for result in payload.get("Results") or []:
        if not isinstance(result, dict):
            continue
        target = result.get("Target") or ""
        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            sev = str(vuln.get("Severity") or "UNKNOWN").upper()
            if sev not in counts:
                sev = "UNKNOWN"
            counts[sev] = counts.get(sev, 0) + 1
            findings.append(
                {
                    "id": vuln.get("VulnerabilityID") or vuln.get("PkgID") or "?",
                    "severity": sev,
                    "pkg": vuln.get("PkgName") or "",
                    "installed": vuln.get("InstalledVersion") or "",
                    "fixed": vuln.get("FixedVersion") or "",
                    "title": (vuln.get("Title") or vuln.get("Description") or "")[:160],
                    "target": target,
                    "source": "trivy",
                }
            )

    rank = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    findings.sort(key=lambda f: rank.get(str(f.get("severity")), 99))
    return counts, findings[: max(1, top_n)]


def _image_cache_key(container: dict[str, Any]) -> str:
    digest = (container.get("local_digest") or "").strip()
    if digest:
        return digest
    image_id = (container.get("image_id") or "").strip()
    if image_id:
        return image_id
    return (container.get("image") or "").strip() or "unknown"


def scan_image(
    image_ref: str,
    image_key: str,
    trivy_cfg: TrivyConfig,
) -> dict[str, Any]:
    """
    Run Trivy against a local image name/id. Returns a cacheable result dict.
    Never raises.
    """
    if not trivy_available():
        result = {
            "image_key": image_key,
            "image_ref": image_ref,
            "status": "unavailable",
            "error": (
                "Trivy not installed. The Compose Docker image includes Trivy; "
                "a local venv does not unless you install it yourself."
            ),
            "severity": _empty_counts(),
            "top_findings": [],
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }
        db.set_image_scan(result)
        return result

    cmd = [
        "trivy",
        "image",
        "--format",
        "json",
        "--quiet",
        "--severity",
        trivy_cfg.severity,
        "--timeout",
        f"{int(trivy_cfg.timeout_seconds)}s",
        "--cache-dir",
        trivy_cfg.cache_dir,
    ]
    if trivy_cfg.ignore_unfixed:
        cmd.append("--ignore-unfixed")
    cmd.append(image_ref)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(30.0, trivy_cfg.timeout_seconds + 30.0),
            check=False,
        )
        # Trivy exits 0 even with vulns when not using --exit-code
        if proc.returncode != 0 and not (proc.stdout or "").strip():
            err = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
            result = {
                "image_key": image_key,
                "image_ref": image_ref,
                "status": "error",
                "error": err[:500],
                "severity": _empty_counts(),
                "top_findings": [],
                "scanned_at": datetime.now(timezone.utc).isoformat(),
            }
            db.set_image_scan(result)
            return result

        payload = json.loads(proc.stdout or "{}")
        counts, top = _parse_trivy_json(
            payload if isinstance(payload, dict) else {},
            trivy_cfg.top_findings,
        )
        result = {
            "image_key": image_key,
            "image_ref": image_ref,
            "status": "ok",
            "error": None,
            "severity": counts,
            "top_findings": top,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }
        db.set_image_scan(result)
        return result
    except subprocess.TimeoutExpired:
        result = {
            "image_key": image_key,
            "image_ref": image_ref,
            "status": "error",
            "error": "trivy scan timed out",
            "severity": _empty_counts(),
            "top_findings": [],
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }
        db.set_image_scan(result)
        return result
    except Exception as exc:
        logger.warning("Trivy scan failed for %s: %s", image_ref, exc)
        result = {
            "image_key": image_key,
            "image_ref": image_ref,
            "status": "error",
            "error": str(exc)[:500],
            "severity": _empty_counts(),
            "top_findings": [],
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }
        db.set_image_scan(result)
        return result


def get_or_scan_image(
    container: dict[str, Any],
    trivy_cfg: TrivyConfig,
    *,
    allow_scan: bool,
) -> dict[str, Any]:
    """Return cached scan or run a new one when allow_scan and cache stale."""
    image_key = _image_cache_key(container)
    image_ref = (
        (container.get("image_id") or "").strip()
        or (container.get("image") or "").strip()
    )
    cached = db.get_image_scan(image_key)
    if cached and _cache_fresh(cached.get("scanned_at") or "", trivy_cfg.scan_interval_hours):
        return {
            "image_key": image_key,
            "image_ref": cached.get("image_ref") or image_ref,
            "status": cached.get("status") or "ok",
            "error": cached.get("error"),
            "severity": cached.get("severity") or _empty_counts(),
            "top_findings": cached.get("top_findings") or [],
            "scanned_at": cached.get("scanned_at"),
            "from_cache": True,
        }

    if not allow_scan:
        if cached:
            return {
                "image_key": image_key,
                "image_ref": cached.get("image_ref") or image_ref,
                "status": cached.get("status") or "ok",
                "error": cached.get("error"),
                "severity": cached.get("severity") or _empty_counts(),
                "top_findings": cached.get("top_findings") or [],
                "scanned_at": cached.get("scanned_at"),
                "from_cache": True,
                "stale": True,
            }
        return {
            "image_key": image_key,
            "image_ref": image_ref,
            "status": "pending",
            "error": None,
            "severity": _empty_counts(),
            "top_findings": [],
            "scanned_at": None,
            "from_cache": False,
        }

    if not image_ref:
        return {
            "image_key": image_key,
            "image_ref": "",
            "status": "unavailable",
            "error": "no image reference",
            "severity": _empty_counts(),
            "top_findings": [],
            "scanned_at": datetime.now(timezone.utc).isoformat(),
        }

    result = scan_image(image_ref, image_key, trivy_cfg)
    result["from_cache"] = False
    return result


def notable_vuln_count(severity: dict[str, int], threshold: str) -> int:
    threshold = (threshold or "HIGH").upper()
    order = list(_SEVERITY_ORDER)
    try:
        idx = order.index(threshold)
    except ValueError:
        idx = order.index("HIGH")
    return sum(int(severity.get(s) or 0) for s in order[: idx + 1] if s != "UNKNOWN")


def enrich_scans_for_containers(
    containers: list[dict[str, Any]],
    security: SecurityConfig,
) -> None:
    """
    Attach image scan summaries onto containers.
    Scans at most max_scans_per_poll stale images per call.
    """
    if not security.enabled or not security.trivy.enabled:
        for c in containers:
            c["image_scan"] = {
                "status": "disabled",
                "severity": _empty_counts(),
                "top_findings": [],
            }
        return

    trivy_cfg = security.trivy
    # Unique keys in poll order
    pending_keys: list[str] = []
    seen: set[str] = set()
    for c in containers:
        key = _image_cache_key(c)
        if key in seen:
            continue
        seen.add(key)
        cached = db.get_image_scan(key)
        if not cached or not _cache_fresh(
            cached.get("scanned_at") or "", trivy_cfg.scan_interval_hours
        ):
            pending_keys.append(key)

    scan_budget = max(0, int(trivy_cfg.max_scans_per_poll))
    keys_to_scan = set(pending_keys[:scan_budget])

    # Cache results per image_key within this poll
    by_key: dict[str, dict[str, Any]] = {}
    for c in containers:
        key = _image_cache_key(c)
        if key not in by_key:
            by_key[key] = get_or_scan_image(
                c, trivy_cfg, allow_scan=key in keys_to_scan
            )
        c["image_scan"] = by_key[key]
