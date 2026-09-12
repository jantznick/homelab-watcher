"""Orchestrate posture + Trivy + OpenSCA into a per-container security summary."""

from __future__ import annotations

from typing import Any

from app.config import SecurityConfig
from app.security_opensca import (
    enrich_scm_scans_for_containers,
    opensca_available,
)
from app.security_posture import (
    evaluate_posture,
    max_severity,
    severity_at_least,
)
from app.security_trivy import enrich_scans_for_containers, notable_vuln_count, trivy_available


def _empty_severity() -> dict[str, int]:
    return {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }


def _merge_severity(a: dict[str, int], b: dict[str, int]) -> dict[str, int]:
    out = _empty_severity()
    for k in out:
        out[k] = int(a.get(k) or 0) + int(b.get(k) or 0)
    return out


def _disabled_summary() -> dict[str, Any]:
    return {
        "enabled": False,
        "trivy_enabled": False,
        "opensca_enabled": False,
        "scan_status": "disabled",
        "severity": _empty_severity(),
        "top_findings": [],
        "posture": [],
        "issue_count": 0,
        "max_severity": None,
        "notable": False,
        "scanned_at": None,
        "trivy_available": trivy_available(),
        "opensca_available": opensca_available(),
        "image_scan_status": None,
        "scm": None,
    }


def build_security_summary(
    container: dict[str, Any],
    security: SecurityConfig,
) -> dict[str, Any]:
    if not security.enabled:
        return _disabled_summary()

    trivy_on = bool(security.trivy.enabled)
    opensca_on = bool(security.opensca.enabled)

    posture: list[dict[str, Any]] = []
    if security.posture.enabled:
        posture = evaluate_posture(container)

    scan = container.get("image_scan") or {} if trivy_on else {}
    scm = container.get("scm_scan") or {} if opensca_on else {}
    scan_status = (scan.get("status") or "pending") if trivy_on else "disabled"
    scm_status = (scm.get("status") or "skipped") if opensca_on else "disabled"

    img_sev = (scan.get("severity") or _empty_severity()) if trivy_on else _empty_severity()
    scm_sev = (scm.get("severity") or _empty_severity()) if opensca_on else _empty_severity()
    # Combined counts for chips; only scanners that are enabled
    severity = _merge_severity(img_sev, scm_sev)

    top = list(scan.get("top_findings") or []) if trivy_on else []
    scm_top = list(scm.get("top_findings") or []) if opensca_on else []
    combined_top = (top + scm_top)[:8]

    img_notable = notable_vuln_count(img_sev, security.notable_severity) if trivy_on else 0
    scm_notable = notable_vuln_count(scm_sev, security.notable_severity) if opensca_on else 0
    vuln_notable = img_notable + scm_notable
    posture_notable = [
        f
        for f in posture
        if severity_at_least(
            str(f.get("severity") or ""),
            security.notable_posture_severity,
        )
    ]

    posture_issues = [
        f
        for f in posture
        if severity_at_least(str(f.get("severity") or ""), "medium")
        or f.get("id") == "runs_as_root"
    ]
    issue_count = vuln_notable + len(
        [f for f in posture if severity_at_least(str(f.get("severity") or ""), "low")]
    )

    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    max_posture = max_severity(posture)
    max_vuln = None
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if int(severity.get(s) or 0) > 0:
            max_vuln = s.lower()
            break

    candidates = [x for x in (max_posture, max_vuln) if x]
    max_sev = None
    if candidates:
        max_sev = max(candidates, key=lambda s: sev_rank.get(s, -1))

    # Overall status from enabled scanners only
    statuses = []
    if trivy_on:
        statuses.append(scan_status)
    if opensca_on and scm_status != "skipped":
        statuses.append(scm_status)
    overall_status = "ok"
    for preferred in ("unavailable", "error", "pending", "ok", "disabled"):
        if preferred in statuses:
            overall_status = preferred
            break
    if not statuses:
        overall_status = "ok"

    scan_error = None
    if trivy_on:
        scan_error = scan.get("error")
    if not scan_error and opensca_on and scm_status in ("error", "unavailable"):
        scan_error = scm.get("error")

    scanned_at = None
    if trivy_on:
        scanned_at = scan.get("scanned_at")
    if not scanned_at and opensca_on:
        scanned_at = scm.get("scanned_at")

    scm_summary = None
    if opensca_on:
        scm_summary = {
            "status": scm_status,
            "error": scm.get("error"),
            "repo_url": scm.get("repo_url"),
            "commit_sha": scm.get("commit_sha"),
            "scm_source": scm.get("scm_source"),
            "severity": scm_sev,
            "top_findings": scm_top,
            "scanned_at": scm.get("scanned_at"),
            "notable_count": scm_notable,
        }

    return {
        "enabled": True,
        "trivy_enabled": trivy_on,
        "opensca_enabled": opensca_on,
        "scan_status": overall_status,
        "scan_error": scan_error,
        "severity": severity,
        "top_findings": combined_top,
        "posture": posture,
        "issue_count": issue_count,
        "vuln_notable_count": vuln_notable,
        "image_vuln_notable_count": img_notable,
        "scm_vuln_notable_count": scm_notable,
        "posture_issue_count": len(posture_issues),
        "max_severity": max_sev,
        "notable": bool(vuln_notable or posture_notable),
        "scanned_at": scanned_at,
        "trivy_available": trivy_available(),
        "opensca_available": opensca_available(),
        "image_key": scan.get("image_key") if trivy_on else None,
        "image_scan_status": scan_status if trivy_on else None,
        "image_severity": img_sev if trivy_on else None,
        "scm": scm_summary,
    }


def enrich_security(
    containers: list[dict[str, Any]],
    security: SecurityConfig,
) -> None:
    """Mutate containers with security summaries. Fail-soft; never raises."""
    try:
        if not security.enabled:
            for c in containers:
                c["security"] = _disabled_summary()
            return

        enrich_scans_for_containers(containers, security)
        enrich_scm_scans_for_containers(containers, security)
        for c in containers:
            c["security"] = build_security_summary(c, security)
    except Exception:
        for c in containers:
            c.setdefault(
                "security",
                {
                    **_disabled_summary(),
                    "enabled": security.enabled,
                    "scan_status": "unavailable",
                    "scan_error": "security enrichment failed",
                },
            )
