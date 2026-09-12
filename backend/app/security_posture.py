"""Lightweight CIS-inspired container posture checks from Docker inspect."""

from __future__ import annotations

from typing import Any

# Host paths that are especially sensitive when bind-mounted into a container.
_SENSITIVE_HOST_PREFIXES = (
    "/",
    "/etc",
    "/root",
    "/home",
    "/var/run/docker.sock",
    "/run/docker.sock",
    "/proc",
    "/sys",
    "/boot",
    "/usr",
    "/lib",
    "/bin",
    "/sbin",
    "/var/lib/docker",
)

_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _finding(
    fid: str,
    severity: str,
    title: str,
    detail: str,
) -> dict[str, Any]:
    return {
        "id": fid,
        "severity": severity,
        "title": title,
        "detail": detail,
        "source": "posture",
    }


def _bind_sources(inspect: dict[str, Any]) -> list[str]:
    sources: list[str] = []
    host = inspect.get("HostConfig") or {}
    for b in host.get("Binds") or []:
        # host:container[:mode]
        if isinstance(b, str) and ":" in b:
            sources.append(b.split(":", 1)[0])
    for m in host.get("Mounts") or []:
        if not isinstance(m, dict):
            continue
        if (m.get("Type") or "").lower() == "bind" and m.get("Source"):
            sources.append(str(m["Source"]))
    # Also check top-level Mounts from inspect (Docker API)
    for m in inspect.get("Mounts") or []:
        if not isinstance(m, dict):
            continue
        if (m.get("Type") or "").lower() == "bind" and m.get("Source"):
            sources.append(str(m["Source"]))
    # Dedupe preserving order
    seen: set[str] = set()
    out: list[str] = []
    for s in sources:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _is_sensitive_mount(source: str) -> bool:
    s = source.rstrip("/") or "/"
    if s in ("/var/run/docker.sock", "/run/docker.sock"):
        return True
    if s == "/":
        return True
    for prefix in _SENSITIVE_HOST_PREFIXES:
        if prefix in ("/", "/var/run/docker.sock", "/run/docker.sock"):
            continue
        if s == prefix or s.startswith(prefix + "/"):
            return True
    return False


def _is_docker_sock(source: str) -> bool:
    s = source.rstrip("/")
    return s.endswith("docker.sock") or s in (
        "/var/run/docker.sock",
        "/run/docker.sock",
    )


def _running_as_root(user: str | None) -> bool:
    u = (user or "").strip()
    if not u:
        return True
    # "0", "0:0", "root", "root:root"
    name = u.split(":", 1)[0]
    return name in ("0", "root")


def evaluate_posture(container: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Return structured posture findings for one container.
    Expects optional `inspect` dict (Docker attrs) on the container row.
    """
    inspect = container.get("inspect") or {}
    host = inspect.get("HostConfig") or {}
    config = inspect.get("Config") or {}

    findings: list[dict[str, Any]] = []

    if host.get("Privileged"):
        findings.append(
            _finding(
                "privileged",
                "critical",
                "Privileged mode",
                "Container runs with --privileged (near-full host access).",
            )
        )

    binds = _bind_sources(inspect)
    sock_mounts = [b for b in binds if _is_docker_sock(b)]
    if sock_mounts:
        findings.append(
            _finding(
                "docker_sock",
                "critical",
                "Docker socket mounted",
                f"Host Docker socket exposed: {', '.join(sock_mounts)}. "
                "Equivalent to root on the host for most setups.",
            )
        )

    sensitive = [
        b for b in binds if _is_sensitive_mount(b) and not _is_docker_sock(b)
    ]
    if sensitive:
        # Cap list for UI noise
        shown = sensitive[:6]
        extra = len(sensitive) - len(shown)
        detail = ", ".join(shown)
        if extra > 0:
            detail += f" (+{extra} more)"
        findings.append(
            _finding(
                "sensitive_mounts",
                "high",
                "Sensitive host mounts",
                f"Bind mounts to sensitive host paths: {detail}.",
            )
        )

    net = (host.get("NetworkMode") or "").lower()
    if net == "host":
        findings.append(
            _finding(
                "host_network",
                "high",
                "Host network mode",
                "Container shares the host network namespace (network_mode: host).",
            )
        )

    cap_add = [str(c).upper() for c in (host.get("CapAdd") or [])]
    if "ALL" in cap_add:
        findings.append(
            _finding(
                "cap_all",
                "critical",
                "All capabilities added",
                "CapAdd includes ALL — container can escalate many privileges.",
            )
        )
    elif cap_add:
        findings.append(
            _finding(
                "cap_add",
                "medium",
                "Extra capabilities",
                f"Added capabilities: {', '.join(cap_add)}.",
            )
        )

    user = config.get("User")
    if _running_as_root(user if isinstance(user, str) else None):
        findings.append(
            _finding(
                "runs_as_root",
                "low",
                "Running as root",
                "User is empty or root (UID 0). Common in images; prefer a non-root user when practical.",
            )
        )

    return findings


def max_severity(findings: list[dict[str, Any]]) -> str | None:
    if not findings:
        return None
    best = max(findings, key=lambda f: _SEVERITY_RANK.get(str(f.get("severity", "")).lower(), -1))
    return str(best.get("severity") or "").lower() or None


def severity_at_least(sev: str, threshold: str) -> bool:
    return _SEVERITY_RANK.get(sev.lower(), -1) >= _SEVERITY_RANK.get(threshold.lower(), 99)
