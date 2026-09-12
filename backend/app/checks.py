"""HTTP, ping, and DNS probes for custom check targets."""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from typing import Any

import dns.resolver
import httpx

from app.config import AppYamlConfig, TargetConfig

logger = logging.getLogger(__name__)


def _ok_http_status(status: int, expect: int | None) -> bool:
    if expect is not None:
        return status == expect
    # SSO-protected apps often 302 to login — treat 2xx/3xx as up
    return 200 <= status < 400


def check_http(target: TargetConfig) -> dict[str, Any]:
    url = target.url or ""
    started = time.perf_counter()
    try:
        with httpx.Client(
            timeout=target.timeout_seconds,
            follow_redirects=False,
            verify=target.verify_tls,
        ) as client:
            r = client.get(url)
        latency = (time.perf_counter() - started) * 1000
        ok = _ok_http_status(r.status_code, target.expect_status)
        return {
            "name": target.name,
            "check_type": "http",
            "ok": ok,
            "latency_ms": round(latency, 1),
            "message": f"HTTP {r.status_code}",
            "detail": {
                "url": url,
                "status_code": r.status_code,
                "location": r.headers.get("location"),
            },
        }
    except Exception as exc:
        latency = (time.perf_counter() - started) * 1000
        return {
            "name": target.name,
            "check_type": "http",
            "ok": False,
            "latency_ms": round(latency, 1),
            "message": str(exc),
            "detail": {"url": url},
        }


def check_ping(target: TargetConfig) -> dict[str, Any]:
    host = target.host or ""
    ping_bin = shutil.which("ping")
    started = time.perf_counter()
    if not ping_bin:
        return {
            "name": target.name,
            "check_type": "ping",
            "ok": False,
            "latency_ms": None,
            "message": "ping binary not available",
            "detail": {"host": host},
        }
    try:
        # -c 1 one packet, -W timeout seconds (Linux); on macOS -W is ms
        timeout = max(1, int(target.timeout_seconds))
        proc = subprocess.run(
            [ping_bin, "-c", "1", "-W", str(timeout), host],
            capture_output=True,
            text=True,
            timeout=timeout + 2,
        )
        latency = (time.perf_counter() - started) * 1000
        ok = proc.returncode == 0
        return {
            "name": target.name,
            "check_type": "ping",
            "ok": ok,
            "latency_ms": round(latency, 1),
            "message": "reachable" if ok else (proc.stderr.strip() or "unreachable"),
            "detail": {"host": host},
        }
    except Exception as exc:
        latency = (time.perf_counter() - started) * 1000
        return {
            "name": target.name,
            "check_type": "ping",
            "ok": False,
            "latency_ms": round(latency, 1),
            "message": str(exc),
            "detail": {"host": host},
        }


def check_dns(target: TargetConfig) -> dict[str, Any]:
    """Ping the nameserver host AND run a DNS query against it."""
    host = target.host or ""
    query = target.query or "example.com"
    started = time.perf_counter()

    ping_result = check_ping(
        TargetConfig(
            name=target.name,
            type="ping",
            host=host,
            timeout_seconds=target.timeout_seconds,
        )
    )

    dns_ok = False
    dns_msg = ""
    answers: list[str] = []
    try:
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [host]
        resolver.lifetime = target.timeout_seconds
        answer = resolver.resolve(query, "A")
        answers = [rr.to_text() for rr in answer]
        dns_ok = len(answers) > 0
        dns_msg = f"resolved {query} → {', '.join(answers[:3])}"
    except Exception as exc:
        dns_msg = f"DNS query failed: {exc}"

    latency = (time.perf_counter() - started) * 1000
    ok = bool(ping_result.get("ok")) and dns_ok
    parts = []
    parts.append("ping ok" if ping_result.get("ok") else f"ping fail ({ping_result.get('message')})")
    parts.append(dns_msg)
    return {
        "name": target.name,
        "check_type": "dns",
        "ok": ok,
        "latency_ms": round(latency, 1),
        "message": "; ".join(parts),
        "detail": {
            "host": host,
            "query": query,
            "answers": answers,
            "ping_ok": ping_result.get("ok"),
        },
    }


def run_all_checks(yaml_cfg: AppYamlConfig) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for t in yaml_cfg.targets:
        try:
            if t.type == "http":
                results.append(check_http(t))
            elif t.type == "ping":
                results.append(check_ping(t))
            elif t.type == "dns":
                results.append(check_dns(t))
            else:
                results.append(
                    {
                        "name": t.name,
                        "check_type": t.type,
                        "ok": False,
                        "latency_ms": None,
                        "message": f"unknown check type: {t.type}",
                        "detail": {},
                    }
                )
        except Exception as exc:
            logger.exception("Check failed for %s", t.name)
            results.append(
                {
                    "name": t.name,
                    "check_type": t.type,
                    "ok": False,
                    "latency_ms": None,
                    "message": str(exc),
                    "detail": {},
                }
            )
    return results
