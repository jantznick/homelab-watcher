"""Read-only Pi-hole local DNS fetch (v5 API token and v6 session/password)."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlparse

import httpx

from app.config import PiHoleConfig, Settings, get_settings

logger = logging.getLogger(__name__)

Version = Literal["auto", "5", "6"]


@dataclass
class DnsRecord:
    hostname: str
    target: str  # IP or CNAME target
    kind: str = "a"  # a | cname


@dataclass
class PiHoleResult:
    configured: bool
    ok: bool
    version: str | None = None
    message: str | None = None
    records: list[DnsRecord] = field(default_factory=list)

    @property
    def hostnames(self) -> list[str]:
        return sorted({r.hostname for r in self.records})


def _normalize_host(name: str) -> str:
    return name.strip().lower().rstrip(".")


def _base_urls(raw_url: str) -> list[str]:
    """Candidate bases for v5 (/admin) and v6 (host root)."""
    u = raw_url.strip().rstrip("/")
    if not u:
        return []
    parsed = urlparse(u if "://" in u else f"http://{u}")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    path = (parsed.path or "").rstrip("/")
    bases = [u]
    if path.endswith("/admin"):
        bases.append(origin)
    else:
        bases.append(f"{origin}/admin")
        if path and path != "/admin":
            bases.append(origin)
    # de-dupe preserve order
    seen: set[str] = set()
    out: list[str] = []
    for b in bases:
        b = b.rstrip("/")
        if b not in seen:
            seen.add(b)
            out.append(b)
    return out


def _parse_hosts_lines(lines: list[Any]) -> list[DnsRecord]:
    """Parse 'IP hostname' or 'IP hostname #comment' style entries."""
    records: list[DnsRecord] = []
    for line in lines:
        if not isinstance(line, str):
            continue
        text = line.split("#", 1)[0].strip()
        if not text:
            continue
        parts = text.split()
        if len(parts) < 2:
            continue
        ip, *hosts = parts
        for h in hosts:
            hn = _normalize_host(h)
            if hn:
                records.append(DnsRecord(hostname=hn, target=ip, kind="a"))
    return records


def _parse_cname_entries(entries: list[Any]) -> list[DnsRecord]:
    records: list[DnsRecord] = []
    for item in entries:
        if isinstance(item, str):
            # "alias,target" or "alias target"
            text = item.split("#", 1)[0].strip()
            parts = re.split(r"[\s,]+", text)
            if len(parts) >= 2:
                records.append(
                    DnsRecord(
                        hostname=_normalize_host(parts[0]),
                        target=_normalize_host(parts[1]),
                        kind="cname",
                    )
                )
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            records.append(
                DnsRecord(
                    hostname=_normalize_host(str(item[0])),
                    target=_normalize_host(str(item[1])),
                    kind="cname",
                )
            )
    return records


def _fetch_v5(
    client: httpx.Client, base: str, token: str
) -> tuple[list[DnsRecord], str | None]:
    """Pi-hole v5: /admin/api.php?customdns&auth=… and customcname."""
    admin = base if base.rstrip("/").endswith("/admin") else f"{base.rstrip('/')}/admin"
    records: list[DnsRecord] = []
    err: str | None = None

    for list_name, kind in (("customdns", "a"), ("customcname", "cname")):
        url = f"{admin}/api.php"
        try:
            r = client.get(url, params={list_name: "", "auth": token})
            if r.status_code == 401:
                return [], "Pi-hole v5 auth failed (check PIHOLE_API_TOKEN)"
            if r.status_code >= 400:
                err = f"Pi-hole v5 {list_name}: HTTP {r.status_code}"
                continue
            data = r.json()
            rows = data.get("data") if isinstance(data, dict) else data
            if not isinstance(rows, list):
                continue
            for row in rows:
                if isinstance(row, (list, tuple)) and len(row) >= 2:
                    records.append(
                        DnsRecord(
                            hostname=_normalize_host(str(row[0])),
                            target=str(row[1]).strip(),
                            kind=kind,
                        )
                    )
                elif isinstance(row, str):
                    records.extend(
                        _parse_hosts_lines([row])
                        if kind == "a"
                        else _parse_cname_entries([row])
                    )
        except Exception as exc:
            err = f"Pi-hole v5 {list_name}: {exc}"
            logger.debug("Pi-hole v5 fetch failed: %s", exc)

    if records:
        return records, None
    return [], err or "No custom DNS records from Pi-hole v5"


def _auth_v6(client: httpx.Client, origin: str, password: str) -> tuple[str | None, str | None, str | None]:
    """Return (sid, csrf, error)."""
    try:
        r = client.post(f"{origin}/api/auth", json={"password": password})
        if r.status_code >= 400:
            return None, None, f"Pi-hole v6 auth HTTP {r.status_code}"
        body = r.json()
        session = body.get("session") if isinstance(body, dict) else None
        if not isinstance(session, dict):
            return None, None, "Pi-hole v6 auth: unexpected response"
        if session.get("valid") is False:
            return None, None, "Pi-hole v6 auth failed (check PIHOLE_PASSWORD)"
        sid = session.get("sid")
        csrf = session.get("csrf")
        if not sid:
            # Passwordless / already valid
            if session.get("valid"):
                return "", csrf, None
            return None, None, "Pi-hole v6 auth: no session id"
        return str(sid), str(csrf) if csrf else None, None
    except Exception as exc:
        return None, None, f"Pi-hole v6 auth: {exc}"


def _fetch_v6(
    client: httpx.Client, origin: str, password: str
) -> tuple[list[DnsRecord], str | None]:
    sid, csrf, err = _auth_v6(client, origin, password)
    if err:
        return [], err

    headers: dict[str, str] = {}
    if sid:
        headers["X-FTL-SID"] = sid
        headers["sid"] = sid
    if csrf:
        headers["X-FTL-CSRF"] = csrf

    records: list[DnsRecord] = []
    try:
        r = client.get(f"{origin}/api/config/dns/hosts", headers=headers, params={"sid": sid or ""})
        if r.status_code >= 400:
            return [], f"Pi-hole v6 hosts: HTTP {r.status_code}"
        body = r.json()
        # Shape: {"config": {"dns": {"hosts": ["1.2.3.4 name", ...]}}}
        hosts: list[Any] = []
        if isinstance(body, dict):
            cfg = body.get("config") or body
            dns = cfg.get("dns") if isinstance(cfg, dict) else None
            if isinstance(dns, dict):
                hosts = dns.get("hosts") or []
            elif "hosts" in body:
                hosts = body.get("hosts") or []
        if isinstance(hosts, list):
            records.extend(_parse_hosts_lines(hosts))

        # CNAMEs
        r2 = client.get(
            f"{origin}/api/config/dns/cnameRecords",
            headers=headers,
            params={"sid": sid or ""},
        )
        if r2.status_code < 400:
            body2 = r2.json()
            cnames: list[Any] = []
            if isinstance(body2, dict):
                cfg = body2.get("config") or body2
                dns = cfg.get("dns") if isinstance(cfg, dict) else None
                if isinstance(dns, dict):
                    cnames = dns.get("cnameRecords") or dns.get("cname_records") or []
            if isinstance(cnames, list):
                records.extend(_parse_cname_entries(cnames))
    except Exception as exc:
        return [], f"Pi-hole v6: {exc}"

    # Best-effort logout
    try:
        if sid:
            client.delete(
                f"{origin}/api/auth",
                headers=headers,
                params={"sid": sid},
            )
    except Exception:
        pass

    return records, None


def fetch_pihole_dns(
    cfg: PiHoleConfig | None,
    settings: Settings | None = None,
    *,
    password_override: str | None = None,
    token_override: str | None = None,
) -> PiHoleResult:
    """
    Fetch local/custom DNS records. Never raises — returns ok=False on failure.
    Supports Pi-hole v5 (API token) and v6 (password / app password).
    Optional overrides come from Settings UI / SQLite.
    """
    settings = settings or get_settings()
    if not cfg or not (cfg.url or "").strip():
        return PiHoleResult(
            configured=False,
            ok=False,
            message="Pi-hole not configured",
        )

    token = (token_override if token_override is not None else settings.pihole_api_token) or ""
    token = token.strip()
    password = (
        password_override if password_override is not None else settings.pihole_password
    ) or ""
    password = password.strip() or token
    if not token and not password:
        return PiHoleResult(
            configured=True,
            ok=False,
            message="Pi-hole URL set but password / API token missing (Settings or .env)",
        )

    version: Version = cfg.version if cfg.version in ("auto", "5", "6") else "auto"
    timeout = cfg.timeout_seconds
    bases = _base_urls(cfg.url)
    if not bases:
        return PiHoleResult(configured=True, ok=False, message="Invalid Pi-hole URL")

    last_err: str | None = None

    try:
        with httpx.Client(timeout=timeout, verify=cfg.verify_tls, follow_redirects=True) as client:
            # Prefer v6 when password available and version allows
            if version in ("auto", "6") and password:
                for base in bases:
                    origin = urlparse(base if "://" in base else f"http://{base}")
                    origin_s = f"{origin.scheme}://{origin.netloc}"
                    records, err = _fetch_v6(client, origin_s, password)
                    if records or (err is None):
                        return PiHoleResult(
                            configured=True,
                            ok=True,
                            version="6",
                            message=None,
                            records=records,
                        )
                    last_err = err
                    if version == "6":
                        break

            if version in ("auto", "5") and token:
                for base in bases:
                    records, err = _fetch_v5(client, base, token)
                    if records or err is None:
                        return PiHoleResult(
                            configured=True,
                            ok=True,
                            version="5",
                            message=None,
                            records=records,
                        )
                    last_err = err
                    # Also try with password as v5 token
                    if password and password != token:
                        records, err = _fetch_v5(client, base, password)
                        if records or err is None:
                            return PiHoleResult(
                                configured=True,
                                ok=True,
                                version="5",
                                message=None,
                                records=records,
                            )
                        last_err = err
    except Exception as exc:
        last_err = str(exc)
        logger.warning("Pi-hole unreachable: %s", exc)

    return PiHoleResult(
        configured=True,
        ok=False,
        message=last_err or "Pi-hole unreachable",
        records=[],
    )
