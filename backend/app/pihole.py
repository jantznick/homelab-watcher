"""Read-only Pi-hole local DNS fetch (v5 API token and v6 session/password)."""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlparse

import httpx

from app.config import PiHoleConfig, Settings, get_settings

logger = logging.getLogger(__name__)

Version = Literal["auto", "5", "6"]

# Pi-hole web ≥ 5.11 (AdminLTE PR #2091, Feb 2022): list Local DNS / CNAME via
#   GET /admin/api.php?customdns&action=get&auth=<WEBPASSWORD hash>
#   GET /admin/api.php?customcname&action=get&auth=<WEBPASSWORD hash>
# Source: https://github.com/pi-hole/web/pull/2091
# Pre-5.11 had no list API (see discourse.pi-hole.net/t/45389). The Discourse
# thread /t/33777 is about lan.list vs custom.list — not the API.
#
# Auth pitfall: if auth fails (or customdns is unknown), api.php skips the
# customdns branch and falls through to json_encode([]) — a bare `[]` with
# HTTP 200. That must NOT be treated as "0 records".


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


def _origin_of(base: str) -> str:
    parsed = urlparse(base if "://" in base else f"http://{base}")
    return f"{parsed.scheme}://{parsed.netloc}"


def _looks_like_html(text: str) -> bool:
    t = text.lstrip()[:200].lower()
    return t.startswith("<!doctype") or t.startswith("<html") or "<html" in t


def _parse_hosts_lines(lines: list[Any]) -> list[DnsRecord]:
    """Parse 'IP hostname' or 'IP hostname #comment' style entries."""
    records: list[DnsRecord] = []
    for line in lines:
        if isinstance(line, dict):
            # Some FTL builds return objects
            ip = str(
                line.get("ip")
                or line.get("address")
                or line.get("target")
                or ""
            ).strip()
            host = str(
                line.get("name")
                or line.get("hostname")
                or line.get("host")
                or line.get("domain")
                or ""
            ).strip()
            if ip and host:
                records.append(
                    DnsRecord(hostname=_normalize_host(host), target=ip, kind="a")
                )
            continue
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


def _extract_hosts_list(body: Any) -> tuple[list[Any], bool]:
    """
    Pull dns.hosts (or similar) from a Pi-hole v6 JSON body.
    Returns (list, key_found).
    """
    if not isinstance(body, dict):
        return [], False
    # Direct
    if isinstance(body.get("hosts"), list):
        return body["hosts"], True
    cfg = body.get("config") if isinstance(body.get("config"), dict) else body
    if not isinstance(cfg, dict):
        return [], False
    dns = cfg.get("dns") if isinstance(cfg.get("dns"), dict) else None
    if isinstance(dns, dict) and "hosts" in dns:
        hosts = dns.get("hosts")
        if isinstance(hosts, list):
            return hosts, True
        if isinstance(hosts, dict):
            # rare map form
            lines = [f"{ip} {name}" for name, ip in hosts.items()]
            return lines, True
        return [], True
    if "hosts" in cfg and isinstance(cfg.get("hosts"), list):
        return cfg["hosts"], True
    return [], False


def _extract_cname_list(body: Any) -> list[Any]:
    if not isinstance(body, dict):
        return []
    cfg = body.get("config") if isinstance(body.get("config"), dict) else body
    if not isinstance(cfg, dict):
        return []
    dns = cfg.get("dns") if isinstance(cfg.get("dns"), dict) else None
    if isinstance(dns, dict):
        for key in ("cnameRecords", "cname_records", "cname"):
            val = dns.get(key)
            if isinstance(val, list):
                return val
    return []


def _parse_cname_entries(entries: list[Any]) -> list[DnsRecord]:
    records: list[DnsRecord] = []
    for item in entries:
        if isinstance(item, str):
            # "alias,target" or "alias,target,ttl" or "alias target"
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
        elif isinstance(item, dict):
            host = str(
                item.get("name")
                or item.get("hostname")
                or item.get("domain")
                or item.get("host")
                or ""
            ).strip()
            target = str(
                item.get("target")
                or item.get("cname")
                or item.get("destination")
                or ""
            ).strip()
            if host and target:
                records.append(
                    DnsRecord(
                        hostname=_normalize_host(host),
                        target=_normalize_host(target),
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


def _parse_v5_rows(rows: list[Any], kind: str) -> list[DnsRecord]:
    """v5 customdns/customcname return {data: [[domain, ip|target], ...]}."""
    records: list[DnsRecord] = []
    for row in rows:
        if isinstance(row, (list, tuple)) and len(row) >= 2:
            records.append(
                DnsRecord(
                    hostname=_normalize_host(str(row[0])),
                    target=str(row[1]).strip(),
                    kind=kind,
                )
            )
        elif isinstance(row, dict):
            if kind == "a":
                records.extend(_parse_hosts_lines([row]))
            else:
                records.extend(_parse_cname_entries([row]))
        elif isinstance(row, str):
            records.extend(
                _parse_hosts_lines([row])
                if kind == "a"
                else _parse_cname_entries([row])
            )
    return records


def _v5_auth_candidates(token: str) -> list[str]:
    """
    v5 ``auth`` must be WEBPASSWORD from setupVars (shown as API token).
    Users often paste the plaintext web password — also try sha256(sha256(pw)).
    """
    t = (token or "").strip()
    if not t:
        return []
    out = [t]
    if not re.fullmatch(r"[0-9a-fA-F]{64}", t):
        inner = hashlib.sha256(t.encode("utf-8")).hexdigest()
        out.append(hashlib.sha256(inner.encode("utf-8")).hexdigest())
    return out


def _loads_pihole_json(text: str) -> Any:
    """
    Parse Pi-hole JSON. Web 5.11 briefly appended a stray ``[]`` after the
    customdns object (pi-hole/web#2123); strip that so records still parse.
    """
    text = (text or "").strip()
    if not text:
        raise json.JSONDecodeError("empty", text, 0)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        # Trailing junk after a complete value — keep the first object/array.
        decoder = json.JSONDecoder()
        obj, end = decoder.raw_decode(text)
        rest = text[end:].strip()
        if rest in ("", "[]"):
            return obj
        raise


_V5_BARE_ARRAY_HINT = (
    "Pi-hole v5 returned bare [] (not {\"data\":[]}). Usually wrong API token, "
    "or web UI older than 5.11 (no Local DNS list API — upgrade web ≥ 5.11 or "
    "use Pi-hole v6). Token = Settings → API → Show API token (WEBPASSWORD hash), "
    "not the login password unless we can hash it."
)


def _fetch_v5_once(
    client: httpx.Client, admin: str, token: str
) -> tuple[list[DnsRecord], str | None]:
    """
    One auth attempt against v5 customdns + customcname.

    Real empty Local DNS is ``{"data": []}``. Bare ``[]`` means the customdns
    branch never ran (bad auth or no endpoint) — treat as failure.
    """
    records: list[DnsRecord] = []
    errors: list[str] = []
    parsed_ok = False
    saw_bare_array = False

    for list_name, kind in (("customdns", "a"), ("customcname", "cname")):
        url = f"{admin}/api.php"
        try:
            # action=get is mandatory (AdminLTE customdns/customcname switch)
            r = client.get(
                url,
                params={list_name: "", "action": "get", "auth": token},
            )
            text = (r.text or "").strip()

            if r.status_code == 401 or re.search(
                r"not authorized", text, re.IGNORECASE
            ):
                return [], "Pi-hole v5 auth failed (check API token)"
            if r.status_code == 404:
                errors.append(
                    f"{list_name}: HTTP 404 — wrong URL? use http://<pi-ip>/admin"
                )
                continue
            if r.status_code >= 400:
                errors.append(f"{list_name}: HTTP {r.status_code}")
                continue
            if text.lower().startswith("wrong action"):
                errors.append(
                    f"{list_name}: Wrong action — need action=get "
                    "(or web < 5.11 with no Local DNS list API)"
                )
                continue
            if _looks_like_html(text):
                errors.append(
                    f"{list_name}: got HTML — check Pi-hole URL "
                    "(http://host or http://host/admin)"
                )
                continue

            try:
                data = _loads_pihole_json(text)
            except Exception:
                snippet = text[:120].replace("\n", " ")
                errors.append(
                    f"{list_name}: non-JSON response ({snippet!r})"
                    if snippet
                    else f"{list_name}: empty/non-JSON response"
                )
                continue

            # Bare [] = auth failed or customdns unknown (api.php fall-through).
            # Do NOT treat as empty Local DNS.
            if isinstance(data, list):
                saw_bare_array = True
                errors.append(
                    f"{list_name}: bare [] — auth failed or Local DNS list "
                    "API missing (need web ≥ 5.11)"
                )
                continue

            if not isinstance(data, dict):
                errors.append(f"{list_name}: unexpected JSON type")
                continue

            if "data" not in data:
                keys = ", ".join(sorted(data.keys())[:8]) or "empty"
                errors.append(
                    f"{list_name}: no 'data' key in JSON (keys: {keys})"
                )
                continue

            rows = data.get("data")
            if rows is None:
                rows = []
            if isinstance(rows, dict):
                # jsonForceObject=1 style — values are [domain, target]
                rows = list(rows.values())
            if not isinstance(rows, list):
                errors.append(f"{list_name}: 'data' is not a list")
                continue

            parsed_ok = True
            records.extend(_parse_v5_rows(rows, kind))
        except Exception as exc:
            errors.append(f"{list_name}: {exc}")
            logger.debug("Pi-hole v5 fetch failed: %s", exc)

    if records:
        return records, None
    if parsed_ok:
        # Auth + {"data": ...} shape OK — Local DNS / CNAME lists are empty
        return [], None
    if saw_bare_array and not parsed_ok:
        return [], _V5_BARE_ARRAY_HINT
    return [], (
        "; ".join(errors)
        if errors
        else "Pi-hole v5: could not read custom DNS (check URL + API token)"
    )


def _fetch_v5(
    client: httpx.Client, base: str, token: str
) -> tuple[list[DnsRecord], str | None]:
    """
    Pi-hole v5 Local DNS via admin API (web ≥ 5.11):

      GET /admin/api.php?customdns&action=get&auth=TOKEN
      GET /admin/api.php?customcname&action=get&auth=TOKEN

    ``action=get`` is required — without it the PHP API dies with ``Wrong action``.
    See module docstring / pi-hole/web#2091.
    """
    admin = base if base.rstrip("/").endswith("/admin") else f"{base.rstrip('/')}/admin"
    last_err: str | None = None
    for candidate in _v5_auth_candidates(token):
        records, err = _fetch_v5_once(client, admin, candidate)
        if records or err is None:
            return records, err
        last_err = err
        # Only retry next candidate when this looked like auth / bare-array failure
        if err and "bare []" not in err and "API token" not in err:
            break
    return [], last_err


def _auth_v6(
    client: httpx.Client, origin: str, password: str
) -> tuple[str | None, str | None, str | None]:
    """Return (sid, csrf, error)."""
    try:
        r = client.post(f"{origin}/api/auth", json={"password": password})
        text = (r.text or "").strip()
        if r.status_code == 404 or _looks_like_html(text):
            return None, None, "Pi-hole v6 API not found (is this a v5 host?)"
        if r.status_code >= 400:
            # Try to extract JSON error
            try:
                err_body = r.json()
                err = err_body.get("error") if isinstance(err_body, dict) else None
                if isinstance(err, dict) and err.get("message"):
                    return None, None, f"Pi-hole v6 auth: {err.get('message')}"
            except Exception:
                pass
            return None, None, f"Pi-hole v6 auth HTTP {r.status_code}"
        try:
            body = r.json()
        except Exception:
            return None, None, "Pi-hole v6 auth: non-JSON response (wrong URL?)"
        session = body.get("session") if isinstance(body, dict) else None
        if not isinstance(session, dict):
            err = body.get("error") if isinstance(body, dict) else None
            if isinstance(err, dict) and err.get("message"):
                return None, None, f"Pi-hole v6 auth: {err.get('message')}"
            return None, None, "Pi-hole v6 auth: unexpected response"
        if session.get("valid") is False:
            return None, None, "Pi-hole v6 auth failed (check password / app password)"
        sid = session.get("sid")
        csrf = session.get("csrf")
        if not sid:
            # Passwordless / already valid
            if session.get("valid"):
                return "", str(csrf) if csrf else None, None
            return None, None, "Pi-hole v6 auth: no session id"
        return str(sid), str(csrf) if csrf else None, None
    except Exception as exc:
        return None, None, f"Pi-hole v6 auth: {exc}"


def _v6_headers(sid: str | None, csrf: str | None) -> dict[str, str]:
    headers: dict[str, str] = {"Accept": "application/json"}
    if sid:
        headers["X-FTL-SID"] = sid
        headers["sid"] = sid
        headers["Cookie"] = f"sid={sid}"
    if csrf:
        headers["X-FTL-CSRF"] = csrf
    return headers


def _fetch_v6(
    client: httpx.Client, origin: str, password: str
) -> tuple[list[DnsRecord], str | None]:
    sid, csrf, err = _auth_v6(client, origin, password)
    if err:
        return [], err

    headers = _v6_headers(sid, csrf)
    params = {"sid": sid or ""}

    records: list[DnsRecord] = []
    hosts_found = False
    last_http_err: str | None = None
    try:
        # Prefer dedicated hosts endpoint; fall back to full config if empty/missing.
        for path in (
            "/api/config/dns/hosts",
            "/api/config/dns",
            "/api/config",
        ):
            r = client.get(f"{origin}{path}", headers=headers, params=params)
            if r.status_code in (401, 403):
                return [], "Pi-hole v6 session rejected (auth failed)"
            if r.status_code >= 400:
                last_http_err = f"Pi-hole v6 {path}: HTTP {r.status_code}"
                if path == "/api/config/dns/hosts":
                    continue
                if path == "/api/config" and not hosts_found and not records:
                    return [], last_http_err
                continue
            try:
                body = r.json()
            except Exception:
                last_http_err = f"Pi-hole v6 {path}: non-JSON response"
                continue
            hosts, found = _extract_hosts_list(body)
            if found:
                hosts_found = True
                records.extend(_parse_hosts_lines(hosts))
            cnames = _extract_cname_list(body)
            if cnames:
                records.extend(_parse_cname_entries(cnames))
            if records:
                break

        # Dedicated CNAME endpoint when still missing
        if not any(r.kind == "cname" for r in records):
            r2 = client.get(
                f"{origin}/api/config/dns/cnameRecords",
                headers=headers,
                params=params,
            )
            if r2.status_code < 400:
                try:
                    body2 = r2.json()
                    cnames = _extract_cname_list(body2)
                    if not cnames and isinstance(body2, dict):
                        cfg = body2.get("config") or body2
                        dns = cfg.get("dns") if isinstance(cfg, dict) else None
                        if isinstance(dns, dict):
                            raw = (
                                dns.get("cnameRecords")
                                or dns.get("cname_records")
                                or []
                            )
                            if isinstance(raw, list):
                                cnames = raw
                    if isinstance(cnames, list):
                        records.extend(_parse_cname_entries(cnames))
                except Exception:
                    pass

        if not hosts_found and not records:
            return [], (
                last_http_err
                or "Pi-hole v6: could not find dns.hosts in API response"
            )
    except Exception as exc:
        return [], f"Pi-hole v6: {exc}"
    finally:
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


def _probe_is_v6(client: httpx.Client, origin: str) -> bool | None:
    """True if v6 API present, False if clearly not, None if inconclusive."""
    try:
        r = client.get(f"{origin}/api/info/version")
        if r.status_code == 404 or _looks_like_html(r.text or ""):
            return False
        if r.status_code < 500:
            try:
                body = r.json()
                if isinstance(body, dict) and (
                    "version" in body or "ftl" in body or "took" in body
                ):
                    return True
            except Exception:
                pass
        # /api/auth GET often returns session info on v6
        r2 = client.get(f"{origin}/api/auth")
        if r2.status_code == 404 or _looks_like_html(r2.text or ""):
            return False
        if r2.status_code < 500:
            try:
                body = r2.json()
                if isinstance(body, dict) and "session" in body:
                    return True
            except Exception:
                pass
    except Exception:
        return None
    return None


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
    password = password.strip()
    # v6 can use app password; never silently treat v5 token as v6 password unless
    # the password field is empty (legacy single-secret setups).
    v6_secret = password or token
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
    origins = []
    for b in bases:
        o = _origin_of(b)
        if o not in origins:
            origins.append(o)

    try:
        with httpx.Client(
            timeout=timeout, verify=cfg.verify_tls, follow_redirects=True
        ) as client:
            prefer_v6 = version in ("auto", "6")
            prefer_v5 = version in ("auto", "5")

            # In auto mode, probe so we don't soft-succeed on the wrong API.
            detected: bool | None = None
            if version == "auto":
                for origin in origins:
                    detected = _probe_is_v6(client, origin)
                    if detected is not None:
                        break
                if detected is True:
                    # Confirmed v6 — never fall through to v5 customdns/customcname.
                    # Leftover v5 API tokens used to overwrite a good v6 result's
                    # poll cache with "customdns: Connection refused".
                    prefer_v5 = False
                elif detected is False:
                    prefer_v6 = False

            if prefer_v6 and v6_secret:
                for origin in origins:
                    records, err = _fetch_v6(client, origin, v6_secret)
                    if records:
                        return PiHoleResult(
                            configured=True,
                            ok=True,
                            version="6",
                            message=f"OK — {len(records)} local/custom DNS records",
                            records=records,
                        )
                    if err is None:
                        # Auth + parse succeeded with a genuine empty hosts list.
                        return PiHoleResult(
                            configured=True,
                            ok=True,
                            version="6",
                            message=(
                                "Connected (v6) — 0 Local DNS records in "
                                "dns.hosts / cnameRecords (API list is empty)"
                            ),
                            records=[],
                        )
                    last_err = err
                    # Definitive v6 talk (auth/API errors) — do not mask with v5.
                    if detected is True or version == "6" or (
                        err
                        and (
                            "v6 auth" in err.lower()
                            or "v6 session" in err.lower()
                            or "v6 api" in err.lower()
                        )
                    ):
                        prefer_v5 = False
                    if version == "6":
                        break

            if prefer_v5 and token:
                for base in bases:
                    records, err = _fetch_v5(client, base, token)
                    if records:
                        return PiHoleResult(
                            configured=True,
                            ok=True,
                            version="5",
                            message=f"OK — {len(records)} local/custom DNS records",
                            records=records,
                        )
                    if err is None:
                        return PiHoleResult(
                            configured=True,
                            ok=True,
                            version="5",
                            message=(
                                "Connected (v5) — 0 Local DNS records "
                                "(customdns/customcname returned {\"data\":[]})"
                            ),
                            records=[],
                        )
                    last_err = err
                    # Also try with password as v5 token (some users paste web password)
                    if password and password != token:
                        records, err = _fetch_v5(client, base, password)
                        if records:
                            return PiHoleResult(
                                configured=True,
                                ok=True,
                                version="5",
                                message=f"OK — {len(records)} local/custom DNS records",
                                records=records,
                            )
                        if err is None:
                            return PiHoleResult(
                                configured=True,
                                ok=True,
                                version="5",
                                message=(
                                    "Connected (v5) — 0 Local DNS records "
                                    "(customdns/customcname returned {\"data\":[]})"
                                ),
                                records=[],
                            )
                        last_err = err
            elif prefer_v5 and password and not token:
                # Password-as-token for v5 when no dedicated token field
                for base in bases:
                    records, err = _fetch_v5(client, base, password)
                    if records:
                        return PiHoleResult(
                            configured=True,
                            ok=True,
                            version="5",
                            message=f"OK — {len(records)} local/custom DNS records",
                            records=records,
                        )
                    if err is None:
                        return PiHoleResult(
                            configured=True,
                            ok=True,
                            version="5",
                            message=(
                                "Connected (v5) — 0 Local DNS records "
                                "(customdns/customcname returned {\"data\":[]})"
                            ),
                            records=[],
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
