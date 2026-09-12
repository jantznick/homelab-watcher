"""Read-only Caddy route discovery (Admin API, Caddyfile, docker-proxy labels)."""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

RouteSource = Literal["caddyfile", "api", "label"]


@dataclass
class ProxyRoute:
    hostname: str
    upstream: str
    source: RouteSource
    path: str | None = None


@dataclass
class RouteDiscoveryResult:
    ok: bool
    routes: list[ProxyRoute] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    sources_tried: list[str] = field(default_factory=list)

    @property
    def message(self) -> str | None:
        if self.ok:
            return None
        return "; ".join(self.errors) if self.errors else "No routes discovered"


_HOST_TOKEN = re.compile(
    r"^(?:https?://)?([A-Za-z0-9_.*-]+(?::\d+)?)(?:/.*)?$"
)
_CADDY_SITE_KEY = re.compile(r"^caddy(?:_\d+)?$", re.IGNORECASE)
_CADDY_RP_KEY = re.compile(
    r"^caddy(?:_\d+)?\.reverse_proxy(?:\.\d+)?$", re.IGNORECASE
)
_UPSTREAMS_TPL = re.compile(
    r"\{\{\s*upstreams(?:\s+(\d+))?\s*\}\}", re.IGNORECASE
)
_SKIP_SITE = re.compile(
    r"^(import|respond|redir|rewrite|reverse_proxy|handle|route|basicauth|"
    r"encode|header|log|tls|file_server|php_fastcgi|root|uri|email|"
    r"acme_server|admin|servers)$",
    re.IGNORECASE,
)
# Caddyfile adapter: {$VAR} and {$VAR:default}
_CADDY_DOLLAR = re.compile(
    r"\{\$([A-Za-z_][A-Za-z0-9_]*)(?::([^}]*))?\}"
)
# Runtime placeholder sometimes used in Caddyfiles: {env.VAR}
_CADDY_ENV_DOT = re.compile(r"\{env\.([A-Za-z_][A-Za-z0-9_]*)\}")
_ENV_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class CaddyPlaceholder:
    name: str
    default: str | None = None


def _norm_host(value: str) -> str:
    v = (value or "").strip().lower().rstrip(".")
    if "://" in v:
        try:
            host = urlparse(v).hostname
            return (host or "").lower().rstrip(".")
        except Exception:
            return v
    # strip path / port for hostname key (keep bare hostname)
    v = v.split("/", 1)[0]
    if v.startswith("*."):
        return v
    # drop listen port on site address like host:443
    if ":" in v and not v.count(":") > 1:
        host, maybe_port = v.rsplit(":", 1)
        if maybe_port.isdigit():
            v = host
    return v.rstrip(".")


def _norm_upstream(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return ""
    # strip quotes
    if (v.startswith('"') and v.endswith('"')) or (
        v.startswith("'") and v.endswith("'")
    ):
        v = v[1:-1].strip()
    # first token (ignore load-balance options)
    v = v.split()[0] if v.split() else v
    if "://" in v:
        try:
            p = urlparse(v)
            if p.hostname:
                if p.port:
                    return f"{p.hostname}:{p.port}"
                return p.hostname
        except Exception:
            pass
    return v.strip().rstrip("/")


def _host_candidates_from_token(token: str) -> list[str]:
    t = (token or "").strip().strip(",")
    if not t or t.startswith("{") or t.startswith("}"):
        return []
    if _SKIP_SITE.match(t):
        return []
    # snip scheme
    if t.startswith("http://") or t.startswith("https://"):
        t = t.split("://", 1)[1]
    # drop path
    t = t.split("/", 1)[0]
    if not t or t in ("localhost", "127.0.0.1", ":443", ":80"):
        # still allow localhost as a site in rare labs
        if t not in ("localhost",):
            return []
    if " " in t or "{" in t:
        return []
    host = _norm_host(t)
    if not host or host.startswith(":"):
        return []
    return [host]


def normalize_caddy_env(raw: Any) -> dict[str, str]:
    """Accept a dict, list of {name,value}, or dotenv-style text."""
    out: dict[str, str] = {}
    if not raw:
        return out
    if isinstance(raw, str):
        return parse_env_text(raw)
    if isinstance(raw, Mapping):
        items = raw.items()
    elif isinstance(raw, list):
        items = []
        for row in raw:
            if isinstance(row, Mapping):
                items.append(
                    (row.get("name") or row.get("key"), row.get("value"))
                )
            else:
                continue
    else:
        return out
    for key, val in items:
        name = str(key or "").strip()
        if not _ENV_KEY.match(name) or val is None:
            continue
        value = str(val)
        if value == "":
            continue
        out[name] = value
    return out


def parse_env_text(text: str) -> dict[str, str]:
    """Parse KEY=value lines (Compose / Caddy env_file)."""
    out: dict[str, str] = {}
    if not text:
        return out
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.lower().startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        key = key.strip()
        if not _ENV_KEY.match(key):
            continue
        val = val.strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
            val = val[1:-1]
        if val == "":
            continue
        out[key] = val
    return out


def strip_caddyfile_comments(text: str) -> str:
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        if " #" in line:
            line = line.split(" #", 1)[0]
        lines.append(line)
    return "\n".join(lines)


def extract_caddy_placeholders(text: str) -> list[CaddyPlaceholder]:
    """Unique {$VAR} / {env.VAR} names in Caddyfile order (comments ignored)."""
    if not text:
        return []
    body = strip_caddyfile_comments(text)
    seen: set[str] = set()
    out: list[CaddyPlaceholder] = []
    for m in _CADDY_DOLLAR.finditer(body):
        name = m.group(1)
        if name in seen:
            continue
        seen.add(name)
        default = m.group(2)
        out.append(CaddyPlaceholder(name=name, default=default))
    for m in _CADDY_ENV_DOT.finditer(body):
        name = m.group(1)
        if name in seen:
            continue
        seen.add(name)
        out.append(CaddyPlaceholder(name=name, default=None))
    return out


def expand_caddy_placeholders(
    text: str, env: Mapping[str, str] | None = None
) -> str:
    """Replace Caddy {$VAR} / {$VAR:default} / {env.VAR} using provided values."""
    values = dict(env or {})

    def dollar(m: re.Match[str]) -> str:
        name = m.group(1)
        default = m.group(2)
        if name in values:
            return values[name]
        if default is not None:
            return default
        return m.group(0)

    def envdot(m: re.Match[str]) -> str:
        name = m.group(1)
        if name in values:
            return values[name]
        return m.group(0)

    out = _CADDY_DOLLAR.sub(dollar, text)
    return _CADDY_ENV_DOT.sub(envdot, out)


def unexpanded_placeholder_names(text: str) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for m in _CADDY_DOLLAR.finditer(text):
        if m.group(1) not in seen:
            seen.add(m.group(1))
            names.append(m.group(1))
    for m in _CADDY_ENV_DOT.finditer(text):
        if m.group(1) not in seen:
            seen.add(m.group(1))
            names.append(m.group(1))
    return names


def parse_caddyfile(
    text: str, env: Mapping[str, str] | None = None
) -> list[ProxyRoute]:
    """
    Best-effort Caddyfile parser for hostname → reverse_proxy upstream.

    Handles simple site blocks; ignores complex matchers / snippets gracefully.
    Expands {$VAR} / {$VAR:default} / {env.VAR} before parsing.
    """
    if not text or not text.strip():
        return []

    content = expand_caddy_placeholders(strip_caddyfile_comments(text), env)
    routes: list[ProxyRoute] = []
    i = 0
    n = len(content)

    def skip_ws(idx: int) -> int:
        while idx < n and content[idx].isspace():
            idx += 1
        return idx

    while i < n:
        i = skip_ws(i)
        if i >= n:
            break
        # global options block
        if content.startswith("{", i):
            depth = 0
            while i < n:
                if content[i] == "{":
                    depth += 1
                elif content[i] == "}":
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                i += 1
            continue

        # site address line until block `{` or newline; skip {$VAR} / {env.VAR}
        addr_start = i
        while i < n and content[i] != "\n":
            if content[i] == "{":
                rest = content[i:]
                if rest.startswith("{$") or rest.startswith("{env."):
                    close = content.find("}", i + 1)
                    if close < 0:
                        i = n
                        break
                    i = close + 1
                    continue
                break
            i += 1
        addr_line = content[addr_start:i].strip()
        if i < n and content[i] == "{":
            # block body
            i += 1
            depth = 1
            body_start = i
            while i < n and depth:
                if content[i] == "{":
                    depth += 1
                elif content[i] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            body = content[body_start:i]
            if i < n and content[i] == "}":
                i += 1
            hosts = []
            for part in re.split(r"[\s,]+", addr_line):
                hosts.extend(_host_candidates_from_token(part))
            upstreams = _upstreams_from_block(body)
            for h in hosts:
                if not upstreams:
                    routes.append(
                        ProxyRoute(hostname=h, upstream="", source="caddyfile")
                    )
                else:
                    for up in upstreams:
                        routes.append(
                            ProxyRoute(
                                hostname=h, upstream=up, source="caddyfile"
                            )
                        )
        else:
            # single-line site without block — skip
            i = skip_ws(i)
            continue

    return _dedupe_routes(routes)


def _upstreams_from_block(body: str) -> list[str]:
    ups: list[str] = []
    for m in re.finditer(
        r"reverse_proxy\b([^\n{]*)(?:\{([^}]*)\})?",
        body,
        re.IGNORECASE,
    ):
        head = (m.group(1) or "").strip()
        inner = (m.group(2) or "").strip()
        # tokens in head before any nested directive noise
        for tok in head.split():
            if tok.startswith("{"):
                break
            if tok.startswith("@") or tok.startswith("/"):
                continue
            if tok == "*":
                continue
            if "=" in tok and not tok.startswith("http"):
                continue
            nu = _norm_upstream(tok)
            if nu and nu not in ups:
                ups.append(nu)
        if inner:
            for line in inner.splitlines():
                ls = line.strip()
                if ls.startswith("to "):
                    nu = _norm_upstream(ls[3:].strip())
                    if nu and nu not in ups:
                        ups.append(nu)
    return ups


def _dedupe_routes(routes: list[ProxyRoute]) -> list[ProxyRoute]:
    seen: set[tuple[str, str, str]] = set()
    out: list[ProxyRoute] = []
    for r in routes:
        key = (r.hostname, r.upstream, r.source)
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def load_caddyfile_text(path: str) -> tuple[str | None, str | None]:
    """Read Caddyfile text via same-path or HOST_ROOT remap. (text, error)."""
    raw = (path or "").strip()
    if not raw:
        return None, "Caddyfile path not set"
    from app.container_actions import resolve_visible_path

    visible = resolve_visible_path(raw) or raw
    p = Path(visible).expanduser()
    try:
        if not p.is_file():
            return None, f"Caddyfile not found: {raw}"
        return p.read_text(encoding="utf-8", errors="replace"), None
    except OSError as exc:
        return None, f"Cannot read Caddyfile: {exc}"


def scan_caddyfile_placeholders(
    path: str,
) -> tuple[list[CaddyPlaceholder], str | None]:
    text, err = load_caddyfile_text(path)
    if err:
        return [], err
    return extract_caddy_placeholders(text or ""), None


def read_caddyfile(
    path: str, env: Mapping[str, str] | None = None
) -> tuple[list[ProxyRoute], str | None]:
    text, err = load_caddyfile_text(path)
    if err:
        return [], err
    try:
        expanded = expand_caddy_placeholders(text or "", env)
        missing = unexpanded_placeholder_names(
            strip_caddyfile_comments(expanded)
        )
        routes = parse_caddyfile(text or "", env=env)
        if missing:
            names = ", ".join(f"{{${n}}}" for n in missing)
            warn = (
                f"Caddyfile has unsubstituted placeholders: {names}. "
                "Set them under Settings → Networking."
            )
            if not routes:
                return [], warn
            return routes, warn
        return routes, None
    except Exception as exc:
        logger.debug("Caddyfile parse failed: %s", exc)
        return [], f"Caddyfile parse error: {exc}"


def _walk_api_routes(node: Any, out: list[ProxyRoute]) -> None:
    if isinstance(node, dict):
        # A route object
        match = node.get("match")
        handle = node.get("handle") or node.get("handlers")
        hosts: list[str] = []
        if isinstance(match, list):
            for m in match:
                if not isinstance(m, dict):
                    continue
                for h in m.get("host") or []:
                    nh = _norm_host(str(h))
                    if nh:
                        hosts.append(nh)
        upstreams: list[str] = []
        if isinstance(handle, list):
            for h in handle:
                if not isinstance(h, dict):
                    continue
                handler = (h.get("handler") or "").lower()
                if handler == "reverse_proxy":
                    for up in h.get("upstreams") or []:
                        if isinstance(up, dict):
                            dial = up.get("dial") or up.get("host")
                            if dial:
                                nu = _norm_upstream(str(dial))
                                if nu:
                                    upstreams.append(nu)
                        elif isinstance(up, str):
                            nu = _norm_upstream(up)
                            if nu:
                                upstreams.append(nu)
                # nested subroutes
                if "routes" in h:
                    _walk_api_routes(h.get("routes"), out)
                if handler == "subroute" and "routes" in h:
                    _walk_api_routes(h["routes"], out)

        if hosts:
            if upstreams:
                for host in hosts:
                    for up in upstreams:
                        out.append(
                            ProxyRoute(
                                hostname=host, upstream=up, source="api"
                            )
                        )
            else:
                for host in hosts:
                    out.append(
                        ProxyRoute(hostname=host, upstream="", source="api")
                    )

        for v in node.values():
            _walk_api_routes(v, out)
    elif isinstance(node, list):
        for item in node:
            _walk_api_routes(item, out)


def fetch_caddy_admin_routes(
    admin_url: str,
    *,
    timeout: float = 5.0,
    verify_tls: bool = True,
) -> tuple[list[ProxyRoute], str | None]:
    base = (admin_url or "").strip().rstrip("/")
    if not base:
        return [], "Caddy admin URL not set"
    if "://" not in base:
        base = f"http://{base}"

    urls = [
        f"{base}/config/",
        f"{base}/config/apps/http",
        f"{base}/config/apps/http/servers",
    ]
    last_err: str | None = None
    try:
        with httpx.Client(timeout=timeout, verify=verify_tls, follow_redirects=True) as client:
            for url in urls:
                try:
                    r = client.get(url)
                    if r.status_code >= 400:
                        last_err = f"Caddy admin HTTP {r.status_code} at {url}"
                        continue
                    data = r.json()
                    found: list[ProxyRoute] = []
                    _walk_api_routes(data, found)
                    if found:
                        return _dedupe_routes(found), None
                    # empty but valid JSON — keep trying other paths
                    last_err = "Caddy admin responded but no host routes found"
                except Exception as exc:
                    last_err = f"Caddy admin: {exc}"
                    logger.debug("Caddy admin fetch failed (%s): %s", url, exc)
    except Exception as exc:
        return [], f"Caddy admin unreachable: {exc}"

    return [], last_err or "Caddy admin: no routes"


def routes_from_container_labels(
    containers: list[dict[str, Any]],
) -> list[ProxyRoute]:
    """Parse caddy-docker-proxy labels already present on inventoried containers."""
    routes: list[ProxyRoute] = []
    for c in containers:
        labels = c.get("labels") or {}
        if not isinstance(labels, dict) or not labels:
            continue
        name = (c.get("name") or "").lstrip("/")
        # Map index → site hosts
        sites: dict[str, list[str]] = {}
        for key, raw in labels.items():
            m = _CADDY_SITE_KEY.match(str(key))
            if not m or not raw:
                continue
            idx = str(key).lower()
            hosts: list[str] = []
            for part in re.split(r"[\s,]+", str(raw).strip()):
                hosts.extend(_host_candidates_from_token(part))
            if hosts:
                sites[idx] = hosts

        # reverse_proxy directives
        rps: dict[str, list[str]] = {}
        for key, raw in labels.items():
            if not _CADDY_RP_KEY.match(str(key)) or raw is None:
                continue
            # caddy.reverse_proxy → caddy ; caddy_0.reverse_proxy → caddy_0
            base = str(key).split(".", 1)[0].lower()
            val = str(raw).strip()
            ups: list[str] = []
            tpl = _UPSTREAMS_TPL.search(val)
            if tpl:
                port = tpl.group(1)
                if port:
                    ups.append(f"{name}:{port}" if name else port)
                elif name:
                    ups.append(name)
            else:
                for tok in val.split():
                    if tok.startswith("{"):
                        continue
                    nu = _norm_upstream(tok)
                    if nu:
                        ups.append(nu)
            if ups:
                rps.setdefault(base, []).extend(ups)

        for site_key, hosts in sites.items():
            ups = rps.get(site_key) or rps.get("caddy") or []
            # default: this container itself
            if not ups and name:
                ups = [name]
            for h in hosts:
                if ups:
                    for up in ups:
                        routes.append(
                            ProxyRoute(
                                hostname=h, upstream=up, source="label"
                            )
                        )
                else:
                    routes.append(
                        ProxyRoute(hostname=h, upstream=name, source="label")
                    )

    return _dedupe_routes(routes)


def discover_caddy_routes(
    *,
    use_admin_api: bool = False,
    admin_url: str = "",
    use_caddyfile: bool = False,
    caddyfile_path: str = "",
    caddyfile_env: Mapping[str, str] | None = None,
    use_labels: bool = False,
    containers: list[dict[str, Any]] | None = None,
    timeout: float = 5.0,
    verify_tls: bool = True,
) -> RouteDiscoveryResult:
    """
    Discover Caddy routes from enabled sources. Fail-soft per source.
    """
    result = RouteDiscoveryResult(ok=False)
    all_routes: list[ProxyRoute] = []

    if use_admin_api:
        result.sources_tried.append("api")
        routes, err = fetch_caddy_admin_routes(
            admin_url, timeout=timeout, verify_tls=verify_tls
        )
        if err:
            result.errors.append(err)
        else:
            all_routes.extend(routes)

    if use_caddyfile:
        result.sources_tried.append("caddyfile")
        routes, err = read_caddyfile(caddyfile_path, env=caddyfile_env)
        if err:
            result.errors.append(err)
        if routes:
            all_routes.extend(routes)

    if use_labels:
        result.sources_tried.append("label")
        try:
            all_routes.extend(routes_from_container_labels(containers or []))
        except Exception as exc:
            result.errors.append(f"Label parse: {exc}")

    all_routes = _dedupe_routes(all_routes)
    # Prefer richer upstream when duplicates share hostname
    by_host: dict[str, ProxyRoute] = {}
    for r in all_routes:
        prev = by_host.get(r.hostname)
        if prev is None:
            by_host[r.hostname] = r
        elif not prev.upstream and r.upstream:
            by_host[r.hostname] = r
        elif prev.upstream and r.upstream and prev.source != r.source:
            # keep both via list — restore multi later
            pass

    # Keep all hostname+upstream pairs (multi-upstream rare but valid)
    result.routes = all_routes
    result.ok = bool(all_routes) or (
        bool(result.sources_tried) and not result.errors
    )
    # If we tried sources and got routes, ok even with partial errors
    if all_routes:
        result.ok = True
    return result
