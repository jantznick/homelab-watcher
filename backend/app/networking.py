"""Join DNS (Pi-hole) → reverse-proxy routes → Docker containers."""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from app.access_urls import hostname_from_url
from app.caddy_routes import ProxyRoute, RouteDiscoveryResult, discover_caddy_routes
from app.container_enrich import correlate_pihole
from app.pihole import PiHoleResult

logger = logging.getLogger(__name__)

_LOCAL_UPSTREAM_HOSTS = {
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "host.docker.internal",
    "docker.for.mac.localhost",
    "gateway.docker.internal",
}


def _norm(s: str) -> str:
    return (s or "").strip().lower().rstrip(".")


def _first_label(hostname: str) -> str:
    return _norm(hostname).split(".", 1)[0]


def _parse_upstream(upstream: str) -> tuple[str | None, int | None]:
    """Return (host, port) from host:port / URL / bare host."""
    raw = (upstream or "").strip()
    if not raw:
        return None, None
    if "://" in raw:
        try:
            p = urlparse(raw)
            return (p.hostname.lower() if p.hostname else None), p.port
        except Exception:
            return None, None
    host = raw
    port: int | None = None
    if raw.startswith("[") and "]" in raw:
        # [ipv6]:port
        bracket, _, rest = raw.partition("]")
        host = bracket[1:]
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
        return host.lower(), port
    if raw.count(":") == 1:
        h, _, p = raw.partition(":")
        if p.isdigit():
            return h.lower(), int(p)
    return host.lower(), port


def _container_port_set(container: dict[str, Any]) -> set[int]:
    ports: set[int] = set()
    for line in container.get("published_ports") or []:
        # "0.0.0.0:8080->80/tcp" or "80/tcp"
        text = str(line)
        m = re.search(r":(\d+)->(\d+)", text)
        if m:
            ports.add(int(m.group(1)))
            ports.add(int(m.group(2)))
            continue
        m2 = re.match(r"(\d+)/", text)
        if m2:
            ports.add(int(m2.group(1)))
    inspect = container.get("inspect") or {}
    ns = inspect.get("NetworkSettings") or {}
    for cport in (ns.get("Ports") or {}) or {}:
        num = str(cport).split("/", 1)[0]
        if num.isdigit():
            ports.add(int(num))
    # ExposedPorts from Config
    cfg = inspect.get("Config") or {}
    for cport in (cfg.get("ExposedPorts") or {}) or {}:
        num = str(cport).split("/", 1)[0]
        if num.isdigit():
            ports.add(int(num))
    return ports


def _network_aliases(container: dict[str, Any]) -> set[str]:
    aliases: set[str] = set()
    name = _norm(container.get("name") or "")
    if name:
        aliases.add(name)
    labels = container.get("labels") or {}
    service = _norm(labels.get("com.docker.compose.service") or "")
    if service:
        aliases.add(service)
    project = _norm(labels.get("com.docker.compose.project") or "")
    if project and service:
        aliases.add(f"{project}-{service}-1")
        aliases.add(f"{project}_{service}_1")

    inspect = container.get("inspect") or {}
    nets = ((inspect.get("NetworkSettings") or {}).get("Networks") or {}) or {}
    for net in nets.values():
        if not isinstance(net, dict):
            continue
        for a in net.get("Aliases") or []:
            na = _norm(str(a))
            if na:
                aliases.add(na)
        dns_names = net.get("DNSNames") or []
        for a in dns_names:
            na = _norm(str(a))
            if na:
                aliases.add(na)
    return aliases


def _match_score(
    route: ProxyRoute,
    container: dict[str, Any],
) -> int:
    """Higher = better match. 0 = no match."""
    host, port = _parse_upstream(route.upstream)
    aliases = _network_aliases(container)
    ports = _container_port_set(container)
    score = 0

    if host:
        if host in aliases:
            score += 50
        elif _first_label(host) in aliases:
            score += 35
        elif host in _LOCAL_UPSTREAM_HOSTS:
            # localhost-style upstream: port is the signal
            score += 5
        else:
            # weak: hostname first label vs container tokens
            fl = _first_label(host)
            if fl and fl in aliases:
                score += 30

    if port is not None:
        if port in ports:
            score += 25
        elif host and host in _LOCAL_UPSTREAM_HOSTS:
            # local upstream with unmatched port — weak
            score += 0
        elif not host:
            if port in ports:
                score += 20

    # Label-sourced routes for this exact container are strong
    if route.source == "label":
        name = _norm(container.get("name") or "")
        up_host, _ = _parse_upstream(route.upstream)
        if up_host and name and (up_host == name or up_host in aliases):
            score += 40
        # site label on this container without upstream still counts
        labels = container.get("labels") or {}
        for key, raw in labels.items():
            if not re.match(r"^caddy(?:_\d+)?$", str(key), re.I):
                continue
            if route.hostname and route.hostname in _norm(str(raw)):
                score += 45
                break

    # Access URL host equals route hostname
    access = hostname_from_url(container.get("access_url"))
    if access and route.hostname and (
        access == route.hostname
        or access.endswith("." + route.hostname)
        or route.hostname.endswith("." + access)
        or _first_label(access) == _first_label(route.hostname)
    ):
        score += 20

    return score


def match_route_to_containers(
    route: ProxyRoute,
    containers: list[dict[str, Any]],
) -> list[tuple[dict[str, Any], int]]:
    scored: list[tuple[dict[str, Any], int]] = []
    for c in containers:
        s = _match_score(route, c)
        if s >= 25:  # threshold: need a real signal
            scored.append((c, s))
    scored.sort(key=lambda x: -x[1])
    return scored


def enrich_networking(
    containers: list[dict[str, Any]],
    *,
    proxy_type: str,
    discovery: RouteDiscoveryResult | None,
    pihole: PiHoleResult | None,
) -> dict[str, Any]:
    """
    Mutate containers with networking join results.

    Returns a serializable networking status for the API / poll snapshot.
    """
    proxy = (proxy_type or "none").lower().strip()
    dns_hosts: set[str] = set()
    if pihole and pihole.ok and pihole.records:
        dns_hosts = {_norm(r.hostname) for r in pihole.records if r.hostname}

    # Always clear first
    for c in containers:
        c["networking"] = {"mapped": False, "entries": []}
        c["proxy_matched"] = False

    status: dict[str, Any] = {
        "proxy_type": proxy,
        "configured": proxy not in ("", "none"),
        "ok": None,
        "route_count": 0,
        "mapped_count": 0,
        "message": None,
        "errors": [],
        "sources_tried": [],
    }

    if proxy in ("", "none"):
        # Hostname-only Pi-hole correlation (legacy path)
        if pihole is not None:
            ph_status = correlate_pihole(containers, pihole)
            status["ok"] = ph_status.get("ok")
            status["message"] = "Proxy off — matching Pi-hole hostnames only"
            return {**status, "pihole": ph_status}
        for c in containers:
            c.setdefault("pihole_matched", False)
            c.setdefault("pihole_hostnames", [])
        status["ok"] = True
        status["message"] = "Proxy type is None"
        return status

    if proxy == "traefik":
        status["ok"] = False
        status["message"] = "Traefik route discovery is coming soon"
        # Still run Pi-hole hostname fallback so DNS badges keep working
        if pihole is not None:
            correlate_pihole(containers, pihole)
        return status

    if proxy != "caddy":
        status["ok"] = False
        status["message"] = f"Unknown proxy type: {proxy}"
        if pihole is not None:
            correlate_pihole(containers, pihole)
        return status

    discovery = discovery or RouteDiscoveryResult(ok=False)
    status["sources_tried"] = list(discovery.sources_tried)
    status["errors"] = list(discovery.errors)
    status["route_count"] = len(discovery.routes)

    if not discovery.routes:
        status["ok"] = False if discovery.errors else True
        status["message"] = discovery.message or "No Caddy routes discovered"
        # Fall back to hostname correlation so Pi-hole badges still appear
        if pihole is not None:
            correlate_pihole(containers, pihole)
        return status

    status["ok"] = True

    # Index routes by hostname
    routes_by_host: dict[str, list[ProxyRoute]] = {}
    for r in discovery.routes:
        routes_by_host.setdefault(r.hostname, []).append(r)

    mapped = 0
    # Prefer routes that appear in Pi-hole when DNS is configured; still map others
    host_list = list(routes_by_host.keys())
    if dns_hosts:
        # Put DNS-overlapping hosts first
        host_list.sort(key=lambda h: (0 if h in dns_hosts else 1, h))

    for hostname in host_list:
        routes = routes_by_host[hostname]
        in_dns = hostname in dns_hosts if dns_hosts else False
        for route in routes:
            matches = match_route_to_containers(route, containers)
            if not matches:
                continue
            # Assign best match; if close seconds, assign top only to avoid fan-out
            best_c, best_s = matches[0]
            assigned = [best_c]
            for other, sc in matches[1:]:
                if sc >= best_s and sc >= 50:
                    # equally strong (e.g. same service replicas) — skip extras
                    break
            for c in assigned:
                entry = {
                    "hostname": route.hostname,
                    "upstream": route.upstream or "",
                    "source": route.source,
                    "proxy": "caddy",
                    "in_dns": bool(in_dns),
                }
                net = c.setdefault("networking", {"mapped": False, "entries": []})
                entries = net.setdefault("entries", [])
                # dedupe
                if any(
                    e.get("hostname") == entry["hostname"]
                    and e.get("upstream") == entry["upstream"]
                    for e in entries
                ):
                    continue
                entries.append(entry)
                net["mapped"] = True
                c["proxy_matched"] = True
                mapped += 1

                # Keep Pi-hole badge fields in sync when the hostname is in DNS
                if in_dns:
                    hosts = list(c.get("pihole_hostnames") or [])
                    if route.hostname not in hosts:
                        hosts.append(route.hostname)
                    c["pihole_hostnames"] = sorted(set(hosts))
                    c["pihole_matched"] = True

    # Containers with DNS names that matched via fuzzy fallback when no proxy hit
    if pihole is not None and pihole.ok and pihole.records:
        unmatched = [
            c
            for c in containers
            if not (c.get("networking") or {}).get("mapped")
        ]
        if unmatched:
            # Temporary list for correlate — only fill empty ones
            correlate_pihole(unmatched, pihole)

    status["mapped_count"] = sum(
        1 for c in containers if (c.get("networking") or {}).get("mapped")
    )
    status["message"] = (
        f"{status['route_count']} routes · {status['mapped_count']} containers mapped"
    )
    return status


def _dns_record_type(kind: str, target: str) -> str:
    k = (kind or "a").strip().lower()
    if k == "cname":
        return "CNAME"
    if k in ("aaaa", "a"):
        # Hosts lines are stored as kind "a"; classify AAAA by IPv6 shape.
        t = (target or "").strip()
        if k == "aaaa" or (":" in t and not t.replace(":", "").isdigit()):
            return "AAAA"
        return "A"
    return k.upper() or "A"


def hostname_to_container_via_proxy(
    containers: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """
    Map normalized hostname → container match from networking join results.

    Only uses Caddy/proxy route assignments (running or stopped). Does not use
    fuzzy Pi-hole hostname correlation.
    """
    by_host: dict[str, dict[str, Any]] = {}
    for c in containers:
        net = c.get("networking") or {}
        if not net.get("mapped"):
            continue
        for entry in net.get("entries") or []:
            hn = _norm(str(entry.get("hostname") or ""))
            if not hn or hn in by_host:
                continue
            upstream = str(entry.get("upstream") or "")
            _host, port = _parse_upstream(upstream)
            by_host[hn] = {
                "name": c.get("name") or "",
                "container_id": c.get("container_id") or "",
                "state": c.get("state") or c.get("status") or "",
                "upstream": upstream,
                "port": port,
                "source": entry.get("source") or "",
                "proxy": entry.get("proxy") or "caddy",
                "in_dns": bool(entry.get("in_dns")),
            }
    return by_host


def build_dns_inventory(
    containers: list[dict[str, Any]],
    pihole: PiHoleResult | None,
) -> list[dict[str, Any]]:
    """
    Local DNS rows for the DNS page: domain → port → container (Caddy join).
    """
    if pihole is None or not pihole.configured or not pihole.ok:
        return []
    by_host = hostname_to_container_via_proxy(containers)
    rows: list[dict[str, Any]] = []
    for rec in pihole.records:
        hn = _norm(rec.hostname)
        match = by_host.get(hn) if hn else None
        port = (match or {}).get("port")
        rows.append(
            {
                "hostname": rec.hostname,
                "type": _dns_record_type(rec.kind, rec.target),
                "target": rec.target,
                "port": port if isinstance(port, int) else None,
                "container": (match or {}).get("name") or None,
                "container_id": (match or {}).get("container_id") or None,
                "container_state": (match or {}).get("state") or None,
                "upstream": (match or {}).get("upstream") or None,
                "route_source": (match or {}).get("source") or None,
                "proxy": (match or {}).get("proxy") or None,
            }
        )
    rows.sort(key=lambda r: (str(r.get("hostname") or ""), str(r.get("type") or "")))
    return rows


def discover_and_enrich(
    containers: list[dict[str, Any]],
    *,
    proxy_type: str,
    use_admin_api: bool = False,
    admin_url: str = "",
    use_caddyfile: bool = False,
    caddyfile_path: str = "",
    use_labels: bool = False,
    verify_tls: bool = True,
    timeout: float = 5.0,
    pihole: PiHoleResult | None = None,
) -> dict[str, Any]:
    """Run discovery (when Caddy) then join. Never raises."""
    proxy = (proxy_type or "none").lower().strip()
    discovery: RouteDiscoveryResult | None = None
    try:
        if proxy == "caddy":
            if not (use_admin_api or use_caddyfile or use_labels):
                discovery = RouteDiscoveryResult(
                    ok=False,
                    errors=[
                        "Enable at least one Caddy discovery method "
                        "(Admin API, Caddyfile, or labels)."
                    ],
                )
            else:
                discovery = discover_caddy_routes(
                    use_admin_api=use_admin_api,
                    admin_url=admin_url,
                    use_caddyfile=use_caddyfile,
                    caddyfile_path=caddyfile_path,
                    use_labels=use_labels,
                    containers=containers,
                    timeout=timeout,
                    verify_tls=verify_tls,
                )
        return enrich_networking(
            containers,
            proxy_type=proxy,
            discovery=discovery,
            pihole=pihole,
        )
    except Exception as exc:
        logger.warning("Networking enrichment failed: %s", exc)
        for c in containers:
            c.setdefault("networking", {"mapped": False, "entries": []})
            c.setdefault("proxy_matched", False)
            c.setdefault("pihole_matched", False)
            c.setdefault("pihole_hostnames", [])
        if pihole is not None:
            try:
                correlate_pihole(containers, pihole)
            except Exception:
                pass
        return {
            "proxy_type": proxy,
            "configured": proxy not in ("", "none"),
            "ok": False,
            "route_count": 0,
            "mapped_count": 0,
            "message": str(exc),
            "errors": [str(exc)],
            "sources_tried": [],
        }
