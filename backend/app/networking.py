"""Join DNS (Pi-hole) → reverse-proxy routes → Docker containers.

Join chain only (no hostname≈container-name fuzzy matching):
  container published/external port
    → Caddy upstream port (and upstream host when present)
    → Caddy site domain
    → Pi-hole DNS A/AAAA target IP
    → host network IP
"""

from __future__ import annotations

import logging
import re
from typing import Any
from urllib.parse import urlparse

from app.caddy_routes import ProxyRoute, RouteDiscoveryResult, discover_caddy_routes
from app.container_enrich import clear_pihole_fields, pihole_status_dict
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

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _norm(s: str) -> str:
    return (s or "").strip().lower().rstrip(".")


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


def _is_ip_literal(host: str | None) -> bool:
    if not host:
        return False
    h = host.strip().lower()
    if _IPV4_RE.match(h):
        return True
    if ":" in h and not h.replace(":", "").isdigit():
        return True
    return False


def _published_host_ports(container: dict[str, Any]) -> set[int]:
    """Host-facing published ports (left side of host:port->container)."""
    ports: set[int] = set()
    for line in container.get("published_ports") or []:
        text = str(line)
        m = re.search(r":(\d+)->(\d+)", text)
        if m:
            ports.add(int(m.group(1)))
            continue
        # Bare EXPOSE-only lines are not external publishes.
    inspect = container.get("inspect") or {}
    ns = inspect.get("NetworkSettings") or {}
    for _cport, bindings in ((ns.get("Ports") or {}) or {}).items():
        if not isinstance(bindings, list):
            continue
        for b in bindings:
            if not isinstance(b, dict):
                continue
            hport = str(b.get("HostPort") or "").strip()
            if hport.isdigit():
                ports.add(int(hport))
    hc = (inspect.get("HostConfig") or {}).get("PortBindings") or {}
    for _cport, bindings in (hc or {}).items():
        if not isinstance(bindings, list):
            continue
        for b in bindings:
            if not isinstance(b, dict):
                continue
            hport = str(b.get("HostPort") or "").strip()
            if hport.isdigit():
                ports.add(int(hport))
    return ports


def _container_listen_ports(container: dict[str, Any]) -> set[int]:
    """Container-side listen/expose ports (right side of publish, EXPOSE)."""
    ports: set[int] = set()
    for line in container.get("published_ports") or []:
        text = str(line)
        m = re.search(r":(\d+)->(\d+)", text)
        if m:
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
    cfg = inspect.get("Config") or {}
    for cport in (cfg.get("ExposedPorts") or {}) or {}:
        num = str(cport).split("/", 1)[0]
        if num.isdigit():
            ports.add(int(num))
    return ports


def _network_aliases(container: dict[str, Any]) -> set[str]:
    """Exact Docker network DNS names / compose service aliases (not domain labels)."""
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
        for a in net.get("DNSNames") or []:
            na = _norm(str(a))
            if na:
                aliases.add(na)
    return aliases


def _container_ips(container: dict[str, Any]) -> set[str]:
    ips: set[str] = set()
    inspect = container.get("inspect") or {}
    ns = inspect.get("NetworkSettings") or {}
    for key in ("IPAddress", "GlobalIPv6Address"):
        raw = (ns.get(key) or "").strip()
        if raw:
            ips.add(raw.lower())
    for net in (ns.get("Networks") or {}).values():
        if not isinstance(net, dict):
            continue
        for key in ("IPAddress", "GlobalIPv6Address"):
            raw = (net.get(key) or "").strip()
            if raw:
                ips.add(raw.lower())
    return ips


def collect_host_network_ips() -> set[str]:
    """
    Host IPv4/IPv6 from host netns (/proc) when available.

    Fail-soft: never calls psutil (can abort in restricted environments).
    Empty set means DNS↔host IP checks are skipped (Caddy port join still works).
    """
    out: set[str] = set()
    try:
        from pathlib import Path

        from app.config import get_settings
        from app.host_metrics import _ipv4_from_fib_trie, _ipv6_by_iface

        host_proc = Path(get_settings().host_proc)
        net_dir = host_proc / "1" / "net"
        if not (net_dir / "dev").is_file():
            net_dir = host_proc / "net"
        if not (net_dir / "dev").is_file():
            return out
        # Inside Docker without real host netns, /host/proc/net is often the
        # container — still useful if it exposes the lab's front-door addresses.
        if (net_dir / "fib_trie").is_file():
            for ip in _ipv4_from_fib_trie(net_dir / "fib_trie"):
                a = str(ip or "").strip().lower()
                if a and not a.startswith("127."):
                    out.add(a)
        if (net_dir / "if_inet6").is_file():
            for addrs in _ipv6_by_iface(net_dir / "if_inet6").values():
                for ip in addrs:
                    a = str(ip or "").split("%")[0].strip().lower()
                    if (
                        a
                        and a != "::1"
                        and not a.startswith("fe80:")
                    ):
                        out.add(a)
    except Exception as exc:
        logger.debug("host network IPs unavailable: %s", exc)
        return set()
    return out


def _dns_a_targets_by_host(
    pihole: PiHoleResult | None,
) -> dict[str, set[str]]:
    """Normalized hostname → resolved A/AAAA target IPs (CNAME one hop)."""
    if pihole is None or not pihole.ok or not pihole.records:
        return {}
    direct: dict[str, set[str]] = {}
    cnames: dict[str, str] = {}
    for rec in pihole.records:
        hn = _norm(rec.hostname)
        if not hn:
            continue
        kind = (rec.kind or "a").strip().lower()
        target = (rec.target or "").strip()
        if not target:
            continue
        if kind == "cname":
            cnames[hn] = _norm(target)
            continue
        # a / aaaa / hosts-line
        direct.setdefault(hn, set()).add(target.lower())

    out: dict[str, set[str]] = {k: set(v) for k, v in direct.items()}
    for hn, target_hn in cnames.items():
        if target_hn in direct:
            out.setdefault(hn, set()).update(direct[target_hn])
    return out


def dns_target_matches_host(
    hostname: str,
    *,
    dns_targets: dict[str, set[str]],
    host_ips: set[str],
) -> bool:
    """True when Pi-hole A/AAAA for hostname points at a host network IP."""
    if not host_ips:
        return False
    targets = dns_targets.get(_norm(hostname)) or set()
    if not targets:
        return False
    return bool(targets & host_ips)


def _label_declares_hostname(container: dict[str, Any], hostname: str) -> bool:
    """Exact Caddy site label on this container (not fuzzy substring of name)."""
    hn = _norm(hostname)
    if not hn:
        return False
    labels = container.get("labels") or {}
    for key, raw in labels.items():
        if not re.match(r"^caddy(?:_\d+)?$", str(key), re.I):
            continue
        # Label value is the site address block — require exact host token match.
        for part in re.split(r"[\s,]+", _norm(str(raw))):
            token = part.split(":", 1)[0].strip()
            if token == hn:
                return True
    return False


def _match_score(
    route: ProxyRoute,
    container: dict[str, Any],
    *,
    host_ips: set[str],
) -> int:
    """
    Higher = better match. 0 = no match.

    Requires upstream port. Matches published host port, or docker-network
    upstream (exact alias) + container listen port. Never matches domain text
    to container/image names.
    """
    host, port = _parse_upstream(route.upstream)
    if port is None:
        # Label-only site on this container with no upstream port — still a join
        # when the Caddy label on *this* container declares the hostname.
        if route.source == "label" and _label_declares_hostname(
            container, route.hostname
        ):
            return 40
        return 0

    pub = _published_host_ports(container)
    listen = _container_listen_ports(container)
    aliases = _network_aliases(container)
    cip = _container_ips(container)
    score = 0

    port_ok = False
    if port in pub:
        score += 50
        port_ok = True
    elif host and host not in _LOCAL_UPSTREAM_HOSTS and not _is_ip_literal(host):
        # Docker-network upstream: reverse_proxy service:port
        if host in aliases and port in listen:
            score += 45
            port_ok = True
    if not port_ok:
        return 0

    if host:
        if host in _LOCAL_UPSTREAM_HOSTS:
            score += 10
        elif _is_ip_literal(host):
            h = host.lower()
            if h in cip or h in host_ips:
                score += 25
            elif h in ("0.0.0.0", "::"):
                score += 5
            else:
                # Upstream IP is neither this container nor this host — reject
                return 0
        elif host in aliases:
            score += 25
        else:
            # Named upstream that isn't this container's docker DNS name
            return 0

    if route.source == "label" and _label_declares_hostname(container, route.hostname):
        score += 20

    return score


def match_route_to_containers(
    route: ProxyRoute,
    containers: list[dict[str, Any]],
    *,
    host_ips: set[str] | None = None,
) -> list[tuple[dict[str, Any], int]]:
    ips = host_ips if host_ips is not None else collect_host_network_ips()
    scored: list[tuple[dict[str, Any], int]] = []
    for c in containers:
        s = _match_score(route, c, host_ips=ips)
        if s > 0:
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
    host_ips = collect_host_network_ips()
    dns_targets = _dns_a_targets_by_host(pihole)
    pihole_active = bool(pihole and pihole.configured and pihole.ok)

    # Always clear first — never leave fuzzy leftovers
    for c in containers:
        c["networking"] = {"mapped": False, "entries": []}
        c["proxy_matched"] = False
    clear_pihole_fields(containers)

    status: dict[str, Any] = {
        "proxy_type": proxy,
        "configured": proxy not in ("", "none"),
        "ok": None,
        "route_count": 0,
        "mapped_count": 0,
        "message": None,
        "errors": [],
        "sources_tried": [],
        "host_ip_count": len(host_ips),
    }

    if proxy in ("", "none"):
        status["ok"] = True
        status["message"] = "Proxy off — no domain↔container joins without Caddy"
        if pihole is not None:
            status["pihole"] = pihole_status_dict(pihole)
        return status

    if proxy == "traefik":
        status["ok"] = False
        status["message"] = "Traefik route discovery is coming soon"
        if pihole is not None:
            status["pihole"] = pihole_status_dict(pihole)
        return status

    if proxy != "caddy":
        status["ok"] = False
        status["message"] = f"Unknown proxy type: {proxy}"
        if pihole is not None:
            status["pihole"] = pihole_status_dict(pihole)
        return status

    discovery = discovery or RouteDiscoveryResult(ok=False)
    status["sources_tried"] = list(discovery.sources_tried)
    status["errors"] = list(discovery.errors)
    status["route_count"] = len(discovery.routes)

    if not discovery.routes:
        status["ok"] = False if discovery.errors else True
        status["message"] = discovery.message or "No Caddy routes discovered"
        if pihole is not None:
            status["pihole"] = pihole_status_dict(pihole)
        return status

    status["ok"] = True

    routes_by_host: dict[str, list[ProxyRoute]] = {}
    for r in discovery.routes:
        routes_by_host.setdefault(r.hostname, []).append(r)

    for hostname in sorted(routes_by_host.keys()):
        routes = routes_by_host[hostname]
        # DNS badge / chain step: A/AAAA must point at a host network IP.
        # If Pi-hole is up and this hostname exists in DNS with a wrong IP,
        # do not attach the domain to a container.
        dns_ips = dns_targets.get(_norm(hostname))
        if pihole_active and dns_ips is not None:
            if host_ips and not (dns_ips & host_ips):
                continue
            in_dns = bool(host_ips and (dns_ips & host_ips))
        elif pihole_active and dns_ips is None:
            # Hostname not in Pi-hole — Caddy-only mapping, no DNS badge
            in_dns = False
        else:
            in_dns = False

        for route in routes:
            matches = match_route_to_containers(
                route, containers, host_ips=host_ips
            )
            if not matches:
                continue
            best_c, best_s = matches[0]
            assigned = [best_c]
            for other, sc in matches[1:]:
                if sc >= best_s and sc >= 50:
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
                if any(
                    e.get("hostname") == entry["hostname"]
                    and e.get("upstream") == entry["upstream"]
                    for e in entries
                ):
                    continue
                entries.append(entry)
                net["mapped"] = True
                c["proxy_matched"] = True

                if in_dns:
                    hosts = list(c.get("pihole_hostnames") or [])
                    if route.hostname not in hosts:
                        hosts.append(route.hostname)
                    c["pihole_hostnames"] = sorted(set(hosts))
                    c["pihole_matched"] = True

    status["mapped_count"] = sum(
        1 for c in containers if (c.get("networking") or {}).get("mapped")
    )
    status["message"] = (
        f"{status['route_count']} routes · {status['mapped_count']} containers mapped"
    )
    if pihole is not None:
        status["pihole"] = pihole_status_dict(pihole)
    return status


def _dns_record_type(kind: str, target: str) -> str:
    k = (kind or "a").strip().lower()
    if k == "cname":
        return "CNAME"
    if k in ("aaaa", "a"):
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

    Only uses Caddy/proxy route assignments. Never fuzzy Pi-hole names.
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

    Container column is filled only from proxy join results — never fuzzy names.
    When host IPs are known, require DNS target ∈ host IPs before linking.
    """
    if pihole is None or not pihole.configured or not pihole.ok:
        return []
    by_host = hostname_to_container_via_proxy(containers)
    host_ips = collect_host_network_ips()
    dns_targets = _dns_a_targets_by_host(pihole)
    rows: list[dict[str, Any]] = []
    for rec in pihole.records:
        hn = _norm(rec.hostname)
        match = by_host.get(hn) if hn else None
        if match and host_ips:
            targets = dns_targets.get(hn) or set()
            # CNAME without resolved A, or A pointing off-host → no container link
            if not targets or not (targets & host_ips):
                match = None
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


def build_caddy_inventory(
    containers: list[dict[str, Any]],
    discovery: RouteDiscoveryResult | None,
) -> list[dict[str, Any]]:
    """
    Caddy site rows for the Caddy page: domain → upstream/port → container.
    """
    by_host = hostname_to_container_via_proxy(containers)
    routes = list(discovery.routes) if discovery and discovery.routes else []
    host_ips = collect_host_network_ips()

    if not routes:
        rows: list[dict[str, Any]] = []
        for hn, match in by_host.items():
            port = match.get("port")
            rows.append(
                {
                    "hostname": hn,
                    "upstream": match.get("upstream") or None,
                    "port": port if isinstance(port, int) else None,
                    "container": match.get("name") or None,
                    "container_id": match.get("container_id") or None,
                    "container_state": match.get("state") or None,
                    "source": match.get("source") or None,
                    "proxy": match.get("proxy") or "caddy",
                    "in_dns": bool(match.get("in_dns")),
                }
            )
        rows.sort(key=lambda r: str(r.get("hostname") or ""))
        return rows

    rows = []
    seen: set[tuple[str, str]] = set()
    for route in routes:
        hn = _norm(route.hostname)
        if not hn:
            continue
        key = (hn, route.upstream or "")
        if key in seen:
            continue
        seen.add(key)

        match = by_host.get(hn)
        if not match:
            scored = match_route_to_containers(
                route, containers, host_ips=host_ips
            )
            if scored:
                c, _ = scored[0]
                up = route.upstream or ""
                _h, port = _parse_upstream(up)
                match = {
                    "name": c.get("name") or "",
                    "container_id": c.get("container_id") or "",
                    "state": c.get("state") or c.get("status") or "",
                    "upstream": up,
                    "port": port,
                    "in_dns": False,
                }

        upstream = route.upstream or (match or {}).get("upstream") or ""
        _h, port = _parse_upstream(upstream)
        if port is None and match and isinstance(match.get("port"), int):
            port = match["port"]

        rows.append(
            {
                "hostname": route.hostname,
                "upstream": upstream or None,
                "port": port if isinstance(port, int) else None,
                "container": (match or {}).get("name") or None,
                "container_id": (match or {}).get("container_id") or None,
                "container_state": (match or {}).get("state") or None,
                "source": route.source,
                "proxy": "caddy",
                "in_dns": bool((match or {}).get("in_dns")),
            }
        )

    rows.sort(
        key=lambda r: (
            str(r.get("hostname") or ""),
            str(r.get("upstream") or ""),
        )
    )
    return rows


def discover_and_enrich(
    containers: list[dict[str, Any]],
    *,
    proxy_type: str,
    use_admin_api: bool = False,
    admin_url: str = "",
    use_caddyfile: bool = False,
    caddyfile_path: str = "",
    caddyfile_env: dict[str, str] | None = None,
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
                    caddyfile_env=caddyfile_env,
                    use_labels=use_labels,
                    containers=containers,
                    timeout=timeout,
                    verify_tls=verify_tls,
                )
        status = enrich_networking(
            containers,
            proxy_type=proxy,
            discovery=discovery,
            pihole=pihole,
        )
        if proxy == "caddy":
            status["route_rows"] = build_caddy_inventory(containers, discovery)
        else:
            status["route_rows"] = []
        return status
    except Exception as exc:
        logger.warning("Networking enrichment failed: %s", exc)
        for c in containers:
            c.setdefault("networking", {"mapped": False, "entries": []})
            c.setdefault("proxy_matched", False)
        clear_pihole_fields(containers)
        return {
            "proxy_type": proxy,
            "configured": proxy not in ("", "none"),
            "ok": False,
            "route_count": 0,
            "mapped_count": 0,
            "message": str(exc),
            "errors": [str(exc)],
            "sources_tried": [],
            "route_rows": [],
        }
