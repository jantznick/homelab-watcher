"""Inventory of host listening sockets (read-only; not a network scanner)."""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from app.config import get_settings

logger = logging.getLogger(__name__)

_TCP_LISTEN = 0x0A
_CONTAINER_ID_RE = re.compile(r"(?:docker[-/]|cri-containerd-)([0-9a-f]{12,64})")


def _hex_port(part: str) -> int | None:
    try:
        return int(part, 16)
    except ValueError:
        return None


def _ipv4_from_hex(addr_hex: str) -> str:
    """Linux /proc/net/tcp local_address: little-endian hex IPv4."""
    raw = int(addr_hex, 16)
    return ".".join(str((raw >> (8 * i)) & 0xFF) for i in range(4))


def _ipv6_from_hex(addr_hex: str) -> str:
    """Linux /proc/net/tcp6: 32 hex chars, little-endian 32-bit words."""
    if len(addr_hex) != 32:
        return addr_hex
    parts: list[str] = []
    for i in range(0, 32, 8):
        word = addr_hex[i : i + 8]
        # Each 32-bit word is little-endian byte order in the hex string.
        b = bytes.fromhex(word)
        parts.append(b[::-1].hex())
    # Collapse to canonical-ish IPv6
    hextets = []
    for p in parts:
        hextets.append(p[0:4])
        hextets.append(p[4:8])
    # Prefer compact form via stdlib when possible
    try:
        import ipaddress

        return str(ipaddress.IPv6Address(":".join(hextets)))
    except Exception:
        return ":".join(hextets)


def _classify_bind(addr: str, family: str) -> str:
    """
    localhost | all | lan

    'all' = wildcard (0.0.0.0 / ::) — reachable on every interface.
    'localhost' = loopback only.
    'lan' = specific non-loopback address (often one NIC / LAN IP).
    """
    a = (addr or "").lower().strip()
    if family == "tcp6" or ":" in a:
        if a in ("::", "0:0:0:0:0:0:0:0", "::0"):
            return "all"
        if a in ("::1",) or a.startswith("::1"):
            return "localhost"
        # IPv4-mapped ::ffff:127.0.0.1
        if a.endswith("127.0.0.1") and "ffff" in a:
            return "localhost"
        return "lan"
    if a in ("0.0.0.0", "*"):
        return "all"
    if a.startswith("127."):
        return "localhost"
    return "lan"


def _parse_proc_net(path: Path, *, family: str, proto: str) -> list[dict[str, Any]]:
    """Parse /proc/net/{tcp,tcp6,udp,udp6} into listening rows."""
    out: list[dict[str, Any]] = []
    try:
        text = path.read_text(errors="replace")
    except OSError as exc:
        logger.debug("Cannot read %s: %s", path, exc)
        return out

    lines = text.splitlines()
    if len(lines) < 2:
        return out

    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        local = parts[1]
        rem = parts[2]
        st_hex = parts[3]
        inode_s = parts[9]
        if ":" not in local:
            continue
        addr_hex, port_hex = local.rsplit(":", 1)
        port = _hex_port(port_hex)
        if port is None:
            continue
        try:
            state = int(st_hex, 16)
        except ValueError:
            continue
        try:
            inode = int(inode_s)
        except ValueError:
            inode = 0

        if proto == "tcp":
            if state != _TCP_LISTEN:
                continue
        else:
            # UDP has no LISTEN; treat unbound remote as a listening datagram socket.
            if rem.split(":")[-1].upper() != "0000":
                continue

        try:
            if family == "tcp4" or family == "udp4":
                addr = _ipv4_from_hex(addr_hex)
            else:
                addr = _ipv6_from_hex(addr_hex)
        except Exception:
            addr = addr_hex

        scope = _classify_bind(addr, family)
        out.append(
            {
                "protocol": proto,
                "family": "ipv6" if "6" in family else "ipv4",
                "port": port,
                "address": addr,
                "bind_scope": scope,
                "inode": inode,
                "pid": None,
                "process": None,
                "container": None,
            }
        )
    return out


def _inode_to_pid(host_proc: Path) -> dict[int, int]:
    """Map socket inode → pid by walking /proc/<pid>/fd (host view when mounted)."""
    mapping: dict[int, int] = {}
    try:
        entries = list(host_proc.iterdir())
    except OSError as exc:
        logger.warning("Cannot list %s for socket inodes: %s", host_proc, exc)
        return mapping

    for pid_dir in entries:
        name = pid_dir.name
        if not name.isdigit():
            continue
        fd_dir = pid_dir / "fd"
        if not fd_dir.is_dir():
            continue
        pid = int(name)
        try:
            for fd in fd_dir.iterdir():
                try:
                    target = str(fd.readlink())
                except OSError:
                    continue
                if not target.startswith("socket:["):
                    continue
                try:
                    inode = int(target[8:-1])
                except ValueError:
                    continue
                # First wins; multiple fds can share an inode
                mapping.setdefault(inode, pid)
        except OSError:
            continue
    return mapping


def _read_comm(host_proc: Path, pid: int) -> str | None:
    try:
        comm = (host_proc / str(pid) / "comm").read_text(errors="replace").strip()
        return comm or None
    except OSError:
        return None


def _read_cmdline(host_proc: Path, pid: int) -> str | None:
    try:
        raw = (host_proc / str(pid) / "cmdline").read_bytes()
        if not raw:
            return None
        parts = [p.decode("utf-8", errors="replace") for p in raw.split(b"\0") if p]
        if not parts:
            return None
        base = Path(parts[0]).name
        return base or parts[0]
    except OSError:
        return None


def _container_id_for_pid(host_proc: Path, pid: int) -> str | None:
    cgroup = host_proc / str(pid) / "cgroup"
    try:
        text = cgroup.read_text(errors="replace")
    except OSError:
        return None
    for line in text.splitlines():
        m = _CONTAINER_ID_RE.search(line)
        if m:
            cid = m.group(1)
            return cid[:12]
    return None


def _docker_name_map(containers: list[dict[str, Any]] | None) -> dict[str, str]:
    """Short container id → name from an already-fetched inventory."""
    out: dict[str, str] = {}
    if not containers:
        return out
    for c in containers:
        short = str(c.get("container_id") or "")
        full = str(c.get("container_id_full") or short)
        name = str(c.get("name") or "").lstrip("/") or short
        if short:
            out[short] = name
        if full:
            out[full] = name
            out[full[:12]] = name
    return out


def _from_psutil() -> list[dict[str, Any]]:
    """Fallback when host /proc/net is missing (e.g. macOS local venv)."""
    try:
        import socket

        import psutil
    except Exception:
        return []

    rows: list[dict[str, Any]] = []
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception as exc:
        logger.warning("psutil.net_connections failed: %s", exc)
        return []

    for c in conns:
        if getattr(c, "status", None) != "LISTEN":
            continue
        if not c.laddr:
            continue
        addr = getattr(c.laddr, "ip", None) or (c.laddr[0] if c.laddr else "")
        port = getattr(c.laddr, "port", None) or (
            c.laddr[1] if len(c.laddr) > 1 else None
        )
        if port is None:
            continue
        proto = "udp" if c.type == socket.SOCK_DGRAM else "tcp"
        family = "ipv6" if c.family == socket.AF_INET6 else "ipv4"
        scope = _classify_bind(str(addr), "tcp6" if family == "ipv6" else "tcp4")
        process = None
        if c.pid:
            try:
                process = psutil.Process(c.pid).name()
            except Exception:
                process = None
        rows.append(
            {
                "protocol": proto,
                "family": family,
                "port": int(port),
                "address": str(addr),
                "bind_scope": scope,
                "inode": None,
                "pid": c.pid,
                "process": process,
                "container": None,
            }
        )
    return rows


def _dedupe_sort(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[Any, ...]] = set()
    out: list[dict[str, Any]] = []
    for r in rows:
        key = (r.get("protocol"), r.get("family"), r.get("address"), r.get("port"))
        if key in seen:
            continue
        seen.add(key)
        clean = {k: v for k, v in r.items() if k != "inode"}
        out.append(clean)

    scope_rank = {"all": 0, "lan": 1, "localhost": 2}

    def sort_key(r: dict[str, Any]) -> tuple:
        return (
            scope_rank.get(str(r.get("bind_scope") or ""), 9),
            str(r.get("protocol") or ""),
            int(r.get("port") or 0),
            str(r.get("address") or ""),
        )

    out.sort(key=sort_key)
    return out


def collect_listening_ports(
    containers: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """
    Discover listening TCP (and UDP) sockets on the host view.

    Prefer HOST_PROC /proc/net + fd→inode attribution when available
    (Compose /:/host:ro → HOST_PROC=/host/proc). Falls back to psutil.
    Never raises — returns empty list + note on failure.
    """
    settings = get_settings()
    host_proc = Path(settings.host_proc)
    notes: list[str] = []
    source = "none"
    rows: list[dict[str, Any]] = []

    try:
        tcp = host_proc / "net" / "tcp"
        if tcp.is_file():
            source = "host_proc"
            for fname, family, proto in (
                ("tcp", "tcp4", "tcp"),
                ("tcp6", "tcp6", "tcp"),
                ("udp", "udp4", "udp"),
                ("udp6", "udp6", "udp"),
            ):
                p = host_proc / "net" / fname
                if p.is_file():
                    rows.extend(_parse_proc_net(p, family=family, proto=proto))

            inode_map = _inode_to_pid(host_proc) if rows else {}
            docker_names = _docker_name_map(containers) if rows else {}
            for r in rows:
                inode = r.get("inode")
                pid = inode_map.get(inode) if inode else None
                if pid:
                    r["pid"] = pid
                    r["process"] = _read_cmdline(host_proc, pid) or _read_comm(
                        host_proc, pid
                    )
                    cid = _container_id_for_pid(host_proc, pid)
                    if cid:
                        r["container"] = docker_names.get(cid) or cid
        else:
            rows = _from_psutil()
            if rows:
                source = "local"
                notes.append(
                    "Limited view — ports from this process only."
                )
            else:
                notes.append(
                    "Open ports unavailable without a host mount."
                )
    except Exception as exc:
        logger.warning("Listening ports collection failed: %s", exc)
        notes.append("Open ports unavailable on this host view.")
        rows = []
        source = "none"

    cleaned = _dedupe_sort(rows)
    exposed = sum(1 for r in cleaned if r.get("bind_scope") in ("all", "lan"))
    return {
        "listening_ports": cleaned,
        "listening_ports_source": source,
        "listening_ports_note": " ".join(notes) if notes else None,
        "listening_ports_exposed_count": exposed,
        "listening_ports_enabled": True,
    }
