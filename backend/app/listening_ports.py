"""Inventory of host listening sockets (read-only; not a network scanner).

Reads the *host* network namespace via ``{HOST_PROC}/1/net/{tcp,…}`` when
``/:/host:ro`` is mounted (Compose ``HOST_PROC=/host/proc``).

Important: ``{HOST_PROC}/net/tcp`` is *not* reliable from inside a container —
Linux ``/proc/net`` follows the reader's netns, so that path often shows only
the Watcher container's own listeners. We never treat that as the host view.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any

from app.config import get_settings

logger = logging.getLogger(__name__)

_TCP_LISTEN = 0x0A
_CONTAINER_ID_RE = re.compile(r"(?:docker[-/]|cri-containerd-)([0-9a-f]{12,64})")

# Short honest copy when host netns sockets are unavailable.
_NOTE_MOUNT = (
    "Host listening ports need /:/host:ro and HOST_PROC=/host/proc "
    "(reads host PID 1 netns)."
)
_NOTE_LIMITED = "Host listening ports unavailable — container-local view only."


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
    """Parse /proc/.../net/{tcp,tcp6,udp,udp6} into listening rows."""
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


def _file_fingerprint(path: Path) -> tuple[int, int] | None:
    """Size + mtime_ns fingerprint to compare proc net tables without parsing."""
    try:
        st = path.stat()
        return (int(st.st_size), int(getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))))
    except OSError:
        return None


def _same_net_table(a: Path, b: Path) -> bool:
    """True when two tcp tables look identical (same netns view)."""
    fa, fb = _file_fingerprint(a), _file_fingerprint(b)
    if fa is None or fb is None:
        return False
    if fa == fb:
        return True
    try:
        return a.read_bytes() == b.read_bytes()
    except OSError:
        return False


def _resolve_host_net_dir(host_proc: Path) -> tuple[Path | None, str | None]:
    """
    Locate a ``…/net`` directory for the *host* network namespace.

    Prefer ``{HOST_PROC}/1/net`` (host PID 1). Reject ``{HOST_PROC}/net`` when it
    matches this process's ``/proc/self/net`` (container-local view).
    """
    self_tcp = Path("/proc/self/net/tcp")
    pid1_net = host_proc / "1" / "net"
    pid1_tcp = pid1_net / "tcp"

    if pid1_tcp.is_file():
        # If PID 1's table matches our own, we are likely on the host already
        # (bare metal / host network mode) — still valid host listeners.
        return pid1_net, None

    # Bare-metal / local venv: HOST_PROC often is /proc and /proc/1/net may be
    # unreadable; /proc/net is fine *only* when it is not a foreign container
    # mount that still mirrors self.
    generic_net = host_proc / "net"
    generic_tcp = generic_net / "tcp"
    if not generic_tcp.is_file():
        return None, _NOTE_MOUNT

    if self_tcp.is_file() and _same_net_table(generic_tcp, self_tcp):
        # Same table as this process — only OK when host_proc is the real /proc
        # (we are not in an isolated container netns, or we *are* the host).
        # Inside Docker without host PID 1 access this is misleading — refuse.
        dockerenv = Path("/.dockerenv").exists()
        in_container_cgroup = False
        try:
            cg = Path("/proc/self/cgroup").read_text(errors="replace")
            in_container_cgroup = "docker" in cg or "containerd" in cg or "kubepods" in cg
        except OSError:
            pass
        if dockerenv or in_container_cgroup:
            return None, _NOTE_LIMITED
        return generic_net, None

    # Different from self — treat as host view (unusual layouts).
    return generic_net, None


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
    Discover listening TCP/UDP sockets on the **host** network namespace.

    Uses ``{HOST_PROC}/1/net/*`` (Compose ``HOST_PROC=/host/proc`` with
    ``/:/host:ro``). Never silently returns container-local listeners as host
    ports — when the host netns is unavailable, returns an empty list and a
    short note.
    """
    settings = get_settings()
    host_proc = Path(settings.host_proc)
    notes: list[str] = []
    source = "none"
    rows: list[dict[str, Any]] = []

    try:
        if not host_proc.is_dir():
            notes.append(_NOTE_MOUNT)
        else:
            net_dir, resolve_note = _resolve_host_net_dir(host_proc)
            if net_dir is None:
                notes.append(resolve_note or _NOTE_MOUNT)
            else:
                tcp = net_dir / "tcp"
                if not tcp.is_file():
                    notes.append(_NOTE_MOUNT)
                else:
                    source = "host_proc"
                    for fname, family, proto in (
                        ("tcp", "tcp4", "tcp"),
                        ("tcp6", "tcp6", "tcp"),
                        ("udp", "udp4", "udp"),
                        ("udp6", "udp6", "udp"),
                    ):
                        p = net_dir / fname
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
    except Exception as exc:
        logger.warning("Listening ports collection failed: %s", exc)
        notes.append("Host listening ports unavailable.")
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
