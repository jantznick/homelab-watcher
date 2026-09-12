"""Host CPU, RAM, disks, uptime/load, and network summary (df-style + /proc)."""

from __future__ import annotations

import logging
import os
import re
import time
from pathlib import Path
from typing import Any

import psutil

from app.config import AppYamlConfig, get_settings

logger = logging.getLogger(__name__)

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_SKIP_IFACE_PREFIXES = ("lo", "docker", "br-", "veth", "virbr", "tun", "tap", "cni", "flannel")

# Filesystems that clutter df output (tmp, docker internals, kernel vfs).
_SKIP_FSTYPES = frozenset(
    {
        "tmpfs",
        "devtmpfs",
        "proc",
        "sysfs",
        "cgroup",
        "cgroup2",
        "overlay",
        "squashfs",
        "ramfs",
        "devpts",
        "mqueue",
        "hugetlbfs",
        "debugfs",
        "tracefs",
        "securityfs",
        "pstore",
        "bpf",
        "nsfs",
        "rpc_pipefs",
        "fusectl",
        "configfs",
        "autofs",
        "binfmt_misc",
        "fuse.lxcfs",
        "fuse.portal",
        "efivarfs",
    }
)

_SKIP_MOUNT_PREFIXES = (
    "/var/lib/docker/",
    "/var/lib/containerd/",
    "/run/docker/",
    "/run/containerd/",
    "/snap/",
)


def _configure_host_proc() -> None:
    """Point psutil at the host's /proc when running in Docker."""
    host_proc = get_settings().host_proc
    if host_proc and Path(host_proc).is_dir():
        os.environ.setdefault("HOST_PROC", host_proc)


def host_root_available() -> bool:
    root = Path(get_settings().host_root)
    return root.is_dir()


def _map_host_path(host_path: str) -> Path:
    """
    Map a host path to the path visible inside the container.
    With /:/host mounted, host /mnt/disk1 → /host/mnt/disk1.
    Root / → /host.
    """
    settings = get_settings()
    root = Path(settings.host_root)
    if not root.is_dir():
        return Path(host_path)

    if host_path == "/":
        return root
    p = host_path if host_path.startswith("/") else f"/{host_path}"
    return root / p.lstrip("/")


def _skip_mount(fstype: str, mountpoint: str) -> bool:
    ft = (fstype or "").lower()
    if ft in _SKIP_FSTYPES or ft.startswith("fuse."):
        return True
    mp = mountpoint or ""
    if mp.startswith(_SKIP_MOUNT_PREFIXES):
        return True
    # Docker overlay workdirs sometimes appear as plain dirs
    if "/overlay2/" in mp or "/overlay/" in mp:
        return True
    return False


def _parse_proc_mounts(path: Path) -> list[dict[str, str]]:
    """Parse /proc/mounts lines → device, mountpoint, fstype."""
    out: list[dict[str, str]] = []
    try:
        text = path.read_text(errors="replace")
    except OSError as exc:
        logger.warning("Cannot read mounts %s: %s", path, exc)
        return out
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        # proc escapes spaces as \040
        device = parts[0].replace("\\040", " ")
        mountpoint = parts[1].replace("\\040", " ")
        fstype = parts[2]
        out.append({"device": device, "mountpoint": mountpoint, "fstype": fstype})
    return out


def _usage_row(
    *,
    mountpoint: str,
    device: str,
    fstype: str,
    mapped: Path,
) -> dict[str, Any] | None:
    result: dict[str, Any] = {
        "path": mountpoint,
        "mountpoint": mountpoint,
        "filesystem": device,
        "fstype": fstype,
        "mounted": False,
        "percent": None,
        "used_bytes": None,
        "total_bytes": None,
        "free_bytes": None,
        "avail_bytes": None,  # df Avail alias of free_bytes
        "error": None,
    }
    try:
        if not mapped.exists():
            result["error"] = f"path not found: {mapped}"
            return result
        usage = psutil.disk_usage(str(mapped))
        result.update(
            {
                "mounted": True,
                "percent": round(usage.percent, 1),
                "used_bytes": usage.used,
                "total_bytes": usage.total,
                "free_bytes": usage.free,
                "avail_bytes": usage.free,
            }
        )
        return result
    except Exception as exc:
        result["error"] = str(exc)
        logger.warning("Disk metrics failed for %s (%s): %s", mountpoint, mapped, exc)
        return result


def _discover_from_mounts(
    mounts_file: Path, *, path_mapper
) -> list[dict[str, Any]]:
    """Build df-style rows from a mounts table."""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for m in _parse_proc_mounts(mounts_file):
        device, mp, fstype = m["device"], m["mountpoint"], m["fstype"]
        if _skip_mount(fstype, mp):
            continue
        key = (device, mp)
        if key in seen:
            continue
        seen.add(key)
        mapped = path_mapper(mp)
        row = _usage_row(
            mountpoint=mp, device=device, fstype=fstype, mapped=mapped
        )
        if row:
            rows.append(row)
    # Prefer shorter mount points first (/, then /boot, …)
    rows.sort(key=lambda r: (r.get("path") or "").count("/"), reverse=False)
    rows.sort(key=lambda r: r.get("path") or "")
    return rows


def _discover_from_psutil() -> list[dict[str, Any]]:
    """Fallback when no /proc/mounts (e.g. macOS local venv)."""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    try:
        parts = psutil.disk_partitions(all=False)
    except Exception as exc:
        logger.warning("disk_partitions failed: %s", exc)
        return rows
    for p in parts:
        if _skip_mount(p.fstype or "", p.mountpoint or ""):
            continue
        key = (p.device or "", p.mountpoint or "")
        if key in seen:
            continue
        seen.add(key)
        row = _usage_row(
            mountpoint=p.mountpoint,
            device=p.device or p.mountpoint,
            fstype=p.fstype or "",
            mapped=Path(p.mountpoint),
        )
        if row:
            rows.append(row)
    rows.sort(key=lambda r: r.get("path") or "")
    return rows


def discover_disks() -> tuple[list[dict[str, Any]], str | None, str]:
    """
    Auto-discover filesystems like `df -h`.

    Returns (disks, note, source) where source is "host" | "local".
    When Compose mounts /:/host:ro, reads the host mount table via HOST_PROC
    and measures usage under HOST_ROOT. Otherwise falls back to this process's
    view (laptop / container rootfs) with an honest note.
    """
    settings = get_settings()
    root = Path(settings.host_root)
    host_proc = Path(settings.host_proc)

    if root.is_dir():
        mounts_file = host_proc / "mounts"
        if not mounts_file.is_file():
            # Host root present but no host proc — still measure under /host
            mounts_file = Path("/proc/mounts")
            # Only keep mounts whose visible path is under host root
            raw = _discover_from_mounts(mounts_file, path_mapper=lambda mp: Path(mp))
            filtered: list[dict[str, Any]] = []
            root_s = str(root)
            for r in raw:
                mp = r.get("path") or ""
                if mp == root_s or mp.startswith(root_s + "/"):
                    # Rewrite to host path for display
                    host_mp = "/" if mp == root_s else mp[len(root_s) :] or "/"
                    r = {**r, "path": host_mp, "mountpoint": host_mp}
                    filtered.append(r)
            if not filtered:
                # At least show host root usage
                row = _usage_row(
                    mountpoint="/",
                    device="host",
                    fstype="",
                    mapped=root,
                )
                filtered = [row] if row else []
            return filtered, None, "host"

        disks = _discover_from_mounts(
            mounts_file, path_mapper=_map_host_path
        )
        if not disks:
            row = _usage_row(
                mountpoint="/",
                device="host",
                fstype="",
                mapped=root,
            )
            disks = [row] if row else []
        return disks, None, "host"

    # Local venv / no /host mount
    disks = _discover_from_psutil()
    return disks, "Limited host view.", "local"


def _skip_iface(name: str) -> bool:
    n = (name or "").lower()
    if not n or n == "lo":
        return True
    return any(n.startswith(p) for p in _SKIP_IFACE_PREFIXES)


def _read_uptime_seconds(host_proc: Path) -> float | None:
    uptime_file = host_proc / "uptime"
    if uptime_file.is_file():
        try:
            first = uptime_file.read_text().split()[0]
            return float(first)
        except Exception as exc:
            logger.warning("uptime read failed: %s", exc)
    try:
        boot = psutil.boot_time()
        return max(0.0, time.time() - boot)
    except Exception as exc:
        logger.warning("boot_time failed: %s", exc)
        return None


def _read_load_avg(host_proc: Path) -> list[float] | None:
    loadavg = host_proc / "loadavg"
    if loadavg.is_file():
        try:
            parts = loadavg.read_text().split()
            return [round(float(parts[0]), 2), round(float(parts[1]), 2), round(float(parts[2]), 2)]
        except Exception as exc:
            logger.warning("loadavg read failed: %s", exc)
    try:
        a, b, c = os.getloadavg()
        return [round(float(a), 2), round(float(b), 2), round(float(c), 2)]
    except (OSError, AttributeError) as exc:
        logger.debug("load average unavailable: %s", exc)
        return None


def _ipv4_from_fib_trie(path: Path) -> list[str]:
    """Best-effort host-local IPv4s from /proc/net/fib_trie (/32 host LOCAL)."""
    out: list[str] = []
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return out
    in_local = False
    pending: str | None = None
    for line in lines:
        if line.strip() == "Local:":
            in_local = True
            pending = None
            continue
        if not in_local:
            continue
        if line.strip() == "Main:" or line.strip().startswith("Propagate"):
            break
        stripped = line.strip()
        if stripped.startswith("|--"):
            token = stripped[3:].strip().split()[0] if stripped[3:].strip() else ""
            pending = token if _IPV4_RE.match(token) else None
            continue
        if pending and "/32 host LOCAL" in line:
            if not pending.startswith("127.") and pending != "0.0.0.0":
                if pending not in out:
                    out.append(pending)
            pending = None
        elif pending and ("UNICAST" in line or "LOCAL" in line or "BROADCAST" in line):
            pending = None
    return out


def _ifaces_from_proc_dev(path: Path) -> list[str]:
    names: list[str] = []
    try:
        lines = path.read_text(errors="replace").splitlines()[2:]
    except OSError:
        return names
    for line in lines:
        if ":" not in line:
            continue
        name = line.split(":", 1)[0].strip()
        if _skip_iface(name):
            continue
        if name not in names:
            names.append(name)
    return names


def _ipv6_by_iface(path: Path) -> dict[str, list[str]]:
    """Parse /proc/net/if_inet6 → iface → global/unique-local addrs (skip link-local)."""
    by_iface: dict[str, list[str]] = {}
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return by_iface
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 6:
            continue
        raw, _idx, _prefix, scope, _flags, name = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]
        if _skip_iface(name):
            continue
        # scope 0x20 = link-local; skip fe80
        try:
            scope_i = int(scope, 16)
        except ValueError:
            scope_i = -1
        if scope_i == 0x20:
            continue
        if len(raw) != 32:
            continue
        groups = [raw[i : i + 4] for i in range(0, 32, 4)]
        addr = ":".join(groups)
        by_iface.setdefault(name, [])
        if addr not in by_iface[name]:
            by_iface[name].append(addr)
    return by_iface


def _collect_network_summary() -> dict[str, Any]:
    """
    Compact host NIC / IP summary. Prefer HOST_PROC when mounted; else psutil.
    """
    settings = get_settings()
    host_proc = Path(settings.host_proc)
    interfaces: list[dict[str, Any]] = []

    if (host_proc / "net" / "dev").is_file():
        names = _ifaces_from_proc_dev(host_proc / "net" / "dev")
        v6 = _ipv6_by_iface(host_proc / "net" / "if_inet6") if (host_proc / "net" / "if_inet6").is_file() else {}
        v4 = (
            _ipv4_from_fib_trie(host_proc / "net" / "fib_trie")
            if (host_proc / "net" / "fib_trie").is_file()
            else []
        )
        # Attach IPv4s to first non-virtual iface when we can't map precisely.
        primary = names[0] if names else None
        for name in names:
            addrs = list(v6.get(name) or [])
            interfaces.append({"name": name, "addresses": addrs})
        if v4:
            if primary and interfaces:
                for ip in v4:
                    if ip not in interfaces[0]["addresses"]:
                        interfaces[0]["addresses"].append(ip)
            else:
                interfaces.append({"name": "host", "addresses": list(v4)})
        return {
            "network_interfaces": interfaces,
            "network_source": "host_proc",
            "network_note": None,
        }

    # Local / container view (macOS venv, no /host mount)
    try:
        addrs_map = psutil.net_if_addrs()
    except Exception as exc:
        logger.warning("net_if_addrs failed: %s", exc)
        return {
            "network_interfaces": [],
            "network_source": "none",
            "network_note": "Network interfaces unavailable.",
        }
    for name, addrs in sorted(addrs_map.items()):
        if _skip_iface(name):
            continue
        collected: list[str] = []
        for a in addrs:
            fam = getattr(a, "family", None)
            try:
                import socket

                if fam not in (socket.AF_INET, socket.AF_INET6):
                    continue
            except Exception:
                # Fall back: skip link/MAC-looking values
                if not a.address or ":" not in a.address and not _IPV4_RE.match(a.address or ""):
                    if fam == getattr(psutil, "AF_LINK", None):
                        continue
            addr = (a.address or "").split("%")[0]
            if not addr:
                continue
            if addr.startswith("127.") or addr == "::1" or addr.lower().startswith("fe80:"):
                continue
            if addr not in collected:
                collected.append(addr)
        if collected:
            interfaces.append({"name": name, "addresses": collected})
    note = None if host_root_available() else "Limited host view."
    if host_root_available():
        note = "Container network view (not host netns)."
    return {
        "network_interfaces": interfaces,
        "network_source": "local",
        "network_note": note,
    }


def collect_host_metrics(
    yaml_cfg: AppYamlConfig,
    containers: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    _configure_host_proc()

    cpu_percent: float | None = None
    mem_percent: float | None = None
    mem_used: int | None = None
    mem_total: int | None = None
    notes: list[str] = []
    host_proc = Path(get_settings().host_proc)

    try:
        # interval=0.3 gives a real first sample (interval=None can be 0.0)
        cpu_percent = float(psutil.cpu_percent(interval=0.3))
    except Exception as exc:
        logger.warning("CPU metrics failed: %s", exc)
        notes.append("CPU metrics unavailable on this host view.")

    try:
        meminfo = host_proc / "meminfo"
        if meminfo.is_file():
            data: dict[str, int] = {}
            for line in meminfo.read_text().splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0].endswith(":"):
                    key = parts[0][:-1]
                    try:
                        data[key] = int(parts[1]) * 1024  # kB → bytes
                    except ValueError:
                        pass
            mem_total = data.get("MemTotal", 0) or None
            available = data.get("MemAvailable", data.get("MemFree", 0))
            if mem_total:
                mem_used = max(0, mem_total - (available or 0))
                mem_percent = round((mem_used / mem_total) * 100, 1)
        else:
            vm = psutil.virtual_memory()
            mem_percent = float(vm.percent)
            mem_used = int(vm.used)
            mem_total = int(vm.total)
            if not host_root_available():
                notes.append("Limited host view.")
    except Exception as exc:
        logger.warning("Memory metrics failed: %s", exc)
        notes.append("Memory metrics unavailable on this host view.")

    uptime_seconds = _read_uptime_seconds(host_proc)
    load_avg = _read_load_avg(host_proc)

    try:
        net = _collect_network_summary()
    except Exception as exc:
        logger.warning("Network summary skipped: %s", exc)
        net = {
            "network_interfaces": [],
            "network_source": "none",
            "network_note": "Network interfaces unavailable.",
        }

    disks, disk_note, disk_source = discover_disks()
    if disk_note:
        notes.append(disk_note)

    selected = [str(p).strip() for p in (yaml_cfg.thresholds.disks or []) if str(p).strip()]
    selection_needed = not selected
    if selection_needed:
        disks = []
        # UI shows its own short CTA; keep host_note free of disk essays.
    else:
        selected_set = set(selected)
        disks = [
            d
            for d in disks
            if (d.get("path") or d.get("mountpoint") or "") in selected_set
        ]

    primary = next((d for d in disks if d.get("mounted") and d.get("path") == "/"), None)
    if primary is None:
        primary = next((d for d in disks if d.get("mounted")), None) or {}

    out: dict[str, Any] = {
        "cpu_percent": cpu_percent,
        "mem_percent": mem_percent,
        "mem_used_bytes": mem_used,
        "mem_total_bytes": mem_total,
        "disk_percent": primary.get("percent"),
        "disk_used_bytes": primary.get("used_bytes"),
        "disk_total_bytes": primary.get("total_bytes"),
        "disks": disks,
        "disk_warn_percent": yaml_cfg.thresholds.disk_warn_percent,
        "disk_source": disk_source,
        "disk_selection_needed": selection_needed,
        "host_note": " ".join(notes) if notes else None,
        "host_root_mounted": host_root_available(),
        "uptime_seconds": uptime_seconds,
        "load_avg": load_avg,
        **net,
    }

    # Listening ports — fail-soft, optional via Settings.
    try:
        from app.listening_ports import collect_listening_ports

        ports_cfg = getattr(yaml_cfg, "listening_ports", None)
        enabled = True if ports_cfg is None else bool(ports_cfg.enabled)
        if enabled:
            out.update(collect_listening_ports(containers=containers))
        else:
            out.update(
                {
                    "listening_ports": [],
                    "listening_ports_source": None,
                    "listening_ports_note": None,
                    "listening_ports_exposed_count": 0,
                    "listening_ports_enabled": False,
                }
            )
    except Exception as exc:
        logger.warning("Listening ports skipped: %s", exc)
        out.update(
            {
                "listening_ports": [],
                "listening_ports_source": "none",
                "listening_ports_note": "Open ports unavailable on this host view.",
                "listening_ports_exposed_count": 0,
                "listening_ports_enabled": True,
            }
        )

    return out
