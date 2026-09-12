"""OpenSCA SCM dependency scans — discover repo URL, shallow clone, fail-soft."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

from app import db
from app.config import OpenSCAConfig, SecurityConfig, get_settings

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
_LEVEL_TO_SEV = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}

# Label keys checked in order (first usable git-like URL wins after overrides).
_SOURCE_LABELS = (
    "org.opencontainers.image.source",
    "org.label-schema.vcs-url",
    "vcs-url",
    "org.opencontainers.image.url",
)

_GIT_HOST_HINT = re.compile(
    r"(github\.com|gitlab\.com|bitbucket\.org|codeberg\.org|gitea\.|"
    r"git\.sr\.ht|raw\.githubusercontent\.com|dev\.azure\.com)",
    re.I,
)


def opensca_available() -> bool:
    return shutil.which("opensca-cli") is not None


def git_available() -> bool:
    return shutil.which("git") is not None


def _empty_counts() -> dict[str, int]:
    return {k: 0 for k in _SEVERITY_ORDER}


def _cache_fresh(scanned_at: str, hours: float) -> bool:
    try:
        dt = datetime.fromisoformat(scanned_at)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - dt).total_seconds()
        return age < hours * 3600
    except Exception:
        return False


def _looks_like_git_url(url: str) -> bool:
    u = (url or "").strip()
    if not u:
        return False
    if u.startswith("git@") or u.startswith("ssh://git@"):
        return True
    if u.startswith("git://"):
        return True
    if not (u.startswith("http://") or u.startswith("https://")):
        # bare github.com/org/repo
        if _GIT_HOST_HINT.search(u) and "/" in u:
            return True
        return False
    parsed = urlparse(u)
    host = (parsed.hostname or "").lower()
    path = (parsed.path or "").strip("/")
    if not host or not path:
        return False
    if _GIT_HOST_HINT.search(host):
        # Prefer repo-shaped paths (owner/repo), allow .git
        parts = [p for p in path.split("/") if p]
        if len(parts) >= 2:
            return True
    # Generic: path ends with .git
    if path.endswith(".git"):
        return True
    return False


def normalize_repo_url(raw: str) -> str | None:
    """Normalize a discovered URL to an https clone URL when possible."""
    u = (raw or "").strip().rstrip("/")
    if not u or not _looks_like_git_url(u):
        return None
    if u.startswith("git@"):
        # git@host:owner/repo(.git)
        m = re.match(r"git@([^:]+):(.+)$", u)
        if not m:
            return None
        host, path = m.group(1), m.group(2)
        if not path.endswith(".git"):
            path = path + ".git"
        return f"https://{host}/{path}"
    if u.startswith("ssh://git@"):
        rest = u[len("ssh://git@") :]
        if "/" not in rest:
            return None
        host, path = rest.split("/", 1)
        if not path.endswith(".git"):
            path = path + ".git"
        return f"https://{host}/{path}"
    if not u.startswith("http://") and not u.startswith("https://"):
        u = "https://" + u
    parsed = urlparse(u)
    path = (parsed.path or "").rstrip("/")
    if path.endswith(".git"):
        pass
    elif path:
        # Drop tree/blob fragments from browse URLs
        path = re.sub(r"/(tree|blob|src|commit)/.*$", "", path)
        if not path.endswith(".git"):
            path = path + ".git"
    cleaned = urlunparse(
        (parsed.scheme or "https", parsed.netloc, path, "", "", "")
    )
    return cleaned.rstrip("/")


def discover_scm_url(
    container: dict[str, Any],
    opensca_cfg: OpenSCAConfig,
) -> tuple[str | None, str | None]:
    """
    Return (normalized_repo_url, discovery_source) or (None, None).
    Overrides in settings take precedence; no hardcoded user repos.
    """
    name = (container.get("name") or "").strip()
    image = (container.get("image") or "").strip()
    overrides = opensca_cfg.scm_overrides or {}
    for key in (name, image):
        if key and key in overrides:
            norm = normalize_repo_url(str(overrides[key]))
            if norm:
                return norm, "override"

    labels = dict(container.get("labels") or {})
    # Also inspect Config.Labels if present
    inspect = container.get("inspect") or {}
    cfg_labels = (inspect.get("Config") or {}).get("Labels") or {}
    if isinstance(cfg_labels, dict):
        for k, v in cfg_labels.items():
            labels.setdefault(k, v)

    for key in _SOURCE_LABELS:
        raw = labels.get(key)
        if not raw:
            continue
        # image.url often points at a homepage — only accept git-shaped URLs
        if key == "org.opencontainers.image.url" and not _looks_like_git_url(str(raw)):
            continue
        norm = normalize_repo_url(str(raw))
        if norm:
            return norm, key

    # Compose / misc: any label whose key ends with source/vcs-url
    for key, raw in labels.items():
        lk = str(key).lower()
        if not (lk.endswith(".source") or lk.endswith(".vcs-url") or lk.endswith("vcsurl")):
            continue
        if key in _SOURCE_LABELS:
            continue
        norm = normalize_repo_url(str(raw))
        if norm:
            return norm, key

    return None, None


def discover_revision(container: dict[str, Any]) -> str | None:
    labels = dict(container.get("labels") or {})
    inspect = container.get("inspect") or {}
    cfg_labels = (inspect.get("Config") or {}).get("Labels") or {}
    if isinstance(cfg_labels, dict):
        for k, v in cfg_labels.items():
            labels.setdefault(k, v)
    for key in (
        "org.opencontainers.image.revision",
        "org.label-schema.vcs-ref",
    ):
        rev = (labels.get(key) or "").strip()
        if rev and re.fullmatch(r"[0-9a-fA-F]{7,40}", rev):
            return rev.lower()
    return None


def _resolve_git_token(opensca_cfg: OpenSCAConfig) -> str:
    tok = (opensca_cfg.git_token or "").strip()
    if tok:
        return tok
    settings = get_settings()
    return (settings.git_token or settings.scm_token or "").strip()


def _authed_url(repo_url: str, token: str) -> str:
    if not token:
        return repo_url
    parsed = urlparse(repo_url)
    if parsed.scheme not in ("http", "https"):
        return repo_url
    # x-access-token works for GitHub; generic user:token for others
    netloc = f"x-access-token:{token}@{parsed.hostname}"
    if parsed.port:
        netloc += f":{parsed.port}"
    return urlunparse((parsed.scheme, netloc, parsed.path, "", "", ""))


def _repo_workdir(clone_dir: str, repo_url: str) -> Path:
    digest = hashlib.sha256(repo_url.encode("utf-8")).hexdigest()[:16]
    return Path(clone_dir) / digest


def _run_git(args: list[str], *, cwd: Path | None = None, timeout: float = 120.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0"},
    )


def ensure_shallow_checkout(
    repo_url: str,
    *,
    clone_dir: str,
    token: str,
    preferred_rev: str | None,
    timeout: float,
) -> tuple[Path | None, str | None, str | None]:
    """
    Shallow clone/fetch into cache. Returns (workdir, commit_sha, error).
    Read-only: never push.
    """
    if not git_available():
        return None, None, "git not installed (Compose image includes git)"

    work = _repo_workdir(clone_dir, repo_url)
    work.parent.mkdir(parents=True, exist_ok=True)
    remote = _authed_url(repo_url, token)
    try:
        if not (work / ".git").is_dir():
            if work.exists():
                shutil.rmtree(work, ignore_errors=True)
            proc = _run_git(
                [
                    "clone",
                    "--depth",
                    "1",
                    "--single-branch",
                    remote,
                    str(work),
                ],
                timeout=timeout,
            )
            if proc.returncode != 0:
                err = (proc.stderr or proc.stdout or "git clone failed").strip()
                # Strip token from error if echoed
                if token:
                    err = err.replace(token, "***")
                return None, None, err[:500]
        else:
            # Update remote URL (token may have changed) then fetch
            _run_git(["remote", "set-url", "origin", remote], cwd=work, timeout=30.0)
            proc = _run_git(
                ["fetch", "--depth", "1", "origin"],
                cwd=work,
                timeout=timeout,
            )
            if proc.returncode != 0:
                err = (proc.stderr or proc.stdout or "git fetch failed").strip()
                if token:
                    err = err.replace(token, "***")
                # Keep existing checkout if fetch fails but we have a commit
                head = _run_git(["rev-parse", "HEAD"], cwd=work, timeout=30.0)
                if head.returncode != 0:
                    return None, None, err[:500]
            else:
                _run_git(
                    ["reset", "--hard", "FETCH_HEAD"],
                    cwd=work,
                    timeout=60.0,
                )

        if preferred_rev:
            # Best-effort: fetch that commit (may fail on shallow clone)
            _run_git(
                ["fetch", "--depth", "1", "origin", preferred_rev],
                cwd=work,
                timeout=timeout,
            )
            chk = _run_git(["checkout", "--force", preferred_rev], cwd=work, timeout=60.0)
            if chk.returncode != 0:
                logger.info(
                    "Could not checkout preferred rev %s for %s; using HEAD",
                    preferred_rev,
                    repo_url,
                )

        head = _run_git(["rev-parse", "HEAD"], cwd=work, timeout=30.0)
        if head.returncode != 0:
            return None, None, "could not resolve HEAD"
        commit = (head.stdout or "").strip().lower()
        return work, commit, None
    except subprocess.TimeoutExpired:
        return None, None, "git clone/fetch timed out"
    except Exception as exc:
        logger.warning("SCM checkout failed for %s: %s", repo_url, exc)
        return None, None, str(exc)[:500]


def _walk_opensca_nodes(node: Any) -> list[dict[str, Any]]:
    """Flatten OpenSCA DepDetailGraph JSON into vulnerability findings."""
    findings: list[dict[str, Any]] = []
    if not isinstance(node, dict):
        return findings
    pkg = node.get("name") or ""
    version = node.get("version") or ""
    for vuln in node.get("vulnerabilities") or []:
        if not isinstance(vuln, dict):
            continue
        level = vuln.get("security_level_id")
        try:
            sev = _LEVEL_TO_SEV.get(int(level), "UNKNOWN")
        except (TypeError, ValueError):
            sev = "UNKNOWN"
        vid = (
            vuln.get("cve_id")
            or vuln.get("id")
            or vuln.get("cnnvd_id")
            or vuln.get("cnvd_id")
            or "?"
        )
        title = (
            vuln.get("name")
            or vuln.get("description_en")
            or vuln.get("description")
            or ""
        )
        findings.append(
            {
                "id": str(vid),
                "severity": sev,
                "pkg": pkg,
                "installed": version,
                "fixed": "",
                "title": str(title)[:160],
                "source": "opensca",
            }
        )
    for child in node.get("children") or []:
        findings.extend(_walk_opensca_nodes(child))
    return findings


def _parse_opensca_json(payload: Any, top_n: int) -> tuple[dict[str, int], list[dict[str, Any]]]:
    counts = _empty_counts()
    # Report root is the dependency graph object
    root = payload
    if isinstance(payload, list) and payload:
        root = payload[0]
    findings = _walk_opensca_nodes(root if isinstance(root, dict) else {})
    # Dedup by id+pkg
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for f in findings:
        key = f"{f.get('id')}|{f.get('pkg')}"
        if key in seen:
            continue
        seen.add(key)
        unique.append(f)
        sev = str(f.get("severity") or "UNKNOWN").upper()
        if sev not in counts:
            sev = "UNKNOWN"
        counts[sev] = counts.get(sev, 0) + 1

    rank = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    unique.sort(key=lambda f: rank.get(str(f.get("severity")), 99))
    return counts, unique[: max(1, top_n)]


def _cache_key(repo_url: str, commit_sha: str) -> str:
    return f"{repo_url}@{commit_sha}"


def scan_repo(
    repo_url: str,
    commit_sha: str,
    workdir: Path,
    opensca_cfg: OpenSCAConfig,
    *,
    scm_source: str | None,
) -> dict[str, Any]:
    """Run OpenSCA-cli on workdir. Never raises."""
    key = _cache_key(repo_url, commit_sha)
    if not opensca_available():
        result = {
            "cache_key": key,
            "repo_url": repo_url,
            "commit_sha": commit_sha,
            "status": "unavailable",
            "error": (
                "OpenSCA-cli not installed. The Compose Docker image includes it; "
                "a local venv does not unless you install opensca-cli yourself."
            ),
            "severity": _empty_counts(),
            "top_findings": [],
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "scm_source": scm_source,
        }
        db.set_scm_scan(result)
        return result

    out_dir = Path(tempfile.mkdtemp(prefix="opensca-"))
    out_json = out_dir / "report.json"
    try:
        cmd = [
            "opensca-cli",
            "-path",
            str(workdir),
            "-out",
            str(out_json),
        ]
        token = (opensca_cfg.opensca_token or "").strip()
        if token:
            cmd.extend(["-token", token])

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=max(30.0, opensca_cfg.timeout_seconds + 30.0),
            check=False,
            cwd=str(workdir),
        )
        if not out_json.is_file():
            err = (proc.stderr or proc.stdout or f"exit {proc.returncode}").strip()
            result = {
                "cache_key": key,
                "repo_url": repo_url,
                "commit_sha": commit_sha,
                "status": "error",
                "error": (err or "OpenSCA produced no report")[:500],
                "severity": _empty_counts(),
                "top_findings": [],
                "scanned_at": datetime.now(timezone.utc).isoformat(),
                "scm_source": scm_source,
            }
            db.set_scm_scan(result)
            return result

        try:
            payload = json.loads(out_json.read_text(encoding="utf-8", errors="replace"))
        except Exception as exc:
            result = {
                "cache_key": key,
                "repo_url": repo_url,
                "commit_sha": commit_sha,
                "status": "error",
                "error": f"invalid OpenSCA JSON: {exc}"[:500],
                "severity": _empty_counts(),
                "top_findings": [],
                "scanned_at": datetime.now(timezone.utc).isoformat(),
                "scm_source": scm_source,
            }
            db.set_scm_scan(result)
            return result

        counts, top = _parse_opensca_json(payload, opensca_cfg.top_findings)
        result = {
            "cache_key": key,
            "repo_url": repo_url,
            "commit_sha": commit_sha,
            "status": "ok",
            "error": None,
            "severity": counts,
            "top_findings": top,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "scm_source": scm_source,
        }
        db.set_scm_scan(result)
        return result
    except subprocess.TimeoutExpired:
        result = {
            "cache_key": key,
            "repo_url": repo_url,
            "commit_sha": commit_sha,
            "status": "error",
            "error": "OpenSCA scan timed out",
            "severity": _empty_counts(),
            "top_findings": [],
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "scm_source": scm_source,
        }
        db.set_scm_scan(result)
        return result
    except Exception as exc:
        logger.warning("OpenSCA scan failed for %s: %s", repo_url, exc)
        result = {
            "cache_key": key,
            "repo_url": repo_url,
            "commit_sha": commit_sha,
            "status": "error",
            "error": str(exc)[:500],
            "severity": _empty_counts(),
            "top_findings": [],
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "scm_source": scm_source,
        }
        db.set_scm_scan(result)
        return result
    finally:
        shutil.rmtree(out_dir, ignore_errors=True)


def _result_from_cached(
    cached: dict[str, Any],
    *,
    stale: bool = False,
) -> dict[str, Any]:
    out = {
        "cache_key": cached.get("cache_key"),
        "repo_url": cached.get("repo_url"),
        "commit_sha": cached.get("commit_sha"),
        "status": cached.get("status") or "ok",
        "error": cached.get("error"),
        "severity": cached.get("severity") or _empty_counts(),
        "top_findings": cached.get("top_findings") or [],
        "scanned_at": cached.get("scanned_at"),
        "scm_source": cached.get("scm_source"),
        "from_cache": True,
    }
    if stale:
        out["stale"] = True
    return out


def get_or_scan_scm(
    container: dict[str, Any],
    opensca_cfg: OpenSCAConfig,
    *,
    allow_scan: bool,
) -> dict[str, Any]:
    repo_url, scm_source = discover_scm_url(container, opensca_cfg)
    if not repo_url:
        return {
            "status": "skipped",
            "error": None,
            "severity": _empty_counts(),
            "top_findings": [],
            "repo_url": None,
            "commit_sha": None,
            "scm_source": None,
            "scanned_at": None,
            "from_cache": False,
        }

    preferred = discover_revision(container)
    # Provisional key before clone: URL only — we refine after commit known.
    # Look for any fresh cache for this URL+preferred, else URL+any via pending logic.
    token = _resolve_git_token(opensca_cfg)

    if not allow_scan:
        # Try preferred commit cache, then any recent for this URL is hard — skip
        if preferred:
            cached = db.get_scm_scan(_cache_key(repo_url, preferred))
            if cached:
                return _result_from_cached(cached, stale=not _cache_fresh(
                    cached.get("scanned_at") or "", opensca_cfg.scan_interval_hours
                ))
        return {
            "status": "pending",
            "error": None,
            "severity": _empty_counts(),
            "top_findings": [],
            "repo_url": repo_url,
            "commit_sha": preferred,
            "scm_source": scm_source,
            "scanned_at": None,
            "from_cache": False,
        }

    workdir, commit, err = ensure_shallow_checkout(
        repo_url,
        clone_dir=opensca_cfg.clone_dir,
        token=token,
        preferred_rev=preferred,
        timeout=max(60.0, opensca_cfg.timeout_seconds),
    )
    if err or not workdir or not commit:
        result = {
            "cache_key": _cache_key(repo_url, preferred or "unknown"),
            "repo_url": repo_url,
            "commit_sha": preferred,
            "status": "error",
            "error": err or "clone failed",
            "severity": _empty_counts(),
            "top_findings": [],
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "scm_source": scm_source,
            "from_cache": False,
        }
        # Don't poison long-lived cache for transient clone errors on unknown commit
        return result

    key = _cache_key(repo_url, commit)
    cached = db.get_scm_scan(key)
    if cached and _cache_fresh(
        cached.get("scanned_at") or "", opensca_cfg.scan_interval_hours
    ):
        return _result_from_cached(cached)

    result = scan_repo(
        repo_url, commit, workdir, opensca_cfg, scm_source=scm_source
    )
    result["from_cache"] = False
    return result


def enrich_scm_scans_for_containers(
    containers: list[dict[str, Any]],
    security: SecurityConfig,
) -> None:
    """
    Attach scm_scan summaries onto containers.
    At most max_scans_per_poll new clones/scans per poll.
    """
    if not security.enabled or not security.opensca.enabled:
        for c in containers:
            c["scm_scan"] = {
                "status": "disabled",
                "severity": _empty_counts(),
                "top_findings": [],
            }
        return

    cfg = security.opensca
    # Unique repos that need work
    pending_urls: list[str] = []
    seen_urls: set[str] = set()
    url_by_container: dict[int, tuple[str, str | None]] = {}

    for i, c in enumerate(containers):
        repo_url, src = discover_scm_url(c, cfg)
        if not repo_url:
            continue
        url_by_container[i] = (repo_url, src)
        if repo_url in seen_urls:
            continue
        seen_urls.add(repo_url)
        preferred = discover_revision(c)
        needs = True
        if preferred:
            cached = db.get_scm_scan(_cache_key(repo_url, preferred))
            if cached and _cache_fresh(
                cached.get("scanned_at") or "", cfg.scan_interval_hours
            ):
                needs = False
        if needs:
            pending_urls.append(repo_url)

    budget = max(0, int(cfg.max_scans_per_poll))
    urls_to_scan = set(pending_urls[:budget])

    by_url: dict[str, dict[str, Any]] = {}
    for i, c in enumerate(containers):
        info = url_by_container.get(i)
        if not info:
            c["scm_scan"] = {
                "status": "skipped",
                "error": None,
                "severity": _empty_counts(),
                "top_findings": [],
                "repo_url": None,
                "commit_sha": None,
                "scm_source": None,
            }
            continue
        repo_url, _src = info
        if repo_url not in by_url:
            # If we have a fresh preferred-commit cache, serve without scanning
            preferred = discover_revision(c)
            served = False
            if preferred:
                cached = db.get_scm_scan(_cache_key(repo_url, preferred))
                if cached and _cache_fresh(
                    cached.get("scanned_at") or "", cfg.scan_interval_hours
                ):
                    by_url[repo_url] = _result_from_cached(cached)
                    served = True
            if not served:
                by_url[repo_url] = get_or_scan_scm(
                    c, cfg, allow_scan=repo_url in urls_to_scan
                )
        c["scm_scan"] = by_url[repo_url]
