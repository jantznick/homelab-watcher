"""SQLite schema, snapshots, settings, watched containers, notes, and scan cache."""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from app.config import get_settings

_lock = threading.Lock()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    path = Path(get_settings().database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    with _lock:
        conn = _connect()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def init_db() -> None:
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS container_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                taken_at TEXT NOT NULL,
                container_id TEXT NOT NULL,
                name TEXT NOT NULL,
                image TEXT,
                image_id TEXT,
                status TEXT,
                state TEXT,
                started_at TEXT,
                restart_count INTEGER DEFAULT 0,
                update_available INTEGER DEFAULT 0,
                local_digest TEXT,
                remote_digest TEXT,
                raw_json TEXT
            );

            CREATE TABLE IF NOT EXISTS host_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                taken_at TEXT NOT NULL,
                cpu_percent REAL,
                mem_percent REAL,
                mem_used_bytes INTEGER,
                mem_total_bytes INTEGER,
                disk_percent REAL,
                disk_used_bytes INTEGER,
                disk_total_bytes INTEGER,
                raw_json TEXT
            );

            CREATE TABLE IF NOT EXISTS check_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                taken_at TEXT NOT NULL,
                name TEXT NOT NULL,
                check_type TEXT NOT NULL,
                ok INTEGER NOT NULL,
                latency_ms REAL,
                message TEXT,
                detail_json TEXT
            );

            CREATE TABLE IF NOT EXISTS registry_cache (
                image_ref TEXT PRIMARY KEY,
                remote_digest TEXT,
                checked_at TEXT NOT NULL,
                error TEXT
            );

            CREATE TABLE IF NOT EXISTS digest_state (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                last_sent_at TEXT,
                last_kind TEXT,
                last_summary TEXT
            );

            INSERT OR IGNORE INTO digest_state (id, last_sent_at, last_kind, last_summary)
            VALUES (1, NULL, NULL, NULL);

            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS vital_containers (
                vital_key TEXT PRIMARY KEY,
                name TEXT,
                compose_project TEXT,
                compose_service TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS image_scan_cache (
                image_key TEXT PRIMARY KEY,
                image_ref TEXT,
                scanned_at TEXT NOT NULL,
                status TEXT,
                error TEXT,
                severity_json TEXT,
                findings_json TEXT
            );

            CREATE TABLE IF NOT EXISTS scm_scan_cache (
                cache_key TEXT PRIMARY KEY,
                repo_url TEXT,
                commit_sha TEXT,
                scanned_at TEXT NOT NULL,
                status TEXT,
                error TEXT,
                severity_json TEXT,
                findings_json TEXT,
                scm_source TEXT
            );

            CREATE TABLE IF NOT EXISTS container_notes (
                watched_key TEXT PRIMARY KEY,
                description TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_containers_taken ON container_snapshots(taken_at);
            CREATE INDEX IF NOT EXISTS idx_host_taken ON host_snapshots(taken_at);
            CREATE INDEX IF NOT EXISTS idx_checks_taken ON check_results(taken_at);
            CREATE INDEX IF NOT EXISTS idx_checks_name ON check_results(name, taken_at);
            """
        )


# --- app settings (JSON blobs keyed by section) ---

def get_setting(key: str) -> dict[str, Any] | list[Any] | None:
    with db() as conn:
        row = conn.execute(
            "SELECT value_json FROM app_settings WHERE key = ?", (key,)
        ).fetchone()
    if not row:
        return None
    try:
        return json.loads(row["value_json"])
    except Exception:
        return None


def set_setting(key: str, value: dict[str, Any] | list[Any]) -> None:
    with db() as conn:
        conn.execute(
            """
            INSERT INTO app_settings (key, value_json, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value_json = excluded.value_json,
                updated_at = excluded.updated_at
            """,
            (key, json.dumps(value), _utc_now()),
        )


def delete_setting(key: str) -> None:
    with db() as conn:
        conn.execute("DELETE FROM app_settings WHERE key = ?", (key,))


def list_setting_keys() -> list[str]:
    with db() as conn:
        rows = conn.execute("SELECT key FROM app_settings ORDER BY key").fetchall()
    return [r["key"] for r in rows]


# --- watched containers (table name vital_containers kept for migration sanity) ---

def _watched_row(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize DB row to watched_* fields (+ vital_* dual-read aliases)."""
    key = row.get("vital_key") or row.get("watched_key")
    out = {
        "watched_key": key,
        "name": row.get("name"),
        "compose_project": row.get("compose_project"),
        "compose_service": row.get("compose_service"),
        "created_at": row.get("created_at"),
        # One-release aliases
        "vital_key": key,
    }
    return out


def list_watched_containers() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM vital_containers ORDER BY name COLLATE NOCASE"
        ).fetchall()
    return [_watched_row(dict(r)) for r in rows]


def set_watched_container(
    watched_key: str,
    *,
    name: str | None = None,
    compose_project: str | None = None,
    compose_service: str | None = None,
) -> None:
    with db() as conn:
        conn.execute(
            """
            INSERT INTO vital_containers (
                vital_key, name, compose_project, compose_service, created_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(vital_key) DO UPDATE SET
                name = excluded.name,
                compose_project = excluded.compose_project,
                compose_service = excluded.compose_service
            """,
            (watched_key, name, compose_project, compose_service, _utc_now()),
        )


def clear_watched_container(watched_key: str) -> None:
    with db() as conn:
        conn.execute("DELETE FROM vital_containers WHERE vital_key = ?", (watched_key,))


def is_watched_container(watched_key: str) -> bool:
    with db() as conn:
        row = conn.execute(
            "SELECT 1 FROM vital_containers WHERE vital_key = ?", (watched_key,)
        ).fetchone()
    return row is not None


# Deprecated aliases — prefer watched_* names.
def list_vitals() -> list[dict[str, Any]]:
    return list_watched_containers()


def set_vital(
    vital_key: str,
    *,
    name: str | None = None,
    compose_project: str | None = None,
    compose_service: str | None = None,
) -> None:
    set_watched_container(
        vital_key,
        name=name,
        compose_project=compose_project,
        compose_service=compose_service,
    )


def clear_vital(vital_key: str) -> None:
    clear_watched_container(vital_key)


def is_vital(vital_key: str) -> bool:
    return is_watched_container(vital_key)


# --- per-container description / notes (keyed like watched stars) ---

def _notes_row(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "watched_key": row.get("watched_key"),
        "description": row.get("description") or "",
        "notes": row.get("notes") or "",
        "updated_at": row.get("updated_at"),
    }


def list_container_notes() -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM container_notes ORDER BY watched_key COLLATE NOCASE"
        ).fetchall()
    return [_notes_row(dict(r)) for r in rows]


def container_notes_map() -> dict[str, dict[str, Any]]:
    return {row["watched_key"]: row for row in list_container_notes() if row.get("watched_key")}


def get_container_notes(watched_key: str) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM container_notes WHERE watched_key = ?",
            (watched_key,),
        ).fetchone()
    return _notes_row(dict(row)) if row else None


def upsert_container_notes(
    watched_key: str,
    *,
    description: str = "",
    notes: str = "",
) -> dict[str, Any]:
    """Store notes; delete the row when both fields are empty."""
    desc = (description or "").strip()
    body = notes or ""
    # Preserve intentional trailing newlines in notes, but trim edges for empty check.
    body_stripped = body.strip()
    if not desc and not body_stripped:
        clear_container_notes(watched_key)
        return {
            "watched_key": watched_key,
            "description": "",
            "notes": "",
            "updated_at": None,
        }
    now = _utc_now()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO container_notes (watched_key, description, notes, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(watched_key) DO UPDATE SET
                description = excluded.description,
                notes = excluded.notes,
                updated_at = excluded.updated_at
            """,
            (watched_key, desc, body, now),
        )
    return {
        "watched_key": watched_key,
        "description": desc,
        "notes": body,
        "updated_at": now,
    }


def clear_container_notes(watched_key: str) -> None:
    with db() as conn:
        conn.execute(
            "DELETE FROM container_notes WHERE watched_key = ?", (watched_key,)
        )


# --- image scan cache ---

def get_image_scan(image_key: str) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM image_scan_cache WHERE image_key = ?", (image_key,)
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    try:
        d["severity"] = json.loads(d.pop("severity_json") or "{}")
    except Exception:
        d["severity"] = {}
    try:
        d["top_findings"] = json.loads(d.pop("findings_json") or "[]")
    except Exception:
        d["top_findings"] = []
    return d


def set_image_scan(result: dict[str, Any]) -> None:
    with db() as conn:
        conn.execute(
            """
            INSERT INTO image_scan_cache (
                image_key, image_ref, scanned_at, status, error,
                severity_json, findings_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(image_key) DO UPDATE SET
                image_ref = excluded.image_ref,
                scanned_at = excluded.scanned_at,
                status = excluded.status,
                error = excluded.error,
                severity_json = excluded.severity_json,
                findings_json = excluded.findings_json
            """,
            (
                result.get("image_key"),
                result.get("image_ref"),
                result.get("scanned_at") or _utc_now(),
                result.get("status"),
                result.get("error"),
                json.dumps(result.get("severity") or {}),
                json.dumps(result.get("top_findings") or []),
            ),
        )


# --- SCM / OpenSCA scan cache (keyed by repo URL + commit) ---

def get_scm_scan(cache_key: str) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM scm_scan_cache WHERE cache_key = ?", (cache_key,)
        ).fetchone()
    if not row:
        return None
    d = dict(row)
    try:
        d["severity"] = json.loads(d.pop("severity_json") or "{}")
    except Exception:
        d["severity"] = {}
    try:
        d["top_findings"] = json.loads(d.pop("findings_json") or "[]")
    except Exception:
        d["top_findings"] = []
    return d


def set_scm_scan(result: dict[str, Any]) -> None:
    with db() as conn:
        conn.execute(
            """
            INSERT INTO scm_scan_cache (
                cache_key, repo_url, commit_sha, scanned_at, status, error,
                severity_json, findings_json, scm_source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
                repo_url = excluded.repo_url,
                commit_sha = excluded.commit_sha,
                scanned_at = excluded.scanned_at,
                status = excluded.status,
                error = excluded.error,
                severity_json = excluded.severity_json,
                findings_json = excluded.findings_json,
                scm_source = excluded.scm_source
            """,
            (
                result.get("cache_key"),
                result.get("repo_url"),
                result.get("commit_sha"),
                result.get("scanned_at") or _utc_now(),
                result.get("status"),
                result.get("error"),
                json.dumps(result.get("severity") or {}),
                json.dumps(result.get("top_findings") or []),
                result.get("scm_source"),
            ),
        )


# --- snapshots (unchanged patterns) ---

def save_container_snapshots(rows: list[dict[str, Any]]) -> str:
    taken_at = _utc_now()
    with db() as conn:
        for r in rows:
            # Don't persist huge inspect blobs in history forever
            slim = {k: v for k, v in r.items() if k != "inspect"}
            conn.execute(
                """
                INSERT INTO container_snapshots (
                    taken_at, container_id, name, image, image_id, status, state,
                    started_at, restart_count, update_available, local_digest,
                    remote_digest, raw_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    taken_at,
                    r.get("container_id"),
                    r.get("name"),
                    r.get("image"),
                    r.get("image_id"),
                    r.get("status"),
                    r.get("state"),
                    r.get("started_at"),
                    r.get("restart_count", 0),
                    1 if r.get("update_available") else 0,
                    r.get("local_digest"),
                    r.get("remote_digest"),
                    json.dumps(slim),
                ),
            )
    return taken_at


def save_host_snapshot(metrics: dict[str, Any]) -> str:
    taken_at = _utc_now()
    with db() as conn:
        conn.execute(
            """
            INSERT INTO host_snapshots (
                taken_at, cpu_percent, mem_percent, mem_used_bytes, mem_total_bytes,
                disk_percent, disk_used_bytes, disk_total_bytes, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                taken_at,
                metrics.get("cpu_percent"),
                metrics.get("mem_percent"),
                metrics.get("mem_used_bytes"),
                metrics.get("mem_total_bytes"),
                metrics.get("disk_percent"),
                metrics.get("disk_used_bytes"),
                metrics.get("disk_total_bytes"),
                json.dumps(metrics),
            ),
        )
    return taken_at


def save_check_results(results: list[dict[str, Any]]) -> str:
    taken_at = _utc_now()
    with db() as conn:
        for r in results:
            conn.execute(
                """
                INSERT INTO check_results (
                    taken_at, name, check_type, ok, latency_ms, message, detail_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    taken_at,
                    r.get("name"),
                    r.get("check_type"),
                    1 if r.get("ok") else 0,
                    r.get("latency_ms"),
                    r.get("message"),
                    json.dumps(r.get("detail") or {}),
                ),
            )
    return taken_at


def get_registry_cache(image_ref: str) -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM registry_cache WHERE image_ref = ?", (image_ref,)
        ).fetchone()
    return dict(row) if row else None


def set_registry_cache(
    image_ref: str, remote_digest: str | None, error: str | None = None
) -> None:
    with db() as conn:
        conn.execute(
            """
            INSERT INTO registry_cache (image_ref, remote_digest, checked_at, error)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(image_ref) DO UPDATE SET
                remote_digest = excluded.remote_digest,
                checked_at = excluded.checked_at,
                error = excluded.error
            """,
            (image_ref, remote_digest, _utc_now(), error),
        )


def latest_containers() -> list[dict[str, Any]]:
    with db() as conn:
        row = conn.execute(
            "SELECT taken_at FROM container_snapshots ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not row:
            return []
        taken_at = row["taken_at"]
        rows = conn.execute(
            """
            SELECT * FROM container_snapshots
            WHERE taken_at = ?
            ORDER BY name COLLATE NOCASE
            """,
            (taken_at,),
        ).fetchall()
    return [dict(r) for r in rows]


def latest_host() -> dict[str, Any] | None:
    with db() as conn:
        row = conn.execute(
            "SELECT * FROM host_snapshots ORDER BY id DESC LIMIT 1"
        ).fetchone()
    return dict(row) if row else None


def latest_checks() -> list[dict[str, Any]]:
    with db() as conn:
        row = conn.execute(
            "SELECT taken_at FROM check_results ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not row:
            return []
        taken_at = row["taken_at"]
        rows = conn.execute(
            """
            SELECT * FROM check_results
            WHERE taken_at = ?
            ORDER BY name COLLATE NOCASE
            """,
            (taken_at,),
        ).fetchall()
    return [dict(r) for r in rows]


def recent_check_history(name: str, limit: int = 20) -> list[dict[str, Any]]:
    with db() as conn:
        rows = conn.execute(
            """
            SELECT * FROM check_results
            WHERE name = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (name, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def get_digest_state() -> dict[str, Any]:
    with db() as conn:
        row = conn.execute("SELECT * FROM digest_state WHERE id = 1").fetchone()
    return dict(row) if row else {}


def set_digest_state(kind: str, summary: str) -> None:
    with db() as conn:
        conn.execute(
            """
            UPDATE digest_state
            SET last_sent_at = ?, last_kind = ?, last_summary = ?
            WHERE id = 1
            """,
            (_utc_now(), kind, summary),
        )


def containers_since(since_iso: str | None) -> list[dict[str, Any]]:
    with db() as conn:
        if since_iso:
            return latest_containers()
        return latest_containers()


def prune_old_rows(keep_days: int = 14) -> None:
    cutoff = datetime.now(timezone.utc).timestamp() - keep_days * 86400
    cutoff_iso = datetime.fromtimestamp(cutoff, tz=timezone.utc).isoformat()
    with db() as conn:
        for table in ("container_snapshots", "host_snapshots", "check_results"):
            conn.execute(f"DELETE FROM {table} WHERE taken_at < ?", (cutoff_iso,))
