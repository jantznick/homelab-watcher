"""Application settings and YAML config loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Thresholds(BaseModel):
    disk_warn_percent: float = 85.0
    alert_on_exited: bool = False
    # Mount paths selected for monitoring (Settings → Disks). Empty = none.
    # Discovery lists all mounts; host metrics filter to this selection.
    disks: list[str] = Field(default_factory=list)


class TargetConfig(BaseModel):
    name: str
    type: Literal["http", "ping", "dns"]
    url: str | None = None
    host: str | None = None
    query: str | None = None
    # If set, require this exact status. Otherwise 2xx/3xx count as up
    # (SSO-protected apps often redirect to login).
    expect_status: int | None = None
    verify_tls: bool = True
    timeout_seconds: float = 5.0


class PiHoleConfig(BaseModel):
    """Optional read-only Pi-hole API (local/custom DNS). Empty = disabled."""

    url: str = ""
    # auto tries v6 then v5; or force "5" / "6"
    version: Literal["auto", "5", "6"] = "auto"
    verify_tls: bool = True
    timeout_seconds: float = 5.0


class NetworkingConfig(BaseModel):
    """
    Optional reverse-proxy route discovery for DNS → proxy → container mapping.
    Prefer Settings → Networking. Read-only against Caddy (and later Traefik).
    """

    # none | caddy | traefik
    proxy_type: Literal["none", "caddy", "traefik"] = "none"
    # Caddy discovery methods (one or more when proxy_type=caddy)
    caddy_use_admin_api: bool = False
    caddy_admin_url: str = "http://host.docker.internal:2019"
    caddy_use_caddyfile: bool = False
    caddy_caddyfile_path: str = "/config/Caddyfile"
    caddy_use_labels: bool = True
    verify_tls: bool = True
    timeout_seconds: float = 5.0


class TrivyConfig(BaseModel):
    """Image SCA via Trivy. Requires `trivy` on PATH (installed in the app image)."""

    enabled: bool = True
    scan_interval_hours: float = 24.0
    # Severities to collect (Trivy --severity)
    severity: str = "CRITICAL,HIGH,MEDIUM,LOW"
    ignore_unfixed: bool = False
    timeout_seconds: float = 180.0
    max_scans_per_poll: int = 2
    top_findings: int = 5
    cache_dir: str = "/data/trivy"


class PostureConfig(BaseModel):
    """CIS-inspired checks from Docker inspect (no CVE database)."""

    enabled: bool = True


class OpenSCAConfig(BaseModel):
    """
    SCM dependency SCA via OpenSCA-cli.
    Discovers repo URLs from image/container labels; clones shallow and scans.
    Requires `opensca-cli` + `git` on PATH (installed in the app image).
    """

    enabled: bool = True
    scan_interval_hours: float = 24.0
    timeout_seconds: float = 300.0
    max_scans_per_poll: int = 1
    top_findings: int = 5
    # Shallow clone + checkout cache
    clone_dir: str = "/data/scm-repos"
    # Optional OpenSCA cloud vuln DB token (improves findings; scan still runs without)
    opensca_token: str = ""
    # Optional git HTTPS token for private repos (also GIT_TOKEN / SCM_TOKEN env)
    git_token: str = ""
    # Manual container name or image → git URL overrides (no hardcoded repos)
    scm_overrides: dict[str, str] = Field(default_factory=dict)


class SecurityConfig(BaseModel):
    """
    Opt-in container security. Disabled by default — enable in Settings or config.yaml.
    Trivy (images) and OpenSCA (SCM) are independent; `enabled` is the umbrella
    (true when any scanner/posture should run). Not a full Wiz replacement.
    """

    enabled: bool = False
    trivy: TrivyConfig = Field(default_factory=TrivyConfig)
    posture: PostureConfig = Field(default_factory=PostureConfig)
    opensca: OpenSCAConfig = Field(default_factory=OpenSCAConfig)
    # Image findings at this severity or worse count as "notable" for digest/UI
    notable_severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] = "HIGH"
    # Posture findings at this severity or worse are notable for digest
    notable_posture_severity: Literal["critical", "high", "medium", "low"] = "high"


class ListeningPortsConfig(BaseModel):
    """
    Open-ports inventory on the Host page: host machine listeners
    (host /proc netns via HOST_PROC) plus Docker published host bindings.
    Not a port scanner. When enabled, both sources are shown.
    """

    enabled: bool = True


class SpeedTestConfig(BaseModel):
    """
    Optional Internet speed check via Cloudflare public endpoints (no API key).
    Disabled by default — transfers are non-trivial; prefer infrequent or manual.
    """

    enabled: bool = False
    # Hours between automatic runs when enabled. 0 = manual only.
    interval_hours: float = 12.0


class AppYamlConfig(BaseModel):
    # Custom HTTP/ping/DNS checks — only what the user lists here (never hardcoded).
    targets: list[TargetConfig] = Field(default_factory=list)
    thresholds: Thresholds = Field(default_factory=Thresholds)
    registry_cache_hours: float = 6.0
    # Optional container name → browser URL when Docker labels are absent.
    container_urls: dict[str, str] = Field(default_factory=dict)
    # Optional Pi-hole API; secrets via PIHOLE_PASSWORD / PIHOLE_API_TOKEN in .env
    # Prefer Settings UI / SQLite when configured there (see runtime_settings).
    pihole: PiHoleConfig = Field(default_factory=PiHoleConfig)
    networking: NetworkingConfig = Field(default_factory=NetworkingConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    listening_ports: ListeningPortsConfig = Field(default_factory=ListeningPortsConfig)
    speed_test: SpeedTestConfig = Field(default_factory=SpeedTestConfig)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    resend_api_key: str = ""
    digest_from: str = "Homelab Watcher <onboarding@resend.dev>"
    digest_to: str = ""
    digest_cron: str = ""  # empty = not scheduled; obscure env fallback only
    digest_send_all_clear: bool = True
    poll_interval_seconds: int = 300
    database_path: str = "/data/homelab-watcher.db"
    config_path: str = "/config/config.yaml"
    host_proc: str = "/host/proc"
    host_root: str = "/host"
    tz: str = "UTC"
    # Pi-hole secrets (fallback when not saved via Settings UI)
    pihole_password: str = ""
    pihole_api_token: str = ""
    # Optional private-repo clone token (fallback when not in Settings → Security)
    git_token: str = ""
    scm_token: str = ""


def get_settings() -> Settings:
    return Settings()


def load_yaml_config(path: str | None = None) -> AppYamlConfig:
    cfg_path = Path(path or get_settings().config_path)
    if not cfg_path.is_file():
        return AppYamlConfig()
    raw: dict[str, Any] = yaml.safe_load(cfg_path.read_text()) or {}
    return AppYamlConfig.model_validate(raw)


def reload_yaml_config() -> AppYamlConfig:
    """Always read config from disk."""
    return load_yaml_config()
