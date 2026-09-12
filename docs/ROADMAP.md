# Homelab Watcher — roadmap & ideas

Practical ideas for turning this into a stronger **homelab mini-Wiz**: one Docker host, clear attention signals, optional deep dives — not an enterprise console.

Scope reminder (today): **single host**, live Docker inventory, Settings-in-SQLite, quiet digests. No reverse-proxy management, no SSO product, no multi-cluster.

---

## Current strengths

What’s already solid:

- **Home** — attention-first summary (running count, image updates, starred-down, disk pressure, LAN ports, HIGH+ security, Pi-hole / Plex / checks).
- **Containers** — live Docker list; scopes (running / all / starred / updates / issues / down); stars; access URLs from labels / config; Compose-only **Update** + gated lifecycle (**Stop** / **Start** / **Restart** / **Pause** / **Kill**) and **tear-down**.
- **Host** — CPU / RAM / selected disks; optional **listening-port** inventory (not a scanner).
- **Checks** — HTTP / ping / DNS (first-class Plex + custom targets) with recent history.
- **Security** — Trivy image SCA, OpenSCA SCM deps, posture (privileged, sock mounts, sensitive binds, host net, caps, root).
- **Digests** — Resend email, multi-profile schedules, “notable vs all-clear,” not alert spam.
- **Ops hygiene (backend ready)** — Cloudflare speed test (scheduled/manual), `docker df` + prune job API / modal code; host collector already gathers uptime, load average, and interface summary (not all surfaced in the UI yet).

Honest gaps to close first (often higher value than brand-new features):

| Exists in code | Gap |
|----------------|-----|
| Speed test | Little/no Settings + Host UI |
| Docker df / prune | API + `DockerPruneModal`; not wired into nav/pages |
| Host uptime / load / NICs | Collected in poll; `/api/host` + Host page mostly omit them |

---

## UX / product improvements

- **Surface unfinished backends** — speed test toggle + last result; Docker disk usage + prune entry point (Containers or Host); host uptime / load / primary IPs on Host and maybe Home.
- **Security overview page** — one place for HIGH+ across images / SCM / posture instead of only per-container modal + Home chip.
- **Checks as a first-class nav item** (or sticky Home section) when ≥1 target is configured — easy to miss today.
- **Filter / sort polish** — Containers: sort by severity, update age, uptime; Host ports: filter LAN-only / process name.
- **“What changed since last poll / last digest”** — short delta on Home (new downs, new HIGH findings, new update badges).
- **Job history** — Update / stop / tear-down / prune logs beyond the live modal (last N jobs).
- **Empty states with one action** — e.g. disks not selected → Settings; security off → enable Trivy; no checks → add HTTP target.
- **Mobile** — denser Host ports cards already help; keep Home actionable on a phone on the LAN.
- **Dark UI polish** — keep it dense and readable; avoid dashboard-widget sprawl.

---

## New metrics

### Host

- Expose **uptime**, **load average**, **network interfaces** (IPs, maybe RX/TX counters over time).
- **Temperature / fan** if sensors are available (`sensors`, hwmon) — fail-soft.
- **ZFS / Btrfs** pool health when those mounts are selected (simple state, not a full storage suite).
- Optional **inode** pressure on selected disks (full disks ≠ only %-used).

### Network

- Speed test **history** (last N runs: down / up / latency) on Host.
- **LAN latency** to gateway or a user-picked host (cheap ping check, separate from Internet speed).
- Highlight **unexpected new LAN listeners** vs a previous snapshot (digest-worthy).

### Docker

- **docker df** breakdown: images / containers / volumes / build cache reclaimable.
- Per-container **CPU % / RSS** (from Docker stats, sampled) — optional, interval-gated so polls stay light.
- **Restart count / OOM** flags from inspect.
- **Compose project** grouping (project → services) as an alternate Containers view.
- Image **age** and “how long has update_available been true.”

### Security

- Aggregate **CVE age / fixable** counts (Trivy already has richness; UI shows top findings).
- **Base image** drift (same service, digest changed).
- Posture: allowlist known-good sock mounts (Watcher itself) so noise drops.
- Optional **Grype** or Trivy **filesystem** scan of bind-mounted app dirs — heavy; keep opt-in.

### Energy / power (nice)

- **UPS** status (NUT / APCNIC / Home Assistant sensor): on battery, runtime, load %.
- Host **power draw** only if a cheap source exists (IPMI, smart plug API) — don’t invent fake Watts.

### Backups

- “Last successful backup” probes: **restic** / **borg** exit status file, **Proxmox Backup**, TrueNAS snapshot age, or a simple “file mtime must be &lt; N hours” check.
- Digest section: backup stale → notable.

---

## New pages or views

| Page / view | Why |
|-------------|-----|
| **Security** | Fleet CVE + posture rollup; filter by severity / starred only. |
| **Network** (or Host tab) | Ports + speed history + NICs; keep Host from becoming a junk drawer. |
| **Docker disk** | df table + prune with clear presets (safe vs aggressive). |
| **Compose projects** | Group services; update whole project later (carefully). |
| **Activity / jobs** | Past update, tear-down, prune, manual poll. |
| **Digest preview** | “What would email say right now?” without sending. |
| **History sparklines** | CPU / mem / disk / check latency over 24h–7d (SQLite already retains ~14d rows). |

Avoid a fifth “everything” dashboard. Prefer one job per page.

---

## Integrations

Keep them **opt-in Settings cards** with test buttons (same pattern as Plex / Pi-hole).

### High fit

- **Authentik / Authelia / Pocket ID** — document “put Watcher behind SSO”; optional “SSO health” HTTP check template. Don’t build an IdP.
- **Caddy** — already read site labels for access URLs; optional admin API: cert expiry, upstream unhealthy.
- **Cloudflare** — Tunnel status / last seen; zone cert expiry; reuse Cloudflare for speed (already).
- **UPS (NUT)** — on-battery → Home warn + digest.
- **SMART** — `smartctl` on selected disks (Wear_Leveling, Reallocated) via host mount / privileged sidecar — careful with privileges.
- **Home Assistant** — push a few sensors (or pull HA states for UPS / disk / binary “lab ok”).

### Medium fit

- **Unifi / Omada** — WAN up, alert count (read-only API).
- **Tailscale / Headscale** — peer online for “admin laptop can reach lab.”
- **Paperless / Immich / Nextcloud** — first-class HTTP identity like Plex (optional templates).
- **Grafana** — deep links only; don’t embed Grafana.
- **Gotify / ntfy / Discord webhook** — instant path for “starred down” (see digests).

### Low fit / later

- Kubernetes, Nomad, remote Docker contexts, full CMDB, ticket systems.

---

## Digests & alerting evolution

Today: scheduled **Resend** digests, multi-profile, notable vs all-clear.

Natural next steps:

1. **Digest preview** in UI + “sections included” checklist per profile (security / disks / ports / checks / updates).
2. **Webhook / ntfy / Gotify** for *urgent* only (starred container down, UPS on battery) — keep digests for the daily/weekly rollup.
3. **Quiet hours** and **dedupe** (“same HIGH CVE set → don’t re-email every day”).
4. **Diff digests** — only new notables since last send.
5. Optional **second channel** profile (e.g. daily to you, weekly to a shared inbox).
6. Attach or link a **small CSV / JSON** of HIGH findings for the week.

Stay allergic to page-every-blip monitoring. Homelab default = quiet.

---

## Hardening / multi-host later

### Hardening (single host, soon-ish)

- Document **read-only socket** + actions off as the safe default for exposed UIs.
- **Authn** — trust reverse proxy headers *or* a simple local password / OIDC — before any Internet exposure.
- Audit log for update / tear-down / prune (who/when — even if “who” is just “UI session”).
- Secrets: Settings already hold Resend / Pi-hole / git tokens — consider export/backup guidance and redaction in API responses (partially done).
- Rate-limit destructive APIs; confirm strings already exist — keep them.

### Multi-host (later, big)

Only when single-host UX is boringly good:

- Agent or SSH/`docker context` per machine → **Hosts** switcher.
- Star / digest keys become `host/project/service`.
- Security scans stay **on the host that owns the images** (don’t central-scan over WAN without care).

Until then: one Watcher per machine, or one host + Checks for the rest, is enough.

---

## Nice-to-haves vs high-value next

### High value (do these first)

1. Wire **Docker df + prune** into the UI.
2. Show **host uptime / load / NICs** already collected.
3. **Speed test** Settings + last result on Host/Home.
4. **Security rollup** page (or dense Home section).
5. **Digest preview** + per-profile section toggles.
6. **ntfy/Gotify** for starred-down / UPS only.
7. **Backup freshness** check type (mtime / HTTP / script exit).

### Nice-to-haves

- Per-container live stats, Compose project view, SMART, Caddy admin, Cloudflare Tunnel card, sparklines, energy/UPS, allowlisted posture noise, mobile PWA, export settings.
- **docker exec** interactive shells in the dashboard (out of scope for the lifecycle-actions pass; keep CLI/`exec` local).

### Probably skip

- Full Wiz/CSPM, K8s, auto-remediation of CVEs, public SaaS multi-tenant, replacing Prometheus/Grafana for metrics history.

---

## Design principles (keep)

- **Attention over inventory** — Home answers “do I need to care?”
- **Fail-soft** — missing Trivy / Pi-hole / host mount never blanks the app.
- **Compose-first** for mutations — no inspect-recreate lies.
- **Settings UI &gt; YAML** for day-to-day; YAML remains bootstrap.
- **One host done well** beats half a fleet manager.

When adding a metric or page: prefer something you would check on a Sunday coffee digest — not something that needs a NOC.
