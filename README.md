# Homelab Watcher

A small dashboard for a **single Docker host**. It shows live containers (with optional security checks), host CPU/RAM/disk/uptime/load, open-port inventory (host listeners via host `/proc` + Docker published bindings), optional Internet speed checks, optional HTTP/ping/DNS checks (Plex, custom targets), and quiet email digests when something needs attention.

Configure most things in the **web Settings** UI (saved to SQLite). `.env` / `config.yaml` are optional fallbacks for first boot.

It does **not** manage reverse proxies, SSO, or remote Docker hosts. Container **lifecycle** (stop / start / restart / pause / kill), **update**, **tear-down**, and **Docker reclaim** are optional (Settings → General) and need a writable Docker socket. **Update is Compose-only** — it runs `docker compose pull` + `up -d` for that service so restart policy, `depends_on`, and networks stay under Compose control. **Stop / start / restart** prefer Compose when labeled and the project dir is visible; otherwise they use the Docker Engine API.

---

## Concepts (read this once)

| Concept | Meaning |
|--------|---------|
| **Containers** | Discovered **live** from Docker on the host running Watcher. Not configured by hand. |
| **Star / important** | A star on a container in the UI. Persisted in SQLite by compose `project/service` when labeled, otherwise by container name. Digests call out starred containers that go down. |
| **Checks** | Optional **HTTP / ping / DNS probes** (first-class Plex + custom targets) for things Docker inventory does not cover well. Configured under their own Settings sections / `config.yaml` `targets:`. |
| **Settings** | Primary config UI (General, Plex, Pi-hole, Email, Security, Disks, …). Stored in SQLite on the `watcher-data` volume — **treat that volume as sensitive**. |

---

## Quick start (home server)

**You** run these on the Docker host. Do not run them from a laptop “agent” session unless that machine *is* the home server.

1. Copy files:

```bash
cp .env.example .env
cp config.example.yaml config.yaml
```

2. Optional bootstrap in `.env`: `RESEND_API_KEY`, `DIGEST_TO`, `TZ`. You can also set these later in **Settings → Email digests**.

3. Start:

```bash
docker compose up -d --build
```

4. Open **http://localhost:8080** (or your reverse-proxied hostname). Use **Settings** for Plex, Pi-hole, digests, security, disks.

5. Put the UI behind Caddy/Authentik or LAN-only. Do **not** expose publicly without auth — especially with container actions enabled.

### Volumes / socket

| Mount | Purpose |
|-------|---------|
| `docker.sock` (**writable**) | Inventory + optional update/restart/tear-down/reclaim. Use `:ro` only if you disable actions in Settings → General. |
| `/:/host:ro` | Host metrics, disk paths under `/mnt/...`, and **host** listening ports (`HOST_PROC=/host/proc` → reads **host PID 1** netns at `/host/proc/1/net/*`, not the Watcher container’s `/proc/net`). Also remaps Compose `working_dir` / config file paths for Update (see below). |
| Optional same-path stacks mount | e.g. `/home/user/stacks:/home/user/stacks:ro` if you prefer not relying on `/host` remapping |
| `./config.yaml` | Optional YAML fallback |
| `watcher-data` | SQLite DB, Trivy cache, SCM clone cache, settings/secrets |

### Compose-first updates (required mounts)

Homelab stacks that use Compose intentionally depend on it for **restart policy**, **`depends_on`**, and **recovery after server failure**. Updating a container by pulling its image and recreating it from Docker inspect **bypasses Compose** and is therefore **not supported**.

**Update** always:

1. Detects Compose membership from labels (`com.docker.compose.project`, `.service`, `.project.working_dir`, `.project.config_files`).
2. Runs `docker compose -p <project> [-f …] pull <service>` in the project directory.
3. Runs `docker compose … up -d <service>` so Compose reconciles the service definition.

The Watcher container must be able to **read** those compose project paths:

- **Default:** with `/:/host:ro` mounted (`HOST_ROOT=/host`), Watcher resolves `/home/you/stacks/app` → `/host/home/you/stacks/app`.
- **Same-path mount (recommended for clarity):** mount your stacks root at the same path inside Watcher, e.g. `/home/you/stacks:/home/you/stacks:ro`.
- If neither works, Update fails with an in-UI error explaining the mount requirement.

Standalone (non-Compose) containers: Update is disabled in the UI — there is no inspect/recreate fallback.

### Updating the app

```bash
cd /path/to/homelab-watcher
git pull   # if you track git
docker compose up -d --build
```

---

## Settings tabs

- **General** — Poll interval; **Enable container actions** (update / stop / start / restart / pause / kill / tear-down / Docker reclaim). Update is Compose-only; lifecycle prefers Compose when the project dir is visible, else Engine API. Risks are called out in the UI. Star containers on the Containers page (not a Settings tab).
- **Plex** — First-class HTTP identity check.
- **Pi-hole** — URL, version, password (v6) / API token (v5), with where-to-click directions.
- **Email digests** — What digests are, enable/schedule/from/to/Resend key, all-clear toggle, what counts as notable, test send.
- **Security** — Trivy image SCA, OpenSCA SCM dependency scans, posture checks; intervals; severity thresholds.
- **Host** — Open ports toggle (host machine listeners + Docker published host bindings; default both when on); optional Internet speed check (Cloudflare public endpoints, no API key) with interval or Run now.
- **Disks** — Paths to monitor; warn percent.

---

## Container detail drawer (lifecycle / update / remove)

Click a container row → custom drawer (never browser `alert` / `confirm` / `prompt`). Actions shown depend on container state. Stopped rows also offer a short **Start** quick action (same confirm flow).

### Lifecycle (stop / start / restart / pause / unpause / kill)

Gated by **Settings → General → Enable container actions**. Progress uses the in-drawer job poller.

| Action | Typical states | Compose (when project dir visible) | Else |
|--------|----------------|--------------------------------------|------|
| **Start** | exited / created / dead | `compose start` (fallback `up -d`) | `docker start` |
| **Stop** | running / paused / restarting | `compose stop` | `docker stop` |
| **Restart** | running / paused / restarting / stopped | `compose restart` or start path when stopped | `docker restart` / `start` |
| **Pause** / **Unpause** | running / paused | Engine API | Engine API |
| **Kill** | running / paused / restarting | `compose kill` | `docker kill` |

Kill and Remove use stronger in-drawer confirms.

### Update (Compose only)

1. Requires Compose labels (`project` + `service`). Non-Compose containers: Update is unavailable — standalone containers are not supported for update.
2. Runs `docker compose pull <service>` then `docker compose up -d <service>` using the labeled project name, working dir, and config file(s).
3. Compose reconciles networks, `depends_on`, restart policy, etc. from your compose file — **not** an inspect-based recreate.
4. Progress streams in the drawer.

If the compose project directory / config files are not visible inside Watcher, the job fails with a clear error (mount stacks or use `/:/host:ro` remapping — see **Compose-first updates** above).

### Auto-update (Compose only, per container)

Open a container drawer → **Auto-update**. Pick daily or weekly + a time (same plain-language schedule as Email digests). When due, Watcher runs the same Compose `pull` + `up -d` as manual Update — only if **Settings → General → Enable container actions** is on.

By default, auto-update runs only when the last poll marked an image update available. Turn that off to always pull on the cadence. Standalone (non-Compose) containers cannot be auto-updated.

### Tear down / Remove

Options (custom “I understand” confirmation):

- Remove container  
- Remove **image** (Docker image on the host — **not** Compose build cache)  
- Keep or remove volumes (anonymous / create-time volumes; shared named volumes may remain if used elsewhere)

For Compose services, tear-down prefers `docker compose stop` / `rm` for **that service only** (not a full project `down`). If the compose project dir is not visible, it falls back to Docker API remove for that container. Shared networks/volumes and sibling services are left alone.

Gated by **Settings → General → Enable container actions** (default on; disable for inventory-only). API returns 403 when disabled.

---

## Docker disk usage / reclaim

**Host** shows a **Docker disk** table (images, containers, volumes, build cache — size + reclaimable), similar to `docker system df`. Home can show a compact **Docker reclaimable** metric linking to Host.

**Reclaim…** (when actions are enabled) opens a custom confirm modal:

- Presets: **Safe reclaim** (stopped containers, dangling images, build cache) vs **Aggressive** (also all unused images, all build cache, unused networks). Unused volumes stay off unless you opt in.
- Per-item checkboxes; unused volumes need an extra “I understand” confirm (default off).
- Progress/result via the existing job poller (`GET /api/jobs/{id}`).

APIs: `GET /api/docker/df` (fail-soft if Docker is down), `POST /api/docker/prune` (gated + `confirm: true`). Uses the Docker Engine SDK (`client.df()`, prune endpoints), not shell.

---

## Security (Trivy + OpenSCA + posture)

Opt-in via Settings (or `security.enabled` in YAML).

- **Trivy** ships in the app image; scans local images via the Docker socket. Results cached in SQLite by image digest; configurable interval; a few scans per poll so the dashboard stays responsive. Missing/failed Trivy → “scan unavailable”, dashboard still works.
- **OpenSCA (SCM)** ships in the app image with `git`. Discovers a source repo URL from container/image labels when present (`org.opencontainers.image.source`, `org.label-schema.vcs-url`, git-shaped `org.opencontainers.image.url`, plus optional Settings overrides). Shallow-clones into `/data/scm-repos` (cached by URL + commit; not every poll). Runs [OpenSCA-cli](https://github.com/XmirrorSecurity/OpenSCA-cli) for dependency findings. No URL or missing binary → skip/unavailable, fail-soft. Private repos: set `GIT_TOKEN` / `SCM_TOKEN` or a git token in Settings → Security (HTTPS clone only; never push).
- **Posture** (no CVE DB): privileged, docker.sock mounts, sensitive host binds, host network, CapAdd ALL / extras, running as root (informational).

Not a Wiz replacement — useful homelab signal.

After pulling these changes on the home server, rebuild so the image picks up OpenSCA + git:

```bash
docker compose up -d --build
```

---

## Email digests (Resend)

Quiet summary on a cron — not alert spam. Notable includes: starred container down, image updates, check failures, disk pressure, notable security. Configure in Settings → Email (API key can start in `.env`).

---

## Develop locally (without Docker)

For laptop testing. **Production is Compose on the home server.**

### One-command backend

From the repo root (backend only — does not start Vite):

```bash
./dev.sh
# or: bash dev.sh
```

Creates `backend/.venv` (Python 3.12) if needed, installs requirements, copies `config.example.yaml` → `config.yaml` when missing, sets `DATABASE_PATH` / `CONFIG_PATH` (and Colima `DOCKER_HOST` when that socket exists), then runs uvicorn on **http://127.0.0.1:8080**. Start the frontend separately with `cd frontend && npm run dev` if you want the UI.

### Python version (required)

Local backend needs **Python 3.12 or 3.13** — same family as the image (`python:3.12-slim` in the Dockerfile). Prefer **3.12** so laptop and Compose stay aligned.

**Do not use Python 3.14** yet. Current pinned deps (notably `pydantic` / `pydantic-core`) build via PyO3, which only supports up through 3.13. A plain `python3 -m venv` on a Mac that defaults to 3.14 will fail mid-install and leave `uvicorn` missing.

On macOS with Homebrew:

```bash
brew install python@3.12   # or python@3.13
```

The repo includes `.python-version` (`3.12`) for pyenv / similar tools.

### Backend

```bash
cd backend
# Use an explicit 3.12/3.13 binary — not bare `python3` if that is 3.14+
python3.12 -m venv .venv   # or: python3.13 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
python -V                   # expect 3.12.x or 3.13.x
pip install -r requirements.txt

# From repo root or set paths:
export DATABASE_PATH="$(pwd)/../data/homelab-watcher.db"
export CONFIG_PATH="$(pwd)/../config.yaml"
export HOST_PROC="/proc"
export HOST_ROOT="/"
# Optional: RESEND_*, PIHOLE_*, POLL_INTERVAL_SECONDS

# Docker socket: macOS Docker Desktop usually works via /var/run/docker.sock.
# Without Docker, container list is empty — UI/settings still work.

cd ..   # or run module from backend with PYTHONPATH
uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8080 --reload
```

If `uvicorn` cannot find the app:

```bash
cd backend
uvicorn app.main:app --host 127.0.0.1 --port 8080 --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Vite serves the UI (default **http://127.0.0.1:5173**) and proxies `/api` → `http://127.0.0.1:8080`.

Trivy and OpenSCA are optional locally; install them yourself or expect “scan unavailable” / skipped SCM. The Compose image includes both.

---

## Troubleshooting

| Symptom | Likely cause |
|---------|----------------|
| Containers empty | Socket not mounted / Docker down / wrong host |
| Update disabled / “not a Compose service” | Container lacks Compose labels — Update is Compose-only |
| Update fails: project dir / config not visible | Mount stacks into Watcher (same path) or ensure `/:/host:ro` covers the compose path; see Compose-first updates |
| Update/lifecycle/tear-down fail with permission | Socket mounted `:ro` — use writable sock or disable actions |
| HTTPS check down, container up | Caddy / certs / Authentik — not the app container |
| Scans slow / pending | First Trivy DB download + image scan, or first SCM clone/OpenSCA; cached afterward |
| Pi-hole no badges / 0 records | Settings → Pi-hole → **Test**. **v5** (web ≥ 5.11): API token + `GET /admin/api.php?customdns&action=get&auth=TOKEN` (and `customcname`). Bare `[]` = wrong token or web &lt; 5.11 (no list API) — not empty DNS. **v6**: password/app password + `/api/config/dns/hosts`. URL: `http://<pi-ip>` (optional `/admin`). |
| Digests not sending | Resend key + To in Settings; check enabled + cron/TZ |
| `pip install` fails building `pydantic-core` / PyO3; or `uvicorn: command not found` | Venv created with **Python 3.14+**. PyO3 in the pinned stack maxes out at 3.13, so install aborts and `uvicorn` never lands. See recovery steps below. |

### Local venv: pydantic-core / PyO3 / Python 3.14

If you see errors mentioning `pydantic-core`, `PyO3`, or “unsupported Python version” while installing, or `uvicorn` is missing after a failed `pip install`:

```bash
cd backend
deactivate 2>/dev/null || true
rm -rf .venv
# Prefer 3.12 (matches Dockerfile). 3.13 is OK.
python3.12 -m venv .venv   # or: python3.13 -m venv .venv
source .venv/bin/activate
python -V                  # must be 3.12.x or 3.13.x — not 3.14
pip install -r requirements.txt
uvicorn app.main:app --host 127.0.0.1 --port 8080 --reload
```

If `python3.12` / `python3.13` are missing: `brew install python@3.12` (or `@3.13`), then recreate the venv.

Future: when deps ship reliable 3.14 wheels, the `requires-python` ceiling can be raised — until then stay on 3.12/3.13.


---

## API (selected)

- `GET /api/containers`, `GET /api/containers/{id}` — containers include `watched` / `watched_key` (star flag; `vital*` aliases for one release)
- `GET/POST /api/watched` — list / star / unstar containers (`/api/vitals` alias)
- `GET /api/checks` — latest HTTP/ping/DNS check results
- `POST /api/containers/{id}/update`, `.../teardown`, `GET /api/jobs/{id}`
- `GET/PUT /api/settings`, `/api/settings/{general|checks|plex|pihole|digest|security|disks|listening_ports|speed_test}` (`settings/watched` alias for checks)
- `GET /api/host` — host snapshot (CPU/RAM/disks/uptime/load/NICs/ports) + last speed result
- `POST /api/host/speed-test` — start an on-demand Cloudflare speed check (background)
- `POST /api/poll`, `POST /api/digest/test`

---

## License / scope

Homelab tool. Prefer LAN or SSO. You are responsible for destructive Docker actions you confirm in the UI.
