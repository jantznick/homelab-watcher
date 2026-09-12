export type SecuritySummary = {
  enabled: boolean;
  trivy_enabled?: boolean;
  opensca_enabled?: boolean;
  scan_status?: string;
  scan_error?: string | null;
  severity?: Record<string, number>;
  top_findings?: Array<{
    id: string;
    severity: string;
    pkg?: string;
    title?: string;
    source?: string;
  }>;
  posture?: Array<{
    id: string;
    severity: string;
    title: string;
    detail: string;
  }>;
  issue_count?: number;
  max_severity?: string | null;
  notable?: boolean;
  scanned_at?: string | null;
  trivy_available?: boolean;
  opensca_available?: boolean;
  image_scan_status?: string | null;
  image_severity?: Record<string, number> | null;
  scm?: {
    status?: string;
    error?: string | null;
    repo_url?: string | null;
    commit_sha?: string | null;
    scm_source?: string | null;
    severity?: Record<string, number>;
    top_findings?: Array<{
      id: string;
      severity: string;
      pkg?: string;
      title?: string;
      source?: string;
    }>;
    scanned_at?: string | null;
    notable_count?: number;
  } | null;
};

export type ContainerMount = {
  type: string;
  source: string;
  destination: string;
  mode: string;
};

export type ContainerItem = {
  container_id: string;
  name: string;
  image: string;
  image_id?: string | null;
  status: string;
  state: string;
  created_at?: string | null;
  started_at: string | null;
  uptime_seconds: number | null;
  restart_count: number;
  health?: string | null;
  networks?: string[];
  published_ports?: string[];
  mounts?: ContainerMount[];
  update_available: boolean;
  /** Semver jump when an update is available: major | minor | patch | unknown */
  update_bump?: "major" | "minor" | "patch" | "unknown" | null;
  /** Current image tag (when classified). */
  update_from?: string | null;
  /** Newest comparable registry tag (when classified). */
  update_to?: string | null;
  local_digest: string | null;
  remote_digest: string | null;
  taken_at: string;
  access_url: string | null;
  access_url_source: string | null;
  pihole_matched: boolean;
  pihole_hostnames: string[];
  /** Starred / important container (digest when down). */
  watched?: boolean;
  watched_key?: string | null;
  /** @deprecated Prefer watched / watched_key */
  vital?: boolean;
  /** @deprecated Prefer watched_key */
  vital_key?: string | null;
  /** User short description (survives recreate via watched_key). */
  description?: string | null;
  /** User multiline notes (survives recreate via watched_key). */
  notes?: string | null;
  compose_project?: string | null;
  compose_service?: string | null;
  compose_workdir?: string | null;
  compose_config_files?: string | null;
  security?: SecuritySummary;
  labels?: Record<string, string>;
  inspect_summary?: {
    privileged?: boolean;
    network_mode?: string;
    user?: string;
  };
};

export type PiHoleStatus = {
  configured: boolean;
  ok: boolean | null;
  version: string | null;
  message: string | null;
  record_count: number;
};

export type DiskMetric = {
  path: string;
  mountpoint?: string;
  filesystem?: string | null;
  fstype?: string | null;
  mounted?: boolean;
  percent: number | null;
  used_bytes?: number | null;
  total_bytes?: number | null;
  free_bytes?: number | null;
  error?: string | null;
};

export type ListeningPort = {
  protocol: string;
  family?: string;
  port: number;
  address: string;
  bind_scope: "all" | "lan" | "localhost" | string;
  pid?: number | null;
  process?: string | null;
  container?: string | null;
};

export type HostNetworkInterface = {
  name: string;
  addresses: string[];
};

export type SpeedTestLast = {
  ok?: boolean | null;
  provider?: string | null;
  taken_at?: string | null;
  download_mbps?: number | null;
  upload_mbps?: number | null;
  ping_ms?: number | null;
  error?: string | null;
};

export type SpeedTestInfo = {
  enabled?: boolean;
  interval_hours?: number;
  source?: string;
  busy?: boolean;
  last?: SpeedTestLast | null;
};

export type HostMetrics = {
  taken_at: string | null;
  cpu_percent: number | null;
  mem_percent: number | null;
  mem_used_bytes: number | null;
  mem_total_bytes: number | null;
  disks: DiskMetric[];
  disk_warn_percent: number;
  disk_source?: string | null;
  disk_selection_needed?: boolean | null;
  host_note?: string | null;
  host_root_mounted?: boolean | null;
  uptime_seconds?: number | null;
  load_avg?: number[] | null;
  network_interfaces?: HostNetworkInterface[];
  network_source?: string | null;
  network_note?: string | null;
  listening_ports?: ListeningPort[];
  listening_ports_source?: string | null;
  listening_ports_note?: string | null;
  listening_ports_exposed_count?: number | null;
  listening_ports_enabled?: boolean | null;
  speed_test?: SpeedTestInfo | null;
  metrics?: null;
};

export type CheckItem = {
  name: string;
  check_type: string;
  ok: boolean;
  latency_ms: number | null;
  message: string;
  detail: Record<string, unknown>;
  taken_at: string;
  recent: { ok: boolean; taken_at: string; message: string }[];
};

/** @deprecated Prefer CheckItem — probes are checks, not a "Watched" surface. */
export type WatchedItem = CheckItem;

export type StatusPayload = {
  poll: {
    last_poll_at: string | null;
    last_poll_error: string | null;
    poll_interval_seconds: number;
    pihole?: PiHoleStatus | null;
    docker_available?: boolean;
    docker_error?: string | null;
  };
  digest: {
    last_sent_at: string | null;
    last_kind: string | null;
    cron: string;
    tz: string;
    send_all_clear: boolean;
    next_at: string | null;
    configured: boolean;
    enabled?: boolean;
    scheduled?: boolean;
    schedule_summary?: string;
    profiles?: Array<{
      id: string;
      name: string;
      enabled: boolean;
      scheduled?: boolean;
      schedule_summary?: string;
      next_at?: string | null;
    }>;
  };
  actions_enabled?: boolean;
  security_enabled?: boolean;
  trivy_available?: boolean;
};

export type ActionJob = {
  id: string;
  kind?: string;
  status: string;
  message?: string;
  error?: string | null;
  logs?: { at: string; message: string }[];
  new_container_id?: string;
  space_reclaimed_bytes?: number;
};

export type DockerDiskCategory = {
  type: string;
  label: string;
  total_count: number;
  active_count: number;
  size_bytes: number;
  reclaimable_bytes: number;
  reclaimable_percent: number | null;
};

export type DockerDiskUsage = {
  available: boolean;
  error?: string | null;
  taken_at?: string | null;
  layers_size_bytes?: number | null;
  categories: DockerDiskCategory[];
  total_bytes?: number | null;
  reclaimable_bytes?: number | null;
};

export type DockerPruneOptions = {
  containers: boolean;
  images: boolean;
  images_all_unused: boolean;
  build_cache: boolean;
  build_cache_all: boolean;
  volumes: boolean;
  networks: boolean;
};

export type DigestProfile = {
  id: string;
  name: string;
  enabled: boolean;
  digest_from: string;
  digest_to: string;
  digest_send_all_clear: boolean;
  tz: string;
  schedule_frequency?: string | null;
  schedule_weekday?: string | null;
  schedule_hour?: number | null;
  schedule_minute?: number | null;
  scheduled?: boolean;
  schedule_summary?: string;
  configured?: boolean;
};

export type SettingsPayload = {
  general: {
    poll_interval_seconds: number;
    registry_cache_hours: number;
    actions_enabled: boolean;
    source?: string;
  };
  plex: {
    enabled: boolean;
    url: string;
    verify_tls: boolean;
    source?: string;
  };
  checks: {
    targets: Array<Record<string, unknown>>;
    source?: string;
  };
  /** @deprecated Prefer checks — same custom probe targets. */
  watched?: {
    targets: Array<Record<string, unknown>>;
    source?: string;
  };
  pihole: {
    source: string;
    configured: boolean;
    url: string;
    version: string;
    verify_tls: boolean;
    has_password: boolean;
    has_api_token: boolean;
    password_in_db: boolean;
    api_token_in_db: boolean;
  };
  digest: {
    source: string;
    enabled: boolean;
    digest_from: string;
    digest_to: string;
    digest_cron?: string;
    digest_send_all_clear: boolean;
    tz: string;
    has_resend_api_key: boolean;
    resend_api_key_in_db: boolean;
    configured: boolean;
    scheduled?: boolean;
    schedule_summary?: string;
    schedule_frequency?: string | null;
    schedule_weekday?: string | null;
    schedule_hour?: number | null;
    schedule_minute?: number | null;
    profiles?: DigestProfile[];
  };
  security: Record<string, unknown> & {
    enabled: boolean;
    source?: string;
    trivy_available?: boolean;
    opensca_available?: boolean;
    trivy?: Record<string, unknown>;
    posture?: Record<string, unknown>;
    opensca?: Record<string, unknown> & {
      enabled?: boolean;
      scan_interval_hours?: number;
      has_git_token?: boolean;
      has_opensca_token?: boolean;
    };
  };
  disks: {
    disk_warn_percent: number;
    disks: string[];
    alert_on_exited: boolean;
    source?: string;
  };
  listening_ports?: {
    enabled: boolean;
    source?: string;
  };
  speed_test?: {
    enabled: boolean;
    interval_hours: number;
    source?: string;
    last?: SpeedTestLast | null;
    busy?: boolean;
  };
  notes?: {
    secrets_in_db?: string;
    socket?: string;
    compose_updates?: string;
    host_disks?: string;
    listening_ports?: string;
    speed_test?: string;
    trivy?: string;
    opensca?: string;
    starred?: string;
  };
};

async function getJson<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, init);
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail =
        typeof body?.detail === "string"
          ? body.detail
          : body?.detail?.reason || JSON.stringify(body?.detail || body);
    } catch {
      try {
        detail = await res.text();
      } catch {
        /* ignore */
      }
    }
    throw new Error(detail || res.statusText);
  }
  return res.json() as Promise<T>;
}

export function fetchContainers() {
  return getJson<{
    items: ContainerItem[];
    taken_at: string | null;
    pihole: PiHoleStatus;
    actions_enabled: boolean;
    docker_available?: boolean;
    docker_error?: string | null;
  }>("/api/containers");
}

export function fetchHost() {
  return getJson<HostMetrics & { metrics?: null }>("/api/host");
}

export function runHostSpeedTest() {
  return getJson<{
    ok: boolean;
    started?: boolean;
    busy?: boolean;
    speed_test?: SpeedTestInfo;
  }>("/api/host/speed-test", { method: "POST" });
}

export function fetchChecks() {
  return getJson<{
    items: CheckItem[];
    taken_at: string | null;
    config_source?: string;
  }>("/api/checks");
}

/** @deprecated Prefer fetchChecks — GET /api/watched is now starred containers. */
export function fetchWatched() {
  return fetchChecks();
}

export function fetchStatus() {
  return getJson<StatusPayload>("/api/status");
}

export function fetchSettings() {
  return getJson<SettingsPayload>("/api/settings");
}

export function putSettings(section: string, body: Record<string, unknown>) {
  return getJson<Record<string, unknown>>(`/api/settings/${section}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export function fetchDiskDiscover() {
  return getJson<{
    disks: DiskMetric[];
    note: string | null;
    source: string;
    selected: string[];
    disk_warn_percent: number;
    host_root_mounted: boolean;
  }>("/api/disks/discover");
}

export function testPlex(body?: { url?: string; verify_tls?: boolean; enabled?: boolean }) {
  return getJson<{
    ok: boolean;
    message?: string;
    latency_ms?: number | null;
    detail?: Record<string, unknown>;
  }>("/api/settings/plex/test", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
  });
}

export function testPihole() {
  return getJson<{
    ok: boolean;
    configured?: boolean;
    version?: string | null;
    message?: string;
    record_count?: number;
  }>("/api/settings/pihole/test", { method: "POST" });
}

export function setWatched(body: {
  watched_key?: string;
  vital_key?: string;
  name?: string;
  compose_project?: string | null;
  compose_service?: string | null;
  watched?: boolean;
  vital?: boolean;
}) {
  return getJson<{
    ok: boolean;
    watched_key: string;
    watched: boolean;
    vital_key: string;
    vital: boolean;
  }>("/api/watched", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

export function saveContainerNotes(body: {
  watched_key?: string;
  name?: string;
  compose_project?: string | null;
  compose_service?: string | null;
  description?: string;
  notes?: string;
}) {
  return getJson<{
    ok: boolean;
    watched_key: string;
    description: string;
    notes: string;
    updated_at: string | null;
    error?: string;
  }>("/api/containers/notes", {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
}

/** @deprecated Prefer setWatched */
export function setVital(body: {
  vital_key?: string;
  watched_key?: string;
  name?: string;
  compose_project?: string | null;
  compose_service?: string | null;
  vital?: boolean;
  watched?: boolean;
}) {
  return setWatched({
    watched_key: body.watched_key || body.vital_key,
    vital_key: body.vital_key,
    name: body.name,
    compose_project: body.compose_project,
    compose_service: body.compose_service,
    watched: body.watched ?? body.vital,
    vital: body.vital,
  });
}

export function triggerPoll() {
  return getJson<{ ok: boolean }>("/api/poll", { method: "POST" });
}

export function sendTestDigest(profileId?: string | null) {
  const q =
    profileId && profileId.trim()
      ? `?profile_id=${encodeURIComponent(profileId.trim())}`
      : "";
  return getJson<Record<string, unknown>>(`/api/digest/test${q}`, {
    method: "POST",
  });
}

export function fetchContainerLogs(containerId: string, tail = 150) {
  const q = `?tail=${encodeURIComponent(String(tail))}`;
  return getJson<{
    ok: boolean;
    logs: string;
    error: string | null;
    tail: number;
  }>(`/api/containers/${encodeURIComponent(containerId)}/logs${q}`);
}

export function startUpdate(containerId: string) {
  return getJson<{ ok: boolean; job: ActionJob }>(
    `/api/containers/${encodeURIComponent(containerId)}/update`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirm: true }),
    },
  );
}

function postContainerAction(containerId: string, action: string) {
  return getJson<{ ok: boolean; job: ActionJob }>(
    `/api/containers/${encodeURIComponent(containerId)}/${action}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirm: true }),
    },
  );
}

export function startStop(containerId: string) {
  return postContainerAction(containerId, "stop");
}

export function startStart(containerId: string) {
  return postContainerAction(containerId, "start");
}

export function startRestart(containerId: string) {
  return postContainerAction(containerId, "restart");
}

export function startPause(containerId: string) {
  return postContainerAction(containerId, "pause");
}

export function startUnpause(containerId: string) {
  return postContainerAction(containerId, "unpause");
}

export function startKill(containerId: string) {
  return postContainerAction(containerId, "kill");
}

export function startTeardown(
  containerId: string,
  opts: {
    remove_container: boolean;
    remove_image: boolean;
    remove_volumes: boolean;
  },
) {
  return getJson<{ ok: boolean; job: ActionJob }>(
    `/api/containers/${encodeURIComponent(containerId)}/teardown`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ confirm: true, ...opts }),
    },
  );
}

export function fetchDockerDf() {
  return getJson<DockerDiskUsage>("/api/docker/df");
}

export function startDockerPrune(opts: DockerPruneOptions) {
  return getJson<{ ok: boolean; job: ActionJob }>("/api/docker/prune", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      confirm: true,
      volumes_confirm: Boolean(opts.volumes),
      ...opts,
    }),
  });
}

export function fetchJob(jobId: string) {
  return getJson<ActionJob>(`/api/jobs/${encodeURIComponent(jobId)}`);
}
