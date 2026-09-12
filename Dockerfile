# --- Frontend build ---
FROM node:22-alpine AS frontend
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Docker CLI + Compose plugin (Compose-first container updates)
FROM docker:27-cli AS dockercli

# --- Backend runtime ---
FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iputils-ping \
        ca-certificates \
        curl \
        git \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin \
    && test -x /usr/local/bin/trivy \
    && /usr/local/bin/trivy --version \
    && ln -sf /usr/local/bin/trivy /usr/bin/trivy \
    && ARCH="$(dpkg --print-architecture)" \
    && case "$ARCH" in amd64) OA=amd64 ;; arm64) OA=arm64 ;; *) OA=amd64 ;; esac \
    && OSCA_VER="$(curl -sL https://api.github.com/repos/XmirrorSecurity/OpenSCA-cli/releases/latest \
        | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)" \
    && test -n "$OSCA_VER" \
    && mkdir -p /tmp/opensca-install \
    && curl -sL "https://github.com/XmirrorSecurity/OpenSCA-cli/releases/download/${OSCA_VER}/opensca-cli-${OSCA_VER}-linux-${OA}.tar.gz" \
        | tar -xz -C /tmp/opensca-install \
    && OSCA_BIN="$(find /tmp/opensca-install -type f -name 'opensca-cli' | head -1)" \
    && test -n "$OSCA_BIN" \
    && install -m 0755 "$OSCA_BIN" /usr/local/bin/opensca-cli \
    && rm -rf /tmp/opensca-install \
    && opensca-cli -version || true \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

ENV PATH="/usr/local/bin:${PATH}"

# Required for Update: `docker compose pull` + `up -d` against compose projects
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
RUN mkdir -p /usr/local/lib/docker/cli-plugins /usr/local/libexec/docker/cli-plugins
COPY --from=dockercli /usr/local/libexec/docker/cli-plugins/docker-compose \
    /usr/local/libexec/docker/cli-plugins/docker-compose
RUN ln -sf /usr/local/libexec/docker/cli-plugins/docker-compose \
        /usr/local/lib/docker/cli-plugins/docker-compose \
    && chmod +x /usr/local/libexec/docker/cli-plugins/docker-compose \
    && docker compose version

WORKDIR /app

COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/app ./app
COPY --from=frontend /frontend/dist ./static

ENV PYTHONUNBUFFERED=1
ENV TRIVY_CACHE_DIR=/data/trivy
# Host metrics / listening ports: Compose should set HOST_PROC=/host/proc and
# HOST_ROOT=/host with volume /:/host:ro (see docker-compose.yml).
EXPOSE 8080

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
