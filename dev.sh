#!/usr/bin/env bash
# Local backend starter for Homelab Watcher (uvicorn only — no frontend).
# Usage: ./dev.sh   or   bash dev.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

BACKEND_DIR="$SCRIPT_DIR/backend"
VENV_DIR="$BACKEND_DIR/.venv"
REQS="$BACKEND_DIR/requirements.txt"
DATA_DIR="$SCRIPT_DIR/data"
COLIMA_SOCK="${HOME}/.colima/default/docker.sock"

resolve_python312() {
  if command -v python3.12 >/dev/null 2>&1; then
    command -v python3.12
    return 0
  fi
  if command -v brew >/dev/null 2>&1; then
    local brew_py
    brew_py="$(brew --prefix python@3.12 2>/dev/null)/bin/python3.12"
    if [[ -x "$brew_py" ]]; then
      echo "$brew_py"
      return 0
    fi
  fi
  echo "error: Python 3.12 not found. Install with: brew install python@3.12" >&2
  exit 1
}

if [[ ! -d "$VENV_DIR" ]]; then
  PY312="$(resolve_python312)"
  echo "Creating venv with $PY312 → $VENV_DIR"
  "$PY312" -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

if ! python -c "import uvicorn" >/dev/null 2>&1; then
  echo "Installing backend requirements…"
  python -m pip install -r "$REQS"
else
  # Quick refresh so deps stay aligned with requirements.txt
  python -m pip install -q -r "$REQS"
fi

mkdir -p "$DATA_DIR"

if [[ ! -f "$SCRIPT_DIR/config.yaml" && -f "$SCRIPT_DIR/config.example.yaml" ]]; then
  cp "$SCRIPT_DIR/config.example.yaml" "$SCRIPT_DIR/config.yaml"
  echo "Created config.yaml from config.example.yaml"
fi

export DATABASE_PATH="${DATABASE_PATH:-$DATA_DIR/homelab-watcher.db}"
export CONFIG_PATH="${CONFIG_PATH:-$SCRIPT_DIR/config.yaml}"

if [[ -S "$COLIMA_SOCK" ]]; then
  export DOCKER_HOST="unix://$COLIMA_SOCK"
  echo "DOCKER_HOST=$DOCKER_HOST"
fi

echo "DATABASE_PATH=$DATABASE_PATH"
echo "CONFIG_PATH=$CONFIG_PATH"
echo "API → http://127.0.0.1:8080"
echo "Docs → http://127.0.0.1:8080/docs"
echo "(Frontend separately: cd frontend && npm install && npm run dev → http://127.0.0.1:5173)"
echo

cd "$BACKEND_DIR"
exec python -m uvicorn app.main:app --host 127.0.0.1 --port 8080 --reload
