#!/usr/bin/env bash
set -euo pipefail

venv="$RUNNER_TEMP/hch-venv"
if ! python3.12 -m venv "$venv" || ! command -v psql >/dev/null; then
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3.12-venv postgresql-client
  python3.12 -m venv "$venv"
fi
"$venv/bin/python" -m pip install --disable-pip-version-check -r apps/api/requirements.lock
"$venv/bin/python" -m pip install --disable-pip-version-check -e 'apps/api[dev]'
echo "$venv/bin" >> "$GITHUB_PATH"
