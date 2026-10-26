#!/usr/bin/env bash
# One-command install / upgrade of the Databricks Security Posture bundle.
#   ./deploy.sh                       interactive (asks for catalog, group, warehouse)
#   ./deploy.sh --profile ws --yes    non-interactive, reuses the previous answers
#   ./deploy.sh --help                all options
# Requires the Databricks CLI (>= 1.3.0, logged in with `databricks auth login`) and python3.
set -euo pipefail
cd "$(dirname "$0")"
command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
exec python3 tools/install.py "$@"
