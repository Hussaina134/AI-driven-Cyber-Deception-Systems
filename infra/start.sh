#!/usr/bin/env bash
set -e
# move to this script's folder
cd "$(dirname "$0")"
# Use docker compose (modern plugin)
docker compose -f docker-compose.yml up -d --build
echo "Stack started. Cowrie mapped to host port 2222 (keep VM network isolated)."
