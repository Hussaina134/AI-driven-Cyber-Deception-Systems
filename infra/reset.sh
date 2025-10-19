
#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
docker compose -f docker-compose.yml down --volumes --remove-orphans
# remove logs and DB data (careful: this deletes local data)
rm -rf ../honeypot/cowrie/log/*
rm -rf ../data/mongo/*
docker compose -f docker-compose.yml up -d --build
echo "Stack reset and restarted."

