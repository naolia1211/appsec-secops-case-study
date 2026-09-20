#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

docker compose --profile checks build app test
docker compose --profile checks run --rm test
docker compose --profile checks run --rm security
# Reuse the image built above; deployment is reached only after the gate passes.
docker compose up -d --no-build --wait --wait-timeout 90 app
docker compose exec -T app python -c 'import json, urllib.request; assert json.load(urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=5)) == {"status": "ok"}; assert json.load(urllib.request.urlopen("http://127.0.0.1:8080/api/greeting?name=CI", timeout=5)) == {"message": "Hello, CI!"}; print("Deploy mock: PASS")'
echo 'API: http://localhost:18080/health'
echo 'Stop the local service with: docker compose down'
