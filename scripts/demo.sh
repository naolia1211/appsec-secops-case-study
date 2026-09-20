#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p reports/task1
rm -f reports/task1/approved-image.json
docker compose --profile checks build app test
docker compose --profile checks run --rm test
docker compose --profile checks run --rm security
mkdir -p reports/task1
docker image inspect appsec-demo:local --format '{"image":"appsec-demo:local","image_id":"{{.Id}}","source":"local Task 1 gate"}' > reports/task1/approved-image.json
# Reuse the image built above; deployment is reached only after the gate passes.
docker compose up -d --no-build --wait --wait-timeout 90 app
docker compose exec -T app python -c 'import json, urllib.request; assert json.load(urllib.request.urlopen("http://127.0.0.1:8080/health", timeout=5)) == {"status": "ok"}; assert json.load(urllib.request.urlopen("http://127.0.0.1:8080/api/greeting?name=CI", timeout=5)) == {"message": "Hello, CI!"}; print("Deploy mock: PASS")'
echo 'API: http://localhost:18080/health'
echo 'Stop the local service with: docker compose down'
