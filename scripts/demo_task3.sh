#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Git Bash on Windows rewrites leading-slash arguments as host paths before
# they reach docker.exe, which breaks the /workspace/... paths passed to the
# trivy container below. Harmless on Linux/macOS, where this variable is unused.
export MSYS_NO_PATHCONV=1

mkdir -p reports/sca/last-run reports/container/last-run reports/iac/last-run
rm -rf reports/container/last-run/* reports/iac/last-run/*

docker compose build app
docker compose -f docker-compose.security.yml build sca

image=appsec-demo:local
if [[ -f reports/task1/approved-image.json ]]; then
  recorded=$(sed -n 's/.*"image"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' reports/task1/approved-image.json | head -1)
  # Only trust the recorded approval if that image still exists locally;
  # an older local run's record must never silently redirect the scan.
  if [[ -n "$recorded" ]] && docker image inspect "$recorded" > /dev/null 2>&1; then
    image="$recorded"
  fi
fi

echo "=== SCA (pip-audit) ==="
docker compose -f docker-compose.security.yml run --rm sca

echo "=== Container image scan (Trivy) - ${image} ==="
docker save "${image}" -o reports/container/last-run/image.tar
docker compose -f docker-compose.security.yml run --rm trivy \
  image --input /workspace/reports/container/last-run/image.tar --format json \
  --output /workspace/reports/container/last-run/trivy-image.json --quiet
docker compose -f docker-compose.security.yml run --rm gate \
  python scripts/container_gate.py reports/container/last-run/trivy-image.json

echo "=== IaC scan (Trivy config: Dockerfile + k8s manifests) ==="
docker compose -f docker-compose.security.yml run --rm trivy \
  config --format json --output /workspace/reports/iac/last-run/trivy-config.json \
  --skip-dirs .venv,.git,.pytest_cache,reports,.task2 /workspace --quiet
docker compose -f docker-compose.security.yml run --rm gate \
  python scripts/iac_gate.py reports/iac/last-run/trivy-config.json

echo "Task 3 scans complete; reports under reports/sca, reports/container, reports/iac."
