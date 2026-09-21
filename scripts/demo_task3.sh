#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Git Bash on Windows rewrites leading-slash arguments as host paths before
# they reach docker.exe, which breaks the /workspace/... paths passed to the
# trivy container below. Harmless on Linux/macOS, where this variable is unused.
export MSYS_NO_PATHCONV=1

mkdir -p reports/sca/last-run reports/container/last-run reports/iac/last-run
rm -rf reports/container/last-run/* reports/iac/last-run/*

docker compose -f docker-compose.security.yml build sca
# Validate the approval record, then compare the current Docker image ID.
image=$(docker compose -f docker-compose.security.yml run --rm -T gate python scripts/approved_image.py name)
expected=$(docker compose -f docker-compose.security.yml run --rm -T gate python scripts/approved_image.py id)
actual=$(docker image inspect "$image" --format '{{.Id}}')
[[ "$actual" == "$expected" ]] || { echo "BLOCK: approved image changed; rerun Task 1"; exit 2; }

echo "=== SCA (pip-audit) ==="
docker compose -f docker-compose.security.yml run --rm sca

echo "=== Container image scan (Trivy) - ${image} ==="
docker save "${image}" -o reports/container/last-run/image.tar
docker compose -f docker-compose.security.yml run --rm trivy \
  image --input /workspace/reports/container/last-run/image.tar --format json \
  --output /workspace/reports/container/last-run/trivy-image.json --quiet
docker compose -f docker-compose.security.yml run --rm gate \
  python scripts/container_gate.py reports/container/last-run/trivy-image.json --expected-image-id "$expected"

echo "=== IaC scan (Trivy config: Dockerfile + k8s manifests) ==="
docker compose -f docker-compose.security.yml run --rm trivy \
  config --format json --output /workspace/reports/iac/last-run/trivy-config.json \
  --skip-dirs .venv,.git,.pytest_cache,reports,.task2 /workspace --quiet
docker compose -f docker-compose.security.yml run --rm gate \
  python scripts/iac_gate.py reports/iac/last-run/trivy-config.json

echo "Task 3 scans complete; reports under reports/sca, reports/container, reports/iac."
