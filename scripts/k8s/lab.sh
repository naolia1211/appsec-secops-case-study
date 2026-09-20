#!/usr/bin/env bash
set -euo pipefail
cd /workspace
mkdir -p .task2 reports/k8s/last-run
chmod 700 .task2
export KUBECONFIG=/workspace/.task2/kubeconfig
action="${1:-all}"
if [[ "$action" == "destroy" ]]; then
  k3d cluster delete appsec-lab
  rm -f "$KUBECONFIG"
  exit 0
fi
if [[ "$action" != "all" && "$action" != "verify" && "$action" != "serve" && "$action" != "clean-insecure" ]]; then
  echo 'Usage: all | verify | serve | clean-insecure | destroy' >&2
  exit 2
fi
if [[ "$action" == "all" ]]; then
  python3 scripts/k8s/render.py
  if ! k3d cluster list -o json | python3 -c 'import json,sys; sys.exit(not any(c["name"] == "appsec-lab" for c in json.load(sys.stdin)))'; then
    k3d cluster create --config k8s/cluster.yml --wait --timeout 240s
  fi
fi
# The toolbox joins the lab network; the host kubeconfig is never modified.
docker network connect k3d-appsec-lab "$HOSTNAME" 2>/dev/null ||   docker inspect "$HOSTNAME" --format '{{json .NetworkSettings.Networks}}' | grep -q 'k3d-appsec-lab'
k3d kubeconfig get appsec-lab > "$KUBECONFIG"
chmod 600 "$KUBECONFIG"
kubectl config set-cluster k3d-appsec-lab --server=https://k3d-appsec-lab-server-0:6443
kubectl wait --for=condition=Ready nodes --all --timeout=180s
if [[ "$action" == "serve" ]]; then
  exec kubectl -n appsec-hardened port-forward --address=0.0.0.0 service/appsec-demo 18081:8080
fi
if [[ "$action" == "clean-insecure" ]]; then
  kubectl delete namespace appsec-insecure appsec-clients appsec-outsider --ignore-not-found --wait=true --timeout=120s
  exit 0
fi
if [[ "$action" == "all" ]]; then
  image=$(python3 -c 'import json; print(json.load(open("reports/task1/approved-image.json"))["image"])')
  k3d image import "$image" --cluster appsec-lab
  kubectl apply -f .task2/rendered/insecure.yml
  kubectl apply -f .task2/rendered/hardened.yml
  kubectl apply -f k8s/hardened/network-policy.yml
  kubectl apply -f .task2/rendered/probes.yml
fi
python3 scripts/k8s/verify.py
