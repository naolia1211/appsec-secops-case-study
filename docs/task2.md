# Task 2 â€” Kubernetes deployment and hardening

The lab runs K3s nodes in Docker through k3d. K3s uses Flannel for pod networking
and its built-in kube-router controller for NetworkPolicy enforcement. The test
checks packet reachability; creating a NetworkPolicy object alone is not evidence
that it is enforced.

## Run

Requirements: Docker Engine with Linux containers, Compose v2, a shell for the
Task 1 demo, network access for initial downloads, and roughly 4 GB free RAM.
The toolbox contains k3d 5.8.3 and kubectl 1.32.5; nodes use K3s 1.32.5-k3s1.
These are pinned lab versions, not a recommendation to deploy them in production.

```bash
bash scripts/demo.sh
docker compose -f docker-compose.k8s.yml build lab
docker compose -f docker-compose.k8s.yml run --rm lab all
```

Task 1 writes `reports/task1/approved-image.json` only after tests and SAST pass.
Task 2 verifies that the Docker image ID still matches this approval record, then
imports that image into k3d. It never rebuilds the application. Manifests use
`imagePullPolicy: Never` to avoid silently fetching a different image.

The runtime substitutions are written under `.task2/rendered/`; source manifests
retain the explicit placeholder `appsec-demo:task1`. Always use the wrapper rather
than applying the placeholder directly.

The lab has its own kubeconfig under `.task2/` and does not change the host's current
Kubernetes context. The API binds to host loopback port 6550. Docker socket access
lets the toolbox manage the lab's node containers; run it only against your local
development Docker daemon.

```bash
# Repeat checks while before/after namespaces still exist
docker compose -f docker-compose.k8s.yml run --rm lab verify
# Remove only this dedicated cluster
docker compose -f docker-compose.k8s.yml run --rm lab destroy
```

`all` creates both the intentionally insecure and hardened namespaces. Delete the
insecure namespace after the demonstration, or destroy the lab. Do not apply the
insecure manifests to a shared cluster.

## Open the hardened API locally

```bash
docker compose -f docker-compose.k8s.yml run --rm -p 127.0.0.1:18081:18081 lab serve
```

Keep that terminal open and visit `http://localhost:18081/health`. Port-forward is
an administrative access path, not proof of NetworkPolicy enforcement. The probe
tests above exercise actual pod-to-pod traffic.

```bash
docker compose -f docker-compose.k8s.yml run --rm lab clean-insecure
```

This removes the insecure workload and test namespaces while keeping the hardened
API. Run `all` again to recreate the before/after comparison.

## Findings and remediation

This is a documented manual configuration review backed by automated runtime
checks. It is not presented as a kube-bench, kubesec or Trivy report.

| Finding in insecure manifest | Risk and plausible impact | Hardened change | Evidence |
| --- | --- | --- | --- |
| UID 0 and privileged container | An application compromise gains unnecessary kernel/device capabilities; impact is greater than non-root execution | UID/GID 10001, non-root, privileged false, drop ALL, no privilege escalation, RuntimeDefault seccomp | Runtime UID, CapEff, NoNewPrivs, Seccomp |
| Writable root filesystem | Compromised process can modify binaries/configuration or persist files in the container | Read-only root filesystem | Write to /tmp fails with EROFS |
| No CPU or memory requests/limits | Unbounded resource use can starve neighbors; scheduling has no workload request | 100m/64Mi requests; 500m/128Mi limits | Live pod resource fields; this does not claim a stress test |
| No NetworkPolicy | Unapproved pods can reach the API; a compromised app can initiate arbitrary traffic | Default deny ingress and egress; allow only approved clients and DNS | Allowed/denied ingress, denied egress, successful DNS |
| Default service account with wildcard namespace Role and token mount | Token theft can read Secrets or modify workloads within the namespace | Dedicated service account, no RoleBinding and no token automount | Impersonated can-i queries and token-file check |
| Plain demonstration key in env | Real credentials would be exposed through manifest access and source control | Remove the unused variable; the app requires no secret | Before/after manifest review |

The demonstration key is public dummy data, not a real credential. If a future
dependency requires credentials, use a Secret or external secret manager and
restrict access. Base64 encoding in a Secret does not encrypt its contents.

## Why no RoleBinding in the hardened namespace

The Flask API does not call Kubernetes. Its least-privilege permission set is
therefore no workload/Secret API permissions. Adding a read-only Role would grant
access the application does not need. The tests compare `get secrets`, `list pods`
and `create deployments`: allowed for the insecure account and denied for the
hardened account. The lab administrator uses impersonation for these checks; the
application itself has neither that privilege nor a mounted token.

## Network tests

Probe pods use the same application image, with Python's HTTP client. The approved
client must have both the `appsec-clients` namespace and `access=approved` pod label.
An unapproved pod in the correct namespace and an approved-labelled pod in another
namespace must both be blocked (timeout or connection refusal), with a successful approved-client control against the same endpoint. A reachable HTTP sink is used as a positive control
before verifying that hardened app egress to it is blocked.

DNS is explicitly allowed to CoreDNS in kube-system over UDP/TCP 53. Native
NetworkPolicy controls L3/L4 traffic, not URL paths or DNS query names. Node-originated
health probes and administrative `kubectl exec` are not used as substitutes for
pod-to-pod ingress tests. Label modification privileges must be controlled because
the policy selects labels, not an authenticated user identity.

The hardened namespace also enforces the native Restricted Pod Security Standard.
A server-side dry run confirms that a privileged pod is rejected by admission.
No Kyverno or OPA installation is claimed.

## Brownfield NetworkPolicy rollout

1. Inventory services, owners, ingress paths, DNS and outbound dependencies. Collect
   application/access logs and available network flow telemetry across normal and
   peak periods before writing allow rules.
2. Map flows to stable namespace/pod labels and ports. Validate DNS, monitoring,
   probes, deployment hooks and batch jobs with the service owners. Record expected
   success and failure tests and baseline error/latency rates.
3. Test the proposed policies in a staging namespace. Native NetworkPolicy has no
   standard audit-only enforcement mode; `--dry-run=server` validates the object,
   not whether live traffic would break. Log-only observation needs suitable CNI
   tooling or external telemetry.
4. Apply explicit allow policies and default-deny to a canary scope in a controlled
   change window. Policies are additive: an allow policy selecting a pod can already
   isolate it, so applying allow rules first is not a harmless observation phase.
5. Check business transactions, DNS and negative tests. Expand by workload only
   after the canary is stable. Keep reviewed policy files and an owner-approved
   rollback procedure; remove the new isolating policies for the affected scope if
   critical traffic breaks, then investigate before re-enforcing.

## Evidence

`reports/k8s/last-run/verification.json` records each expected/actual result and
the source image approval. Namespace snapshots and admission output accompany it.
Any mismatch makes the verification command fail. `.task2/` contains credentials
and generated manifests and is gitignored; no kubeconfig or token belongs in Git.

References: [K3s networking](https://docs.k3s.io/networking/networking-services),
[NetworkPolicy](https://kubernetes.io/docs/concepts/services-networking/network-policies/),
[Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/).
