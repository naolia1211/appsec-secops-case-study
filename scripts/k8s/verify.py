"""Exercise the lab's runtime controls and save real observations as JSON."""
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess

OUT = Path("reports/k8s/last-run")
OUT.mkdir(parents=True, exist_ok=True)
checks = []


def command(*args, input_text=None, required=True):
    result = subprocess.run(list(args), input=input_text, text=True, capture_output=True, timeout=240)
    if required and result.returncode:
        raise RuntimeError(f"{' '.join(args[:5])}: {result.stderr.strip()}")
    return result


def kubectl(*args, **kwargs):
    return command("kubectl", *args, **kwargs)


def record(name, actual, expected):
    ok = actual == expected
    checks.append({"check": name, "expected": expected, "actual": actual, "passed": ok})
    print(f"{'PASS' if ok else 'FAIL'}: {name}", flush=True)
    if not ok:
        raise AssertionError(f"{name}: expected {expected!r}, got {actual!r}")


def pod(namespace):
    data = json.loads(kubectl("-n", namespace, "get", "pods", "-l", "app=appsec-demo", "-o", "json").stdout)
    running = [p for p in data["items"] if not p["metadata"].get("deletionTimestamp") and p["status"]["phase"] == "Running"]
    if len(running) != 1:
        raise RuntimeError(f"Expected one running app in {namespace}")
    return running[0]


def execute(namespace, name, program):
    return kubectl("-n", namespace, "exec", name, "--", "python", "-c", program).stdout.strip()


def http(namespace, name, target):
    # Run inside the pod to exercise NetworkPolicy.
    program = """import json, urllib.request, urllib.error
try:
    with urllib.request.urlopen(TARGET, timeout=3) as response:
        print(json.dumps({"reachable": True, "body": json.load(response)}))
except (OSError, urllib.error.URLError) as error:
    reason = getattr(error, "reason", error)
    print(json.dumps({"reachable": False, "error_type": type(reason).__name__}))
""".replace("TARGET", repr(target))
    return json.loads(execute(namespace, name, program))


def blocked(namespace, name, target, label):
    result = http(namespace, name, target)
    record(label, result.get("reachable") is False and result.get("error_type") in ("TimeoutError", "ConnectionRefusedError"), True)
    checks[-1]["observation"] = result
    # A negative response alone could mean a dead server; require a live control.
    record(label + " positive control", http("appsec-clients", "allowed", target), {"reachable": True, "body": {"status": "ok"}})


def verify():
    approval = json.loads(Path("reports/task1/approved-image.json").read_text())
    for ns in ["appsec-insecure", "appsec-hardened"]:
        kubectl("-n", ns, "rollout", "status", "deployment/appsec-demo", "--timeout=180s")
    for ns in ["appsec-clients", "appsec-outsider"]:
        kubectl("-n", ns, "wait", "--for=condition=Ready", "pods", "--all", "--timeout=180s")
    pods = {ns: pod(ns) for ns in ["appsec-insecure", "appsec-hardened"]}
    before, after = pods.values()
    image_ids = []
    for ns, data in pods.items():
        record(f"{ns} uses approved Task 1 image", data["spec"]["containers"][0]["image"], approval["image"])
        image_ids.append(data["status"]["containerStatuses"][0]["imageID"])
    record("Before and after resolve to the same image", image_ids[0], image_ids[1])
    for ns, expected_uid, expected_token in [("appsec-insecure", "0", "True"), ("appsec-hardened", "10001", "False")]:
        name = pods[ns]["metadata"]["name"]
        record(f"{ns} runtime UID", execute(ns, name, "import os; print(os.getuid())"), expected_uid)
        record(f"{ns} service account token mounted", execute(ns, name, "from pathlib import Path; print(Path('/var/run/secrets/kubernetes.io/serviceaccount/token').exists())"), expected_token)
    security = after["spec"]["containers"][0]["securityContext"]
    record("Privilege escalation disabled", security["allowPrivilegeEscalation"], False)
    record("All capabilities dropped", security["capabilities"]["drop"], ["ALL"])
    record("Privileged disabled", security["privileged"], False)
    record("Resource limits enforced in pod spec", after["spec"]["containers"][0]["resources"]["limits"], {"cpu": "500m", "memory": "128Mi"})
    name = after["metadata"]["name"]
    fs_program = """from pathlib import Path
import errno
try:
    Path('/tmp/appsec-write-check').write_text('test')
except OSError as error:
    print(error.errno)
else:
    print('writable')
"""
    record("Root filesystem rejects writes with EROFS", execute("appsec-hardened", name, fs_program), "30")
    status = execute("appsec-hardened", name, "from pathlib import Path; print(Path('/proc/self/status').read_text())")
    status_fields = dict(line.split(':', 1) for line in status.splitlines() if ':' in line)
    record("Runtime no new privileges", status_fields["NoNewPrivs"].strip(), "1")
    record("Runtime seccomp filter active", status_fields["Seccomp"].strip(), "2")
    record("Runtime effective capabilities empty", int(status_fields["CapEff"].strip(), 16), 0)
    for ns, sa, expected in [("appsec-insecure", "default", "yes"), ("appsec-hardened", "appsec-demo", "no")]:
        for verb, resource in [("get", "secrets"), ("list", "pods"), ("create", "deployments")]:
            response = kubectl("auth", "can-i", verb, resource, "-n", ns, f"--as=system:serviceaccount:{ns}:{sa}", required=False)
            if response.returncode not in (0, 1):
                raise RuntimeError(response.stderr)
            record(f"RBAC {ns}: {verb} {resource}", response.stdout.strip(), expected)
    before_ip, after_ip = before["status"]["podIP"], after["status"]["podIP"]
    sink = json.loads(kubectl("-n", "appsec-clients", "get", "pod", "sink", "-o", "json").stdout)["status"]["podIP"]
    record("Positive control: sink is reachable", http("appsec-clients", "allowed", f"http://{sink}:8080/health"), {"reachable": True, "body": {"status": "ok"}})
    record("Insecure app accepts unapproved client", http("appsec-clients", "denied", f"http://{before_ip}:8080/health"), {"reachable": True, "body": {"status": "ok"}})
    record("Hardened app accepts approved client", http("appsec-clients", "allowed", f"http://{after_ip}:8080/health"), {"reachable": True, "body": {"status": "ok"}})
    for ns, client in [("appsec-clients", "denied"), ("appsec-outsider", "outsider")]:
        blocked(ns, client, f"http://{after_ip}:8080/health", f"Ingress blocked from {ns}/{client}")
    record("Insecure app has unrestricted egress", http("appsec-insecure", before["metadata"]["name"], f"http://{sink}:8080/health"), {"reachable": True, "body": {"status": "ok"}})
    blocked("appsec-hardened", name, f"http://{sink}:8080/health", "Hardened app egress blocked to reachable sink")
    dns = execute("appsec-hardened", name, "import socket; print(bool(socket.gethostbyname('kubernetes.default.svc.cluster.local')))")
    record("DNS exception still permits resolution", dns, "True")
    bad_pod = {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "rejected-privileged", "namespace": "appsec-hardened"}, "spec": after["spec"]}
    bad_pod["spec"].pop("nodeName", None)
    bad_pod["spec"]["containers"][0]["securityContext"]["privileged"] = True
    bad_pod["spec"]["containers"][0]["securityContext"]["allowPrivilegeEscalation"] = True
    rejection = kubectl("create", "--dry-run=server", "-f", "-", input_text=json.dumps(bad_pod), required=False)
    (OUT / "admission.txt").write_text(rejection.stderr)
    record("Pod Security admission rejects privileged pod", rejection.returncode != 0 and 'violates PodSecurity' in rejection.stderr and 'privileged' in rejection.stderr, True)

    for ns in ["appsec-insecure", "appsec-hardened"]:
        snapshot = kubectl("-n", ns, "get", "deployments,pods,services,networkpolicies,roles,rolebindings,serviceaccounts", "-o", "json").stdout
        (OUT / f"{ns}.json").write_text(snapshot)
    return approval


error = None
approval = None
try:
    approval = verify()
except Exception as exc:
    error = str(exc)
    print(f"FAIL: {error}", flush=True)
finally:
    result = {"timestamp": datetime.now(timezone.utc).isoformat(), "cluster": "appsec-lab", "source_image": approval, "checks": checks, "passed": error is None, "error": error}
    (OUT / "verification.json").write_text(json.dumps(result, indent=2))
if error:
    raise SystemExit(1)
print(f"Verified {len(checks)} checks; evidence saved in {OUT}")
