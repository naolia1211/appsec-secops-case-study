"""Render lab manifests using a previously approved Task 1 image."""
import json
from pathlib import Path
import subprocess
import yaml

record = json.loads(Path("reports/task1/approved-image.json").read_text())
image = record["image"]
if not isinstance(image, str) or not image.startswith("appsec-demo:") or any(c.isspace() for c in image):
    raise SystemExit("Invalid application image reference")
actual = subprocess.check_output(["docker", "image", "inspect", image, "--format", "{{.Id}}"], text=True).strip()
if actual != record["image_id"]:
    raise SystemExit("Image differs from the Task 1 approval record; rerun Task 1")
out = Path(".task2/rendered")
out.mkdir(parents=True, exist_ok=True)
for source, target in [("k8s/insecure/app.yml", "insecure.yml"), ("k8s/hardened/app.yml", "hardened.yml")]:
    docs = list(yaml.safe_load_all(Path(source).read_text()))
    for item in docs:
        if item["kind"] == "Deployment":
            item["spec"]["template"]["spec"]["containers"][0]["image"] = image
    (out / target).write_text(yaml.safe_dump_all(docs, sort_keys=False))
docs = [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": n}} for n in ["appsec-clients", "appsec-outsider"]]
for name, namespace, access, serve in [
    ("allowed", "appsec-clients", "approved", False),
    ("denied", "appsec-clients", "unapproved", False),
    ("outsider", "appsec-outsider", "approved", False),
    ("sink", "appsec-clients", "sink", True),
]:
    container = {"name": "probe", "image": image, "imagePullPolicy": "Never", "resources": {"requests": {"cpu": "25m", "memory": "32Mi"}, "limits": {"cpu": "200m", "memory": "128Mi"}}}
    if not serve:
        container["command"] = ["python", "-c", "import time; time.sleep(3600)"]
    docs.append({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": namespace, "labels": {"access": access}}, "spec": {"automountServiceAccountToken": False, "containers": [container]}})
(out / "probes.yml").write_text(yaml.safe_dump_all(docs, sort_keys=False))
print(f"Verified Task 1 image {image} ({actual})")
