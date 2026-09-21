"""Shared validation and bounded, repository-reviewed risk exceptions."""
import json
from datetime import date
from pathlib import Path

SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}

def require(condition, message):
    if not condition:
        raise ValueError(message)

def text(value):
    return isinstance(value, str) and bool(value.strip())

def exceptions(path, today=None):
    today = today or date.today()
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    require(isinstance(data, dict) and data.get("version") == 1 and isinstance(data.get("exceptions"), list), "invalid exception policy")
    seen = set()
    for item in data["exceptions"]:
        require(isinstance(item, dict), "invalid exception")
        fields = ("scanner", "id", "package", "installed", "scope", "reason", "mitigation", "owner", "review_reference", "expires")
        require(all(text(item.get(k)) for k in fields), "exception fields missing")
        require(item["scanner"] in {"sca", "container"} and item["scope"] == "lab", "only explicit lab exceptions supported")
        require(not any("*" in item[k] for k in ("id", "package", "installed")), "wildcard exceptions forbidden")
        require(date.fromisoformat(item["expires"]) > today, "exception expired")
        key = tuple(item[k] for k in ("scanner", "id", "package", "installed"))
        require(key not in seen, "duplicate exception")
        seen.add(key)
    return data["exceptions"]

def apply_exceptions(scanner, blocking, path):
    allowed = exceptions(path)
    remaining = []
    for finding in blocking:
        match = next((e for e in allowed if e["scanner"] == scanner and all(e[k] == finding.get(k) for k in ("id", "package", "installed"))), None)
        if match:
            print(f"EXCEPTION (lab only): {finding['id']} {finding['package']} until {match['expires']} review={match['review_reference']}")
        else:
            remaining.append(finding)
    return remaining
