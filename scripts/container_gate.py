"""Exit 0: pass; 1: an image vulnerability has a fixed version available; 2: invalid/incomplete scan."""
import argparse
import json
from pathlib import Path
try:
    from .scan_policy import require, text, SEVERITIES, apply_exceptions
except ImportError:
    from scan_policy import require, text, SEVERITIES, apply_exceptions


def evaluate(report):
    if not isinstance(report, dict) or not isinstance(report.get("Results"), list):
        raise ValueError("report must contain a Results array")
    require(report.get("SchemaVersion") == 2 and report.get("ArtifactType") == "container_image", "not a Trivy image report")
    require({"os-pkgs", "lang-pkgs"} <= {r.get("Class") for r in report["Results"] if isinstance(r, dict)}, "missing OS or Python scan coverage")
    actionable, watch = [], []
    for result in report["Results"]:
        if not isinstance(result, dict):
            raise ValueError("malformed result entry")
        require(result.get("Vulnerabilities") is None or isinstance(result["Vulnerabilities"], list), "invalid vulnerabilities")
        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict) or not isinstance(vuln.get("Severity"), str):
                raise ValueError("malformed vulnerability entry")
            require(vuln.get("Severity") in SEVERITIES and all(text(vuln.get(k)) for k in ("PkgName", "InstalledVersion", "VulnerabilityID")), "invalid vulnerability identity or severity")
            entry = {"target": result.get("Target"), "package": vuln.get("PkgName"), "installed": vuln.get("InstalledVersion"), "id": vuln.get("VulnerabilityID"), "severity": vuln["Severity"], "fixed": vuln.get("FixedVersion")}
            (actionable if entry["fixed"] or entry["severity"] in {"HIGH", "CRITICAL", "UNKNOWN"} else watch).append(entry)
    return (1 if actionable else 0), actionable, watch


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--expected-image-id")
    parser.add_argument("--exceptions", type=Path, default=Path("security/exceptions.json"))
    args = parser.parse_args(argv)
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        code, actionable, watch = evaluate(report)
        if args.expected_image_id:
            require(report.get("Metadata", {}).get("ImageID") == args.expected_image_id, "scan image differs from approval")
        actionable = apply_exceptions("container", actionable, args.exceptions)
        code = 1 if actionable else 0
    except (OSError, ValueError) as error:
        print(f"BLOCK: {error}")
        return 2
    for entry in actionable:
        print(f"BLOCK-CANDIDATE: {entry['severity']} {entry['package']} {entry['installed']} ({entry['id']}) -> {entry['fixed']} [{entry['target']}]")
    unfixed_by_severity = {}
    for entry in watch:
        unfixed_by_severity[entry["severity"]] = unfixed_by_severity.get(entry["severity"], 0) + 1
    if unfixed_by_severity:
        print(f"WATCH (no fix published yet): {unfixed_by_severity}")
    print(f"{'BLOCK' if code else 'PASS'}: {len(actionable)} blocking, {len(watch)} warning")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
