"""Exit 0: pass; 1: an image vulnerability has a fixed version available; 2: invalid/incomplete scan."""
import argparse
import json
from pathlib import Path


def evaluate(report):
    if not isinstance(report, dict) or not isinstance(report.get("Results"), list):
        raise ValueError("report must contain a Results array")
    actionable, watch = [], []
    for result in report["Results"]:
        if not isinstance(result, dict):
            raise ValueError("malformed result entry")
        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict) or not isinstance(vuln.get("Severity"), str):
                raise ValueError("malformed vulnerability entry")
            entry = {"target": result.get("Target"), "package": vuln.get("PkgName"), "installed": vuln.get("InstalledVersion"), "id": vuln.get("VulnerabilityID"), "severity": vuln["Severity"], "fixed": vuln.get("FixedVersion")}
            (actionable if entry["fixed"] else watch).append(entry)
    return (1 if actionable else 0), actionable, watch


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args(argv)
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        code, actionable, watch = evaluate(report)
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
    print(f"{'BLOCK' if code else 'PASS'}: {len(actionable)} fixable, {len(watch)} unfixed")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
