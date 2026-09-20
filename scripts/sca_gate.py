"""Exit 0: pass; 1: a dependency has a published fix and is not upgraded; 2: invalid/incomplete scan."""
import argparse
import json
from pathlib import Path


def evaluate(report):
    if not isinstance(report, dict) or not isinstance(report.get("dependencies"), list):
        raise ValueError("report must contain a dependencies array")
    actionable, watch = [], []
    for dependency in report["dependencies"]:
        if not isinstance(dependency, dict) or not isinstance(dependency.get("vulns"), list):
            raise ValueError("malformed dependency entry")
        for vuln in dependency["vulns"]:
            if not isinstance(vuln, dict):
                raise ValueError("malformed vulnerability entry")
            entry = {"package": dependency.get("name"), "installed": dependency.get("version"), "id": vuln.get("id"), "fix_versions": vuln.get("fix_versions") or []}
            (actionable if entry["fix_versions"] else watch).append(entry)
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
        print(f"BLOCK-CANDIDATE: {entry['package']} {entry['installed']} ({entry['id']}) -> {', '.join(entry['fix_versions'])}")
    for entry in watch:
        print(f"WATCH (no fix yet): {entry['package']} {entry['installed']} ({entry['id']})")
    print(f"{'BLOCK' if code else 'PASS'}: {len(actionable)} fixable, {len(watch)} unfixed")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
