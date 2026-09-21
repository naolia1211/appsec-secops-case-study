"""Exit 0: pass; 1: a dependency has a published fix and is not upgraded; 2: invalid/incomplete scan."""
import argparse
import json
from pathlib import Path
try:
    from .scan_policy import require, text, SEVERITIES, apply_exceptions
except ImportError:
    from scan_policy import require, text, SEVERITIES, apply_exceptions


def evaluate(report):
    if not isinstance(report, dict) or not isinstance(report.get("dependencies"), list):
        raise ValueError("report must contain a dependencies array")
    require(bool(report["dependencies"]), "empty dependency scan")
    actionable, watch = [], []
    for dependency in report["dependencies"]:
        if not isinstance(dependency, dict) or not isinstance(dependency.get("vulns"), list):
            raise ValueError("malformed dependency entry")
        require(text(dependency.get("name")) and text(dependency.get("version")) and not dependency.get("skip_reason"), "incomplete dependency scan")
        for vuln in dependency["vulns"]:
            if not isinstance(vuln, dict):
                raise ValueError("malformed vulnerability entry")
            require(text(vuln.get("id")) and isinstance(vuln.get("fix_versions"), list) and all(text(v) for v in vuln["fix_versions"]), "invalid vulnerability")
            entry = {"package": dependency.get("name"), "installed": dependency.get("version"), "id": vuln.get("id"), "fix_versions": vuln.get("fix_versions") or []}
            actionable.append(entry)  # pip-audit has no severity: every advisory requires disposition.
    return (1 if actionable else 0), actionable, watch


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--exceptions", type=Path, default=Path("security/exceptions.json"))
    args = parser.parse_args(argv)
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        code, actionable, watch = evaluate(report)
        expected = {line.split("==")[0].strip().lower().replace("_", "-") for line in Path("requirements.txt").read_text().splitlines() if "==" in line}
        scanned = {d["name"].lower().replace("_", "-") for d in report["dependencies"]}
        require(expected <= scanned, "missing direct dependencies in scan")
        actionable = apply_exceptions("sca", actionable, args.exceptions)
        code = 1 if actionable else 0
    except (OSError, ValueError) as error:
        print(f"BLOCK: {error}")
        return 2
    for entry in actionable:
        print(f"BLOCK-CANDIDATE: {entry['package']} {entry['installed']} ({entry['id']}) -> {', '.join(entry['fix_versions'])}")
    for entry in watch:
        print(f"WATCH (no fix yet): {entry['package']} {entry['installed']} ({entry['id']})")
    print(f"{'BLOCK' if code else 'PASS'}: {len(actionable)} blocking, {len(watch)} warning")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
