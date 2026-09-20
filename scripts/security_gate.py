"""Exit 0: pass; 1: blocking finding; 2: invalid/incomplete scan."""
import argparse
from collections import Counter
import json
import os
from pathlib import Path


def evaluate(report):
    if not isinstance(report, dict):
        raise ValueError("report must be an object")
    if not isinstance(report.get("results"), list) or not isinstance(report.get("errors"), list):
        raise ValueError("report must contain results and errors arrays")
    if report["errors"]:
        raise ValueError("scanner reported errors; scan cannot be trusted")
    paths = report.get("paths")
    if not isinstance(paths, dict) or not isinstance(paths.get("scanned"), list) or not paths["scanned"]:
        raise ValueError("no scanned files recorded")
    counts = Counter({"ERROR": 0, "WARNING": 0, "INFO": 0})
    for finding in report["results"]:
        if not isinstance(finding, dict) or not isinstance(finding.get("extra"), dict):
            raise ValueError("malformed finding")
        severity = finding["extra"].get("severity")
        if not isinstance(severity, str) or severity not in counts:
            raise ValueError(f"unknown severity: {severity!r}")
        counts[severity] += 1
    return (1 if counts["ERROR"] else 0), dict(counts)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args(argv)
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        code, counts = evaluate(report)
    except (OSError, ValueError) as error:
        print(f"BLOCK: {error}")
        return 2
    for finding in report["results"]:
        print(f"{finding['extra']['severity']}: {finding.get('check_id', '?')} at {finding.get('path', '?')}")
    print(f"{'BLOCK' if code else 'PASS'}: {json.dumps(counts, sort_keys=True)}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as stream:
            stream.write("## SAST security gate\n\n")
            stream.write(f"Decision: **{'BLOCK' if code else 'PASS'}**\n\n")
            stream.write("| Severity | Findings |\n| --- | ---: |\n")
            for severity, count in counts.items():
                stream.write(f"| {severity} | {count} |\n")
            stream.write("\nActual Semgrep JSON: download the `sast-report` artifact.\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
