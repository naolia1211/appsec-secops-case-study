"""Run pip-audit against requirements.txt, then apply the independent JSON gate."""
from pathlib import Path
import importlib.util
import subprocess
import sys


def main():
    report = Path("reports/sca/last-run/pip-audit.json")
    report.parent.mkdir(parents=True, exist_ok=True)
    report.unlink(missing_ok=True)  # Never accept evidence from an earlier scan.
    if importlib.util.find_spec("pip_audit") is None:
        print("BLOCK: pip-audit is not installed")
        return 2
    command = [sys.executable, "-m", "pip_audit", "-r", "requirements.txt", "--format", "json", "--output", str(report)]
    # pip-audit's own exit code does not distinguish "vulnerabilities found" from
    # "dependency resolution failed"; the gate below decides policy from the report itself.
    result = subprocess.run(command, check=False)
    if result.returncode not in (0, 1):
        print("BLOCK: scanner execution failed")
        return 2
    if not report.exists():
        print("BLOCK: pip-audit did not produce a report (dependency resolution likely failed)")
        return 2
    return subprocess.run([sys.executable, "scripts/sca_gate.py", str(report)], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
