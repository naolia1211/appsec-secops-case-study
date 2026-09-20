"""Run a real scan and then apply the independent JSON gate."""
from pathlib import Path
import subprocess
import shutil
import sys


def main():
    report = Path("reports/sast/semgrep.json")
    report.parent.mkdir(parents=True, exist_ok=True)
    report.unlink(missing_ok=True)  # Never accept evidence from an earlier scan.
    scanner = Path(sys.executable).parent / ("semgrep.exe" if sys.platform == "win32" else "semgrep")
    executable = str(scanner) if scanner.exists() else shutil.which("semgrep")
    if not executable:
        print("BLOCK: Semgrep CLI is not installed")
        return 2
    command = [executable, "scan", "--config", ".semgrep.yml", "--config", "p/python",
               "--json", "--output", str(report), "--metrics=off", "--disable-version-check",
               "--disable-nosem", "--strict", "app", "scripts"]
    scan = subprocess.run(command, check=False)
    if scan.returncode:
        print(f"BLOCK: scanner failed (exit {scan.returncode})", flush=True)
        return 2
    return subprocess.run([sys.executable, "scripts/security_gate.py", str(report)], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
