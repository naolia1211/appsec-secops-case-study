import json
import pytest
from scripts.container_gate import evaluate, main


def report(*vulns):
    # Synthetic unit-test input, never presented as actual scan evidence.
    return {"Results": [{"Target": "image.tar", "Vulnerabilities": list(vulns) or None}]}


def vuln(severity, fixed=None):
    return {"PkgName": "example", "InstalledVersion": "1.0", "VulnerabilityID": "CVE-0000-0000", "Severity": severity, "FixedVersion": fixed}


@pytest.mark.parametrize("vulns, code", [((), 0), ((vuln("HIGH"),), 0), ((vuln("LOW", "1.0.1"),), 1), ((vuln("CRITICAL", "2.0"), vuln("HIGH")), 1)])
def test_policy(vulns, code):
    assert evaluate(report(*vulns))[0] == code


@pytest.mark.parametrize("data", [None, {}, {"Results": [None]}, {"Results": [{"Target": "x", "Vulnerabilities": [{"PkgName": "y"}]}]}])
def test_fail_closed(data):
    with pytest.raises(ValueError):
        evaluate(data)


def test_cli(tmp_path, capsys):
    path = tmp_path / "report.json"
    assert main([str(path)]) == 2
    path.write_text("bad json", encoding="utf-8")
    assert main([str(path)]) == 2
    path.write_text(json.dumps(report(vuln("CRITICAL", "2.0"))), encoding="utf-8")
    assert main([str(path)]) == 1
    path.write_text(json.dumps(report(vuln("HIGH"))), encoding="utf-8")
    assert main([str(path)]) == 0
    assert "PASS" in capsys.readouterr().out
