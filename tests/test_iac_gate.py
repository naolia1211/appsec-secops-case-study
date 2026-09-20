import json
import pytest
from scripts.iac_gate import evaluate, main


def finding(severity, status="FAIL"):
    return {"ID": "AVD-0000", "Severity": severity, "Status": status, "Title": "example"}


def report(target, *findings):
    # Synthetic unit-test input, never presented as actual scan evidence.
    return {"Results": [{"Target": target, "Misconfigurations": list(findings) or None}]}


@pytest.mark.parametrize(
    "target, findings, code",
    [
        ("Dockerfile", (), 0),
        ("Dockerfile", (finding("LOW"), finding("MEDIUM")), 0),
        ("Dockerfile", (finding("HIGH"),), 1),
        ("k8s/hardened/app.yml", (finding("CRITICAL"),), 1),
        ("k8s/insecure/app.yml", (finding("CRITICAL"),), 0),  # lab fixture, out of gated scope
        ("Dockerfile", (finding("HIGH", status="PASS"),), 0),  # not a failing check
        ("Dockerfile.checks", (finding("HIGH"),), 0),  # CI toolbox image, out of gated scope
    ],
)
def test_policy(target, findings, code):
    assert evaluate(report(target, *findings))[0] == code


@pytest.mark.parametrize("data", [None, {}, {"Results": [None]}, {"Results": [{"Target": "x", "Misconfigurations": [{"ID": "y"}]}]}])
def test_fail_closed(data):
    with pytest.raises(ValueError):
        evaluate(data)


def test_cli(tmp_path, capsys):
    path = tmp_path / "report.json"
    assert main([str(path)]) == 2
    path.write_text("bad json", encoding="utf-8")
    assert main([str(path)]) == 2
    path.write_text(json.dumps(report("Dockerfile", finding("CRITICAL"))), encoding="utf-8")
    assert main([str(path)]) == 1
    path.write_text(json.dumps(report("k8s/insecure/app.yml", finding("CRITICAL"))), encoding="utf-8")
    assert main([str(path)]) == 0
    assert "PASS" in capsys.readouterr().out
