import json
import pytest
from scripts.security_gate import evaluate, main


def report(*severities):
    return {"results": [{"extra": {"severity": s}} for s in severities], "errors": [], "paths": {"scanned": ["app/__init__.py"]}}


@pytest.mark.parametrize("severities, code", [((), 0), (("WARNING", "INFO"), 0), (("ERROR",), 1), (("ERROR", "WARNING"), 1)])
def test_policy(severities, code):
    assert evaluate(report(*severities))[0] == code


@pytest.mark.parametrize("data", [None, {}, {"results": [], "errors": []}, report("UNKNOWN"), report(None), {**report(), "errors": [{"message": "parse failure"}]}, {**report(), "results": [None]}, {**report(), "paths": {"scanned": []}}])
def test_fail_closed(data):
    with pytest.raises(ValueError):
        evaluate(data)


def test_cli(tmp_path, capsys):
    path = tmp_path / "report.json"
    assert main([str(path)]) == 2
    path.write_text("bad json", encoding="utf-8")
    assert main([str(path)]) == 2
    path.write_text(json.dumps(report("ERROR")), encoding="utf-8")
    assert main([str(path)]) == 1
    path.write_text(json.dumps(report("WARNING")), encoding="utf-8")
    assert main([str(path)]) == 0
    assert "PASS" in capsys.readouterr().out
