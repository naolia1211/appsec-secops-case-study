import json
import pytest
from scripts.sca_gate import evaluate, main


def report(*fix_versions_per_vuln):
    # Synthetic unit-test input, never presented as actual scan evidence.
    vulns = [{"id": f"VULN-{i}", "fix_versions": versions} for i, versions in enumerate(fix_versions_per_vuln)]
    return {"dependencies": [{"name": "Flask", "version": "1.0", "vulns": vulns}, {"name": "waitress", "version": "3.0.2", "vulns": []}]}


@pytest.mark.parametrize("fix_versions_per_vuln, code", [((), 0), (([],), 1), ((["1.0.1"],), 1), (([], ["2.0"]), 1)])
def test_policy(fix_versions_per_vuln, code):
    assert evaluate(report(*fix_versions_per_vuln))[0] == code


@pytest.mark.parametrize("data", [None, {}, {"dependencies": [None]}, {"dependencies": [{"name": "x"}]}, {"dependencies": [{"name": "x", "vulns": [None]}]}])
def test_fail_closed(data):
    with pytest.raises(ValueError):
        evaluate(data)


def test_cli(tmp_path, capsys):
    path = tmp_path / "report.json"
    assert main([str(path)]) == 2
    path.write_text("bad json", encoding="utf-8")
    assert main([str(path)]) == 2
    path.write_text(json.dumps(report(["1.0.1"])), encoding="utf-8")
    assert main([str(path)]) == 1
    path.write_text(json.dumps(report([])), encoding="utf-8")
    assert main([str(path)]) == 1
    assert "BLOCK" in capsys.readouterr().out
