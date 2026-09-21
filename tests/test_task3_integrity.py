import json
from datetime import date
import pytest
from scripts import sca_gate, container_gate, iac_gate
from scripts.scan_policy import exceptions, apply_exceptions
from scripts.approved_image import read_record

@pytest.mark.parametrize("gate,data", [(sca_gate,{"dependencies":[]}), (container_gate,{"Results":[]}), (iac_gate,{"Results":[]})])
def test_empty_scope_blocks(gate,data):
    with pytest.raises(ValueError): gate.evaluate(data)

def test_iac_absolute_path_blocks():
    rows=[{"Target":"/workspace/"+t,"Class":"config","MisconfSummary":{"Successes":1}} for t in iac_gate.GATED_TARGETS]
    rows[0]["Misconfigurations"]=[{"ID":"TEST","Severity":"CRITICAL","Status":"FAIL"}]
    assert iac_gate.evaluate({"SchemaVersion":2,"Results":rows})[0] == 1
    with pytest.raises(ValueError): iac_gate.evaluate({"SchemaVersion":2,"Results":rows[1:]})

def policy(tmp_path, **changes):
    e=dict(scanner="container",id="CVE-TEST",package="example",installed="1",scope="lab",reason="test fixture",mitigation="isolated test",owner="test",review_reference="synthetic unit test",expires="2099-01-01")
    e.update(changes)
    p=tmp_path/"exceptions.json"; p.write_text(json.dumps({"version":1,"exceptions":[e]})); return p

def test_exception_match_and_version_boundary(tmp_path):
    p=policy(tmp_path)
    f=dict(id="CVE-TEST",package="example",installed="1")
    assert apply_exceptions("container",[f],p)==[]
    assert apply_exceptions("container",[dict(f,installed="2")],p)
    assert apply_exceptions("sca",[f],p)

@pytest.mark.parametrize("changes",[{"expires":"2000-01-01"},{"id":"*"},{"scope":"production"},{"reason":""}])
def test_bad_exception_blocks(tmp_path,changes):
    with pytest.raises(ValueError): exceptions(policy(tmp_path,**changes))

def test_expiry_boundary(tmp_path):
    with pytest.raises(ValueError): exceptions(policy(tmp_path,expires="2026-09-21"),date(2026,9,21))

def test_invalid_approval(tmp_path):
    p=tmp_path/"approval.json"; p.write_text('{}')
    with pytest.raises(ValueError): read_record(p)
