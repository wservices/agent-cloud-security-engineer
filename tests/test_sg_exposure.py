"""Behavior tests for sg_exposure.py — offline, synthetic security groups."""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "sg_exposure", ROOT / "scripts" / "sg_exposure.py")
sg = importlib.util.module_from_spec(spec)
sys.modules["sg_exposure"] = sg
spec.loader.exec_module(sg)


def _sg(gid, perms):
    return {"SecurityGroups": [{"GroupId": gid, "GroupName": gid, "IpPermissions": perms}]}


SSH_OPEN = _sg("sg-ssh", [
    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
     "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
DB_OPEN_V6 = _sg("sg-db", [
    {"IpProtocol": "tcp", "FromPort": 5432, "ToPort": 5432,
     "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}])
ALL_PORTS = _sg("sg-all", [
    {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
BROAD = _sg("sg-broad", [
    {"IpProtocol": "tcp", "FromPort": 8000, "ToPort": 9000,
     "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
HTTPS_OPEN = _sg("sg-web", [
    {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443,
     "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
INTERNAL = _sg("sg-int", [
    {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
     "IpRanges": [{"CidrIp": "10.0.0.0/8"}]}])


def _only(doc):
    f = sg.audit_groups(doc)
    assert len(f) == 1, f
    return f[0]


def test_ssh_open_to_world_is_critical_mgmt():
    f = _only(SSH_OPEN)
    assert f["check"] == "world-open-mgmt"
    assert f["severity"] == "critical"
    assert f["cidr"] == "0.0.0.0/0"
    assert "22 (SSH)" in f["sensitive_ports"]


def test_db_open_over_ipv6_is_high_sensitive():
    f = _only(DB_OPEN_V6)
    assert f["check"] == "world-open-sensitive"
    assert f["severity"] == "high"
    assert f["cidr"] == "::/0"
    assert "5432 (PostgreSQL)" in f["sensitive_ports"]


def test_all_protocols_is_critical_all_ports():
    f = _only(ALL_PORTS)
    assert f["check"] == "world-open-all-ports"
    assert f["severity"] == "critical"


def test_broad_range_is_high():
    f = _only(BROAD)
    assert f["check"] == "world-open-broad-range"
    assert f["severity"] == "high"


def test_single_nonsensitive_port_is_medium():
    f = _only(HTTPS_OPEN)
    assert f["check"] == "world-open-port"
    assert f["severity"] == "medium"


def test_internal_source_not_flagged():
    assert sg.audit_groups(INTERNAL) == []


def test_findings_sorted_critical_first():
    combined = {"SecurityGroups":
                HTTPS_OPEN["SecurityGroups"] + SSH_OPEN["SecurityGroups"]}
    findings = sg.audit_groups(combined)
    assert findings[0]["severity"] == "critical"


def test_main_exit_codes(tmp_path):
    bad = tmp_path / "sg.json"
    bad.write_text(json.dumps(SSH_OPEN), encoding="utf-8")
    assert sg.main([str(bad)]) == 1
    clean = tmp_path / "clean.json"
    clean.write_text(json.dumps(INTERNAL), encoding="utf-8")
    assert sg.main([str(clean)]) == 0
