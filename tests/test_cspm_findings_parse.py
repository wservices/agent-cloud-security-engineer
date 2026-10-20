"""Behavior tests for cspm_findings_parse.py — offline, synthetic exports."""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "cspm_findings_parse", ROOT / "scripts" / "cspm_findings_parse.py")
cspm = importlib.util.module_from_spec(spec)
sys.modules["cspm_findings_parse"] = cspm
spec.loader.exec_module(cspm)

PROWLER_NATIVE = [
    {"CheckID": "iam_root_mfa_enabled", "ServiceName": "iam",
     "Severity": "critical", "Status": "FAIL", "ResourceId": "root"},
    {"CheckID": "iam_no_root_access_key", "ServiceName": "iam",
     "Severity": "critical", "Status": "PASS", "ResourceId": "root"},
    {"CheckID": "s3_bucket_public", "ServiceName": "s3",
     "Severity": "high", "Status": "FAIL", "ResourceId": "b1"},
]
OCSF_FINDING = {
    "status_code": "FAIL", "severity": "Medium",
    "finding_info": {"title": "ec2_ebs_default_encryption"},
    "resources": [{"uid": "vol-0001"}],
}


def test_normalize_prowler_native():
    out = cspm.normalize_finding(PROWLER_NATIVE[0])
    assert out == {"check": "iam_root_mfa_enabled", "service": "iam",
                   "severity": "critical", "status": "FAIL", "resource": "root"}


def test_normalize_ocsf_derives_service_from_check():
    out = cspm.normalize_finding(OCSF_FINDING)
    assert out["check"] == "ec2_ebs_default_encryption"
    assert out["service"] == "ec2"       # derived from "ec2_..." prefix
    assert out["status"] == "FAIL"
    assert out["resource"] == "vol-0001"
    assert out["severity"] == "medium"   # lower-cased


def test_status_normalization_variants():
    assert cspm.normalize_status("passed") == "PASS"
    assert cspm.normalize_status("FAILED") == "FAIL"
    assert cspm.normalize_status("Manual") == "MANUAL"


def test_summary_counts_pass_fail_and_service():
    findings = [cspm.normalize_finding(f) for f in PROWLER_NATIVE + [OCSF_FINDING]]
    summary = cspm.summarize(findings)
    assert summary["total"] == 4
    assert summary["pass"] == 1
    assert summary["fail"] == 3
    assert summary["by_service"]["iam"] == {"FAIL": 1, "PASS": 1}
    assert summary["by_severity"]["critical"] == 2


def test_status_filter_keeps_only_fail():
    text = json.dumps(PROWLER_NATIVE)
    findings, summary = cspm.parse_export(text, status_filter="FAIL")
    assert summary["total"] == 2
    assert all(f["status"] == "FAIL" for f in findings)


def test_ndjson_is_parsed():
    ndjson = "\n".join(json.dumps(f) for f in PROWLER_NATIVE)
    loaded = cspm.load_findings(ndjson)
    assert len(loaded) == 3


def test_object_wrapping_findings_list():
    text = json.dumps({"findings": PROWLER_NATIVE})
    assert len(cspm.load_findings(text)) == 3


def test_findings_sorted_severity_first():
    findings, _ = cspm.parse_export(json.dumps(PROWLER_NATIVE + [OCSF_FINDING]))
    ranks = [cspm.SEVERITY_ORDER.get(f["severity"], 5) for f in findings]
    assert ranks == sorted(ranks)


def test_main_runs(tmp_path, capsys):
    p = tmp_path / "f.json"
    p.write_text(json.dumps(PROWLER_NATIVE), encoding="utf-8")
    assert cspm.main([str(p)]) == 0
    assert "3 total" in capsys.readouterr().out
    assert cspm.main([str(tmp_path / "missing.json")]) == 2
