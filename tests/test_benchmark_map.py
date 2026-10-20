"""Behavior tests for benchmark_map.py — offline, synthetic findings+catalog."""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "benchmark_map", ROOT / "scripts" / "benchmark_map.py")
bm = importlib.util.module_from_spec(spec)
sys.modules["benchmark_map"] = bm
spec.loader.exec_module(bm)

FINDINGS = [
    {"check": "iam_root_mfa_enabled", "status": "FAIL"},
    {"check": "iam_no_root_access_key", "status": "PASS"},
    {"check": "s3_bucket_public", "status": "FAIL"},
    {"check": "cloudtrail_enabled", "status": "PASS"},
]
CATALOG = {
    "benchmark": "CIS AWS Foundations 3.0",
    "controls": [
        {"id": "1.4", "title": "No root access key", "checks": ["iam_no_root_access_key"]},
        {"id": "1.5", "title": "Root MFA", "checks": ["iam_root_mfa_enabled"]},
        {"id": "3.1", "title": "CloudTrail enabled", "checks": ["cloudtrail_enabled"]},
        {"id": "2.1.1", "title": "S3 not public", "checks": ["s3_bucket_public"]},
        {"id": "1.1", "title": "Contact details (manual)", "checks": []},
        {"id": "4.1", "title": "Unassessed metric filter", "checks": ["not_run_check"]},
    ],
}


def test_overall_coverage_and_compliance():
    rep = bm.evaluate(FINDINGS, CATALOG)
    assert rep["total_controls"] == 6
    assert rep["passed"] == 2
    assert rep["failed"] == 2
    assert rep["manual"] == 1
    assert rep["not_assessed"] == 1
    # assessed = pass+fail = 4 of 6 -> 66.7% coverage; 2/4 pass -> 50% compliance
    assert rep["coverage_pct"] == 66.7
    assert rep["compliance_pct"] == 50.0
    assert rep["benchmark"] == "CIS AWS Foundations 3.0"


def test_per_control_status():
    by_id = {c["id"]: c for c in bm.evaluate(FINDINGS, CATALOG)["controls"]}
    assert by_id["1.4"]["status"] == "pass"
    assert by_id["1.5"]["status"] == "fail"
    assert by_id["1.1"]["status"] == "manual"       # no checks
    assert by_id["4.1"]["status"] == "not-assessed"  # check never ran
    assert by_id["1.5"]["fail_count"] == 1


def test_any_fail_fails_the_control():
    findings = [
        {"check": "c1", "status": "PASS"},
        {"check": "c1", "status": "FAIL"},  # one resource fails
    ]
    catalog = {"controls": [{"id": "x", "title": "t", "checks": ["c1"]}]}
    ctrl = bm.evaluate(findings, catalog)["controls"][0]
    assert ctrl["status"] == "fail"
    assert ctrl["pass_count"] == 1 and ctrl["fail_count"] == 1


def test_all_pass_is_full_compliance():
    findings = [{"check": "c1", "status": "PASS"}]
    catalog = {"controls": [{"id": "x", "title": "t", "checks": ["c1"]}]}
    rep = bm.evaluate(findings, catalog)
    assert rep["compliance_pct"] == 100.0
    assert rep["coverage_pct"] == 100.0


def test_main_yaml_catalog_and_min_compliance(tmp_path):
    import pytest
    pytest.importorskip("yaml")
    import yaml
    fp = tmp_path / "f.json"
    fp.write_text(json.dumps({"findings": FINDINGS}), encoding="utf-8")
    cp = tmp_path / "cis.yaml"
    cp.write_text(yaml.safe_dump(CATALOG), encoding="utf-8")
    # compliance is 50% -> below an 80 gate -> exit 1
    assert bm.main(["--findings", str(fp), "--catalog", str(cp),
                    "--min-compliance", "80"]) == 1
    # no gate -> exit 0
    assert bm.main(["--findings", str(fp), "--catalog", str(cp)]) == 0
