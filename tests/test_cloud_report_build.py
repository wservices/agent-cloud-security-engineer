"""Behavior tests for cloud_report_build.py — offline Markdown rendering."""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "cloud_report_build", ROOT / "scripts" / "cloud_report_build.py")
crb = importlib.util.module_from_spec(spec)
sys.modules["cloud_report_build"] = crb
spec.loader.exec_module(crb)

FINDINGS = [
    {"check": "iam_root_mfa_enabled", "service": "iam", "severity": "critical",
     "status": "FAIL", "resource": "root"},
    {"check": "iam_no_root_access_key", "service": "iam", "severity": "critical",
     "status": "PASS", "resource": "root"},
    {"check": "s3_bucket_public", "service": "s3", "severity": "high",
     "status": "FAIL", "resource": "b1"},
    {"check": "ec2_ebs_default_encryption", "service": "ec2", "severity": "medium",
     "status": "FAIL", "resource": "vol-1"},
]


def test_report_excludes_pass_by_default():
    md = crb.build_report(FINDINGS, title="T", as_of="2026-10-20")
    assert "iam_no_root_access_key" not in md      # a PASS finding
    assert "Findings reported: 3 (of 4 total)" in md
    assert "_As of 2026-10-20._" in md


def test_include_all_keeps_pass():
    md = crb.build_report(FINDINGS, include_all=True)
    assert "iam_no_root_access_key" in md
    assert "of 4 total" in md


def test_services_ordered_worst_severity_first():
    md = crb.build_report(FINDINGS)
    # iam (critical) section must appear before s3 (high) and ec2 (medium)
    assert md.index("### iam") < md.index("### s3") < md.index("### ec2")


def test_severity_summary_line():
    md = crb.build_report(FINDINGS)
    assert "By severity: critical 1, high 1, medium 1" in md


def test_finding_line_format():
    md = crb.build_report(FINDINGS)
    assert "- **[CRITICAL]** iam_root_mfa_enabled — `root` (FAIL)" in md


def test_no_findings_renders_placeholder():
    md = crb.build_report([{"check": "x", "service": "s", "severity": "low",
                            "status": "PASS", "resource": "r"}])
    assert "_No findings to report._" in md


def test_main_writes_file(tmp_path):
    src = tmp_path / "norm.json"
    src.write_text(json.dumps({"findings": FINDINGS}), encoding="utf-8")
    out = tmp_path / "report.md"
    assert crb.main([str(src), "-o", str(out), "--title", "Prod"]) == 0
    body = out.read_text(encoding="utf-8")
    assert body.startswith("# Prod")
    assert "### iam" in body
    assert crb.main([str(tmp_path / "missing.json")]) == 2
