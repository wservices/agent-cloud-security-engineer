"""Behavior tests for iam_policy_audit.py — offline, synthetic IAM policies."""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "iam_policy_audit", ROOT / "scripts" / "iam_policy_audit.py")
iam = importlib.util.module_from_spec(spec)
sys.modules["iam_policy_audit"] = iam
spec.loader.exec_module(iam)

ADMIN = {"Version": "2012-10-17", "Statement": [
    {"Sid": "AdminAll", "Effect": "Allow", "Action": "*", "Resource": "*"}]}
PASSROLE = {"Statement": [
    {"Sid": "Pass", "Effect": "Allow", "Action": ["iam:PassRole", "s3:*"],
     "Resource": "*"}]}
NOTACTION = {"Statement": [
    {"Sid": "Not", "Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]}
CLEAN = {"Statement": [
    {"Sid": "Ro", "Effect": "Allow", "Action": ["s3:GetObject"],
     "Resource": "arn:aws:s3:::bucket/*",
     "Condition": {"Bool": {"aws:SecureTransport": "true"}}}]}
DENY = {"Statement": [
    {"Sid": "D", "Effect": "Deny", "Action": "*", "Resource": "*"}]}


def _checks(doc):
    return {f["check"] for f in iam.audit_policy(doc)}


def test_admin_equivalent_is_critical():
    findings = iam.audit_policy(ADMIN)
    admin = [f for f in findings if f["check"] == "admin-equivalent"]
    assert admin and admin[0]["severity"] == "critical"


def test_privilege_escalation_action_flagged():
    findings = iam.audit_policy(PASSROLE)
    pe = [f for f in findings if f["check"] == "privilege-escalation"]
    assert pe, "iam:PassRole should be flagged as privilege escalation"
    assert "iam:passrole" in pe[0]["detail"]
    # resource "*" makes the priv-esc critical
    assert pe[0]["severity"] == "critical"


def test_service_wide_and_resource_wildcard():
    checks = _checks(PASSROLE)
    assert "service-wide-wildcard" in checks  # s3:*
    assert "resource-wildcard" in checks      # Resource "*"


def test_notaction_allow_is_high():
    findings = iam.audit_policy(NOTACTION)
    na = [f for f in findings if f["check"] == "notaction-allow"]
    assert na and na[0]["severity"] == "high"


def test_allow_without_condition_flagged_on_wildcard():
    assert "allow-without-condition" in _checks(ADMIN)
    # but a scoped, conditioned Allow is clean
    assert "allow-without-condition" not in _checks(CLEAN)


def test_clean_policy_has_no_findings():
    assert iam.audit_policy(CLEAN) == []


def test_deny_statement_not_flagged():
    # A Deny on *:* narrows access and must not be reported as a risk.
    assert iam.audit_policy(DENY) == []


def test_findings_sorted_critical_first():
    findings = iam.audit_policy(PASSROLE)
    sev = [f["severity"] for f in findings]
    assert sev == sorted(sev, key=lambda s: iam.SEVERITY_ORDER[s])
    assert findings[0]["severity"] == "critical"


def test_main_exit_codes(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps(ADMIN), encoding="utf-8")
    assert iam.main([str(bad)]) == 1
    good = tmp_path / "good.json"
    good.write_text(json.dumps(CLEAN), encoding="utf-8")
    assert iam.main([str(good)]) == 0
    assert iam.main([str(tmp_path / "missing.json")]) == 2
