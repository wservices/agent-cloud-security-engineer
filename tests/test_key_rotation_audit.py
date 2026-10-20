"""Behavior tests for key_rotation_audit.py — offline, metadata only."""
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "key_rotation_audit", ROOT / "scripts" / "key_rotation_audit.py")
kra = importlib.util.module_from_spec(spec)
sys.modules["key_rotation_audit"] = kra
spec.loader.exec_module(kra)

NOW = kra._parse_dt("2026-10-01")

INVENTORY = {"keys": [
    {"key_id": "key-0001", "created": "2020-01-01T00:00:00Z",
     "last_rotated": "2024-06-01T00:00:00Z", "rotation_enabled": True},
    {"key_id": "key-0002", "created": "2019-01-01T00:00:00Z",
     "rotation_enabled": False},
    {"key_id": "key-0003", "created": "2018-01-01T00:00:00Z",
     "last_rotated": "2018-02-01T00:00:00Z", "rotation_enabled": True,
     "policy": {"Statement": [
         {"Effect": "Allow", "Principal": {"AWS": "*"},
          "Action": "kms:Decrypt", "Resource": "*"}]}},
]}
CLEAN = {"keys": [
    {"key_id": "key-ok", "created": "2026-01-01T00:00:00Z",
     "last_rotated": "2026-09-01T00:00:00Z", "rotation_enabled": True,
     "policy": {"Statement": [
         {"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::111:root"},
          "Action": "kms:Decrypt", "Resource": "*"}]}}]}


def _checks_for(key_id, doc):
    return {f["check"] for f in kra.audit_inventory(doc, NOW, max_age_days=365)
            if f["key_id"] == key_id}


def test_rotation_disabled_flagged():
    assert "rotation-disabled" in _checks_for("key-0002", INVENTORY)


def test_never_rotated_old_key_flagged():
    assert "never-rotated" in _checks_for("key-0002", INVENTORY)


def test_stale_rotation_severity_scales():
    f = kra.audit_inventory(INVENTORY, NOW, max_age_days=365)
    stale_1 = [x for x in f if x["key_id"] == "key-0001"
               and x["check"] == "rotation-stale"]
    stale_3 = [x for x in f if x["key_id"] == "key-0003"
               and x["check"] == "rotation-stale"]
    assert stale_1 and stale_1[0]["severity"] == "high"   # 852d > 2x365
    assert stale_3 and stale_3[0]["severity"] == "high"   # very old
    assert stale_1[0]["age_days"] > 365


def test_recent_rotation_not_stale():
    f = kra.audit_inventory(
        {"keys": [{"key_id": "k", "created": "2025-01-01T00:00:00Z",
                   "last_rotated": "2026-08-01T00:00:00Z",
                   "rotation_enabled": True}]},
        NOW, max_age_days=365)
    assert f == []


def test_wildcard_key_policy_is_critical():
    f = kra.audit_inventory(INVENTORY, NOW, max_age_days=365)
    wc = [x for x in f if x["check"] == "wildcard-key-policy"]
    assert wc and wc[0]["severity"] == "critical"
    assert wc[0]["key_id"] == "key-0003"


def test_scoped_policy_not_flagged():
    assert "wildcard-key-policy" not in _checks_for("key-ok", CLEAN)


def test_clean_inventory_has_no_findings():
    assert kra.audit_inventory(CLEAN, NOW, max_age_days=365) == []


def test_findings_sorted_critical_first():
    f = kra.audit_inventory(INVENTORY, NOW, max_age_days=365)
    ranks = [kra.SEVERITY_ORDER[x["severity"]] for x in f]
    assert ranks == sorted(ranks)
    assert f[0]["severity"] == "critical"


def test_main_exit_codes(tmp_path):
    bad = tmp_path / "keys.json"
    bad.write_text(json.dumps(INVENTORY), encoding="utf-8")
    assert kra.main([str(bad), "--now", "2026-10-01"]) == 1
    good = tmp_path / "clean.json"
    good.write_text(json.dumps(CLEAN), encoding="utf-8")
    assert kra.main([str(good), "--now", "2026-10-01"]) == 0
