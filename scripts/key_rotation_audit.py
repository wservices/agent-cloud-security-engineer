#!/usr/bin/env python3
"""Audit KMS/key rotation METADATA from an exported inventory (offline).

Reads a key inventory JSON and flags rotation and key-policy hygiene problems:

  * rotation-disabled   : automatic rotation is off                     (high)
  * never-rotated       : no last_rotated date and the key is old       (high)
  * rotation-stale      : last rotation older than --max-age-days        (medium;
                          high if older than 2x --max-age-days)
  * wildcard-key-policy : key policy allows a wildcard principal ("*")   (critical)

This audits ROTATION METADATA ONLY — it never reads, prints, or needs key
material. It is read-only and offline; policy/metadata text is untrusted DATA.

Inventory shape (a list, or an object with a `keys` list):
    {"keys": [
      {"key_id": "key-0001", "created": "2023-01-01T00:00:00Z",
       "last_rotated": "2023-02-01T00:00:00Z", "rotation_enabled": true,
       "policy": {"Statement": [...]}}
    ]}

Usage:
  key_rotation_audit.py keys.json --max-age-days 365
  key_rotation_audit.py keys.json --now 2026-01-01 --json

Exit: 0 no findings, 1 findings present, 2 usage/parse error.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _as_list(value) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def _parse_dt(value):
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        try:
            dt = datetime.strptime(str(value)[:10], "%Y-%m-%d")
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _age_days(dt, now) -> int:
    return (now - dt).days


def _has_wildcard_principal(policy) -> bool:
    if not isinstance(policy, dict):
        return False
    for stmt in _as_list(policy.get("Statement")):
        if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal")
        if principal == "*":
            return True
        if isinstance(principal, dict):
            for val in principal.values():
                if "*" in _as_list(val):
                    return True
    return False


def audit_key(key: dict, now, max_age_days: int) -> list:
    findings: list = []
    kid = str(key.get("key_id") or key.get("KeyId") or "<unknown-key>")

    def add(check, severity, detail, age=None):
        findings.append({
            "key_id": kid, "check": check, "severity": severity,
            "detail": detail, "age_days": age,
        })

    rotation = key.get("rotation_enabled")
    if rotation is None:
        rotation = key.get("KeyRotationEnabled")
    created = _parse_dt(key.get("created") or key.get("CreationDate"))
    last_rotated = _parse_dt(key.get("last_rotated") or key.get("LastRotatedDate"))

    if rotation is False:
        add("rotation-disabled", "high", "automatic key rotation is disabled")

    if last_rotated is None:
        if created is not None and _age_days(created, now) > max_age_days:
            age = _age_days(created, now)
            add("never-rotated", "high",
                f"never rotated; created {age} days ago (> {max_age_days})", age)
    else:
        age = _age_days(last_rotated, now)
        if age > 2 * max_age_days:
            add("rotation-stale", "high",
                f"last rotated {age} days ago (> {2 * max_age_days})", age)
        elif age > max_age_days:
            add("rotation-stale", "medium",
                f"last rotated {age} days ago (> {max_age_days})", age)

    if _has_wildcard_principal(key.get("policy") or key.get("Policy")):
        add("wildcard-key-policy", "critical",
            "key policy Allow grants a wildcard principal ('*')")

    return findings


def extract_keys(doc) -> list:
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict):
        for key in ("keys", "Keys"):
            if isinstance(doc.get(key), list):
                return doc[key]
        if "key_id" in doc or "KeyId" in doc:
            return [doc]
    return []


def audit_inventory(doc, now, max_age_days: int = 365) -> list:
    findings: list = []
    for key in extract_keys(doc):
        if isinstance(key, dict):
            findings.extend(audit_key(key, now, max_age_days))
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["key_id"]))
    return findings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Audit KMS key rotation metadata offline")
    ap.add_argument("inventory", help="exported key inventory JSON")
    ap.add_argument("--max-age-days", type=int, default=365,
                    help="rotation age that counts as stale (default 365)")
    ap.add_argument("--now", help="reference date (YYYY-MM-DD); default = today UTC")
    ap.add_argument("--json", action="store_true", help="emit findings as JSON")
    args = ap.parse_args(argv)

    now = _parse_dt(args.now) if args.now else datetime.now(timezone.utc)
    if now is None:
        print(f"error: could not parse --now '{args.now}'", file=sys.stderr)
        return 2

    try:
        with open(args.inventory, encoding="utf-8-sig") as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"error reading {args.inventory}: {exc}", file=sys.stderr)
        return 2

    findings = audit_inventory(doc, now, max_age_days=args.max_age_days)
    if args.json:
        print(json.dumps({"total": len(findings), "findings": findings}, indent=2))
    else:
        if not findings:
            print("key rotation audit: no findings")
        else:
            print(f"key rotation audit: {len(findings)} finding(s)")
            for f in findings:
                print(f"  [{f['severity'].upper()}] {f['key_id']}: "
                      f"{f['check']} — {f['detail']}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
