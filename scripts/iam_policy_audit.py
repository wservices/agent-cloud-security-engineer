#!/usr/bin/env python3
"""Audit an AWS IAM policy document (offline) for over-permissive grants.

Reads an exported IAM policy JSON document and flags least-privilege problems:
  * action wildcard            : Action "*" (and Action "*" + Resource "*" = admin)
  * service-wide wildcard      : "s3:*" style grants (whole service)
  * resource wildcard          : Resource "*" on an Allow
  * NotAction on Allow         : grants everything EXCEPT the listed actions
  * allow-without-condition    : a wildcard Allow with no Condition guardrail
  * privilege-escalation       : known priv-esc-prone actions (iam:PassRole,
                                 iam:CreatePolicyVersion, sts:AssumeRole, ...)

Strictly read-only and offline: it parses the JSON you exported with a read-only
call (e.g. `aws iam get-policy-version`) and never contacts AWS. The policy text
is untrusted DATA — a Sid or description is reported, never executed.

Usage:
  iam_policy_audit.py policy.json
  iam_policy_audit.py --json policy.json

Exit: 0 no findings, 1 findings present, 2 usage/parse error.
"""
from __future__ import annotations

import argparse
import json
import sys

# Actions that are classic privilege-escalation primitives (Rhino Security Labs
# "AWS IAM Privilege Escalation" research). Stored lowercase; AWS is case-insensitive.
PRIVESC_ACTIONS = {
    "iam:passrole",
    "iam:createpolicyversion",
    "iam:setdefaultpolicyversion",
    "iam:attachuserpolicy",
    "iam:attachgrouppolicy",
    "iam:attachrolepolicy",
    "iam:putuserpolicy",
    "iam:putgrouppolicy",
    "iam:putrolepolicy",
    "iam:createaccesskey",
    "iam:createloginprofile",
    "iam:updateloginprofile",
    "iam:updateassumerolepolicy",
    "iam:createuser",
    "iam:createrole",
    "sts:assumerole",
    "lambda:createfunction",
    "lambda:updatefunctioncode",
    "glue:createdevendpoint",
    "cloudformation:createstack",
    "ec2:runinstances",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _as_list(value) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, list) else [value]


def extract_statements(doc) -> list:
    """Pull the Statement list out of common IAM document wrappers."""
    if isinstance(doc, list):
        return doc
    if not isinstance(doc, dict):
        return []
    if "Statement" in doc:
        return _as_list(doc["Statement"])
    for key in ("PolicyDocument", "Document", "policy", "Policy"):
        if key in doc:
            return extract_statements(doc[key])
    return []


def _matched_privesc(actions_lower: list) -> list:
    matched: set = set()
    for a in actions_lower:
        if a == "*":
            matched.update(PRIVESC_ACTIONS)
        elif a.endswith(":*"):
            svc = a[:-1]  # "iam:*" -> "iam:"
            matched.update(p for p in PRIVESC_ACTIONS if p.startswith(svc))
        elif a in PRIVESC_ACTIONS:
            matched.add(a)
    return sorted(matched)


def audit_statement(stmt: dict, index: int) -> list:
    """Return a list of finding dicts for one Allow statement."""
    findings: list = []
    if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
        return findings  # Deny statements narrow access; not a risk here.

    sid = stmt.get("Sid") or f"statement[{index}]"
    actions = [str(a) for a in _as_list(stmt.get("Action"))]
    actions_lower = [a.lower() for a in actions]
    not_actions = _as_list(stmt.get("NotAction"))
    resources = [str(r) for r in _as_list(stmt.get("Resource"))]
    has_condition = bool(stmt.get("Condition"))
    res_wildcard = "*" in resources

    def add(check, severity, detail):
        findings.append({
            "sid": sid, "check": check, "severity": severity, "detail": detail,
        })

    full_action_wildcard = "*" in actions_lower
    if full_action_wildcard and res_wildcard:
        add("admin-equivalent", "critical",
            "Allow Action '*' on Resource '*' — full administrative access")
    elif full_action_wildcard:
        add("action-wildcard", "high",
            "Allow Action '*' (every action) regardless of resource")

    service_wildcards = sorted({a for a in actions_lower
                                if a.endswith(":*") and a != "*"})
    if service_wildcards:
        add("service-wide-wildcard", "medium",
            "service-wide grant(s): " + ", ".join(service_wildcards))

    if not_actions:
        add("notaction-allow", "high",
            "Allow with NotAction grants everything except: "
            + ", ".join(str(n) for n in not_actions))

    if res_wildcard and not full_action_wildcard:
        add("resource-wildcard", "medium",
            "Allow on Resource '*' — scope to specific ARNs")

    privesc = _matched_privesc(actions_lower)
    if privesc:
        sev = "critical" if res_wildcard else "high"
        add("privilege-escalation", sev,
            "privilege-escalation-prone action(s): " + ", ".join(privesc))

    if (full_action_wildcard or res_wildcard or service_wildcards) and not has_condition:
        add("allow-without-condition", "low",
            "wildcard Allow has no Condition guardrail (e.g. source IP, MFA, tag)")

    return findings


def audit_policy(doc) -> list:
    statements = extract_statements(doc)
    findings: list = []
    for i, stmt in enumerate(statements):
        findings.extend(audit_statement(stmt, i))
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["sid"], f["check"]))
    return findings


def _load(path: str):
    with open(path, encoding="utf-8-sig") as fh:
        return json.load(fh)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Audit an AWS IAM policy document offline")
    ap.add_argument("policy", help="path to an exported IAM policy JSON document")
    ap.add_argument("--json", action="store_true", help="emit findings as JSON")
    args = ap.parse_args(argv)

    try:
        doc = _load(args.policy)
    except (OSError, ValueError) as exc:
        print(f"error reading {args.policy}: {exc}", file=sys.stderr)
        return 2

    findings = audit_policy(doc)
    if args.json:
        print(json.dumps({"total": len(findings), "findings": findings}, indent=2))
    else:
        if not findings:
            print("IAM policy audit: no least-privilege findings")
        else:
            print(f"IAM policy audit: {len(findings)} finding(s)")
            for f in findings:
                print(f"  [{f['severity'].upper()}] {f['sid']}: {f['check']} — {f['detail']}")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
