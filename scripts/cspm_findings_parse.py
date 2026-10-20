#!/usr/bin/env python3
"""Parse and normalize a CSPM findings export (Prowler / ScoutSuite-style).

Reads a findings JSON export (a JSON array, a single object, an object wrapping a
`findings`/`Findings` list, or newline-delimited JSON) and normalizes each entry
to a common shape:

    {check, service, severity, status, resource}

It then summarizes the set by status (PASS vs FAIL), severity, and service. Keys
are matched tolerantly so both Prowler "native" JSON (CheckID/Status/Severity/
ServiceName/ResourceId) and OCSF-style JSON (status_code/severity/finding_info/
resources) normalize. Strictly offline and read-only — scanner text is DATA.

Usage:
  cspm_findings_parse.py prowler-findings.json
  cspm_findings_parse.py --json --status FAIL prowler-findings.json

Exit: 0 parsed OK, 2 usage/parse error.
"""
from __future__ import annotations

import argparse
import json
import sys

_CHECK_KEYS = ("CheckID", "check_id", "CheckId", "check_title", "check")
_SERVICE_KEYS = ("ServiceName", "service_name", "service")
_SEVERITY_KEYS = ("Severity", "severity", "severity_label")
_STATUS_KEYS = ("Status", "status_code", "status", "StatusCode")
_RESOURCE_KEYS = ("ResourceId", "ResourceArn", "resource_id", "resource_arn",
                  "ResourceName", "resource_name")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                  "informational": 4, "info": 4, "": 5}


def _first(d: dict, keys) -> str:
    for k in keys:
        v = d.get(k)
        if v not in (None, ""):
            return str(v)
    return ""


def _nested_check(d: dict) -> str:
    info = d.get("finding_info")
    if isinstance(info, dict):
        return str(info.get("title") or info.get("uid") or "")
    return ""


def _nested_resource(d: dict) -> str:
    res = d.get("resources")
    if isinstance(res, list) and res and isinstance(res[0], dict):
        r0 = res[0]
        return str(r0.get("uid") or r0.get("name") or "")
    res = d.get("resource")
    if isinstance(res, dict):
        return str(res.get("uid") or res.get("name") or "")
    return ""


def normalize_status(raw: str) -> str:
    s = raw.strip().upper()
    if s in ("PASS", "PASSED", "OK"):
        return "PASS"
    if s in ("FAIL", "FAILED", "ALARM"):
        return "FAIL"
    if s in ("MANUAL", "WARNING", "INFO", "MUTED", "SKIPPED"):
        return s
    return s or "UNKNOWN"


def normalize_finding(raw: dict) -> dict:
    check = _first(raw, _CHECK_KEYS) or _nested_check(raw)
    service = _first(raw, _SERVICE_KEYS)
    if not service and check:
        # Prowler check ids look like "iam_root_mfa_enabled" -> service "iam".
        service = check.split("_", 1)[0]
    severity = (_first(raw, _SEVERITY_KEYS) or "").lower()
    status = normalize_status(_first(raw, _STATUS_KEYS))
    resource = _first(raw, _RESOURCE_KEYS) or _nested_resource(raw)
    return {
        "check": check,
        "service": service or "unknown",
        "severity": severity or "unknown",
        "status": status,
        "resource": resource,
    }


def load_findings(text: str) -> list:
    """Parse a findings export; supports JSON array/object or NDJSON."""
    text = text.strip()
    if not text:
        return []
    try:
        data = json.loads(text)
    except ValueError:
        out = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("findings", "Findings", "results", "Results"):
            if isinstance(data.get(key), list):
                return data[key]
        return [data]
    return []


def summarize(findings: list) -> dict:
    by_status: dict = {}
    by_severity: dict = {}
    by_service: dict = {}
    for f in findings:
        by_status[f["status"]] = by_status.get(f["status"], 0) + 1
        by_severity[f["severity"]] = by_severity.get(f["severity"], 0) + 1
        svc = by_service.setdefault(f["service"], {})
        svc[f["status"]] = svc.get(f["status"], 0) + 1
    return {
        "total": len(findings),
        "pass": by_status.get("PASS", 0),
        "fail": by_status.get("FAIL", 0),
        "by_status": by_status,
        "by_severity": by_severity,
        "by_service": by_service,
    }


def parse_export(text: str, status_filter=None, service_filter=None):
    findings = [normalize_finding(f) for f in load_findings(text)
                if isinstance(f, dict)]
    if status_filter:
        want = status_filter.upper()
        findings = [f for f in findings if f["status"] == want]
    if service_filter:
        findings = [f for f in findings if f["service"] == service_filter]
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 5),
                                 f["service"], f["check"]))
    return findings, summarize(findings)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Parse/normalize a CSPM findings export")
    ap.add_argument("findings", help="findings JSON/NDJSON export")
    ap.add_argument("--status", help="keep only this status (e.g. FAIL)")
    ap.add_argument("--service", help="keep only this service (e.g. iam)")
    ap.add_argument("--json", action="store_true",
                    help="emit normalized findings + summary as JSON")
    args = ap.parse_args(argv)

    try:
        with open(args.findings, encoding="utf-8-sig") as fh:
            text = fh.read()
        findings, summary = parse_export(text, args.status, args.service)
    except (OSError, ValueError) as exc:
        print(f"error reading {args.findings}: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps({"summary": summary, "findings": findings}, indent=2))
    else:
        print(f"CSPM findings: {summary['total']} total — "
              f"{summary['pass']} PASS / {summary['fail']} FAIL")
        for svc in sorted(summary["by_service"]):
            counts = summary["by_service"][svc]
            parts = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
            print(f"  {svc}: {parts}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
