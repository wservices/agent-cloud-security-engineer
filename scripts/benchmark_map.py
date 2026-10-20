#!/usr/bin/env python3
"""Map normalized CSPM findings onto a CIS benchmark catalog (offline).

Takes a normalized findings JSON (the output of `cspm_findings_parse.py --json`,
or any array of objects with at least `check` and `status`) and a CIS cloud
benchmark control catalog (YAML or JSON) that maps each control to the check ids
that assess it:

    benchmark: CIS AWS Foundations 3.0
    controls:
      - id: "1.4"
        title: Ensure no root account access key exists
        checks: [iam_no_root_access_key]
      - id: "1.5"
        title: Ensure MFA is enabled for the root account
        checks: [iam_root_mfa_enabled, iam_root_hardware_mfa]

For each control it computes pass/fail from the matching findings, then overall
coverage (% of controls that have evidence) and compliance (% of assessed
controls that pass). Read-only and offline.

A control with no matching finding is `not-assessed` (a coverage gap); a control
that lists no checks is `manual`.

Usage:
  benchmark_map.py --findings normalized.json --catalog cis_aws.yaml
  benchmark_map.py --findings normalized.json --catalog cis_aws.yaml --json \\
      --min-compliance 80

Exit: 0 OK (or compliance >= --min-compliance), 1 below --min-compliance,
      2 usage/parse error.
"""
from __future__ import annotations

import argparse
import json
import sys


def _load_json(path: str):
    with open(path, encoding="utf-8-sig") as fh:
        return json.load(fh)


def _load_catalog(path: str):
    with open(path, encoding="utf-8-sig") as fh:
        text = fh.read()
    if path.lower().endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
        except ImportError:
            raise ValueError("PyYAML required for YAML catalogs "
                             "(use a JSON catalog or install python3-yaml)")
        return yaml.safe_load(text)
    return json.loads(text)


def _finding_list(doc) -> list:
    if isinstance(doc, dict) and isinstance(doc.get("findings"), list):
        return doc["findings"]
    if isinstance(doc, list):
        return doc
    return []


def _controls(catalog) -> list:
    if isinstance(catalog, dict):
        return list(catalog.get("controls") or [])
    if isinstance(catalog, list):
        return catalog
    return []


def _status_by_check(findings: list) -> dict:
    """Map check id -> list of statuses (upper-cased)."""
    out: dict = {}
    for f in findings:
        if not isinstance(f, dict):
            continue
        check = str(f.get("check", "")).strip()
        if not check:
            continue
        out.setdefault(check, []).append(str(f.get("status", "")).upper())
    return out


def evaluate(findings: list, catalog) -> dict:
    status_map = _status_by_check(findings)
    results = []
    tally = {"pass": 0, "fail": 0, "not-assessed": 0, "manual": 0}
    for ctrl in _controls(catalog):
        if not isinstance(ctrl, dict):
            continue
        cid = str(ctrl.get("id", "?"))
        title = str(ctrl.get("title", ""))
        checks = [str(c) for c in (ctrl.get("checks") or [])]
        statuses = []
        for c in checks:
            statuses.extend(status_map.get(c, []))
        pass_n = statuses.count("PASS")
        fail_n = statuses.count("FAIL")
        if not checks:
            status = "manual"
        elif not statuses:
            status = "not-assessed"
        elif fail_n:
            status = "fail"
        else:
            status = "pass"
        tally[status] += 1
        results.append({
            "id": cid, "title": title, "status": status,
            "pass_count": pass_n, "fail_count": fail_n,
            "checks": checks,
        })

    total = len(results)
    assessed = tally["pass"] + tally["fail"]
    coverage = round(100.0 * assessed / total, 1) if total else 0.0
    compliance = round(100.0 * tally["pass"] / assessed, 1) if assessed else 0.0
    return {
        "benchmark": (catalog.get("benchmark")
                      if isinstance(catalog, dict) else None),
        "total_controls": total,
        "assessed": assessed,
        "passed": tally["pass"],
        "failed": tally["fail"],
        "not_assessed": tally["not-assessed"],
        "manual": tally["manual"],
        "coverage_pct": coverage,
        "compliance_pct": compliance,
        "controls": results,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Map CSPM findings to a CIS catalog")
    ap.add_argument("--findings", required=True, help="normalized findings JSON")
    ap.add_argument("--catalog", required=True, help="CIS control catalog (YAML/JSON)")
    ap.add_argument("--min-compliance", type=float, default=None,
                    help="exit 1 if compliance %% is below this value")
    ap.add_argument("--json", action="store_true", help="emit full report as JSON")
    args = ap.parse_args(argv)

    try:
        findings = _finding_list(_load_json(args.findings))
        catalog = _load_catalog(args.catalog)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = evaluate(findings, catalog)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        name = report["benchmark"] or "benchmark"
        print(f"{name}: {report['total_controls']} controls — "
              f"coverage {report['coverage_pct']}% / "
              f"compliance {report['compliance_pct']}%")
        print(f"  pass={report['passed']} fail={report['failed']} "
              f"not-assessed={report['not_assessed']} manual={report['manual']}")
        for c in report["controls"]:
            if c["status"] == "fail":
                print(f"  [FAIL] {c['id']} {c['title']} "
                      f"(fail={c['fail_count']}, pass={c['pass_count']})")

    if args.min_compliance is not None and report["compliance_pct"] < args.min_compliance:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
