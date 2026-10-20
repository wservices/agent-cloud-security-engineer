#!/usr/bin/env python3
"""Build a prioritized cloud posture report (Markdown) from normalized findings.

Reads a normalized findings JSON (the output of `cspm_findings_parse.py --json`,
or any array of objects with `check`, `service`, `severity`, `status`,
`resource`) and renders a Markdown posture report:

  * a summary with counts by severity and status,
  * findings grouped by service (services ordered worst-severity first) and
    ranked by severity within each service.

By default only non-PASS findings are reported (the things needing a fix); pass
`--all` to include everything. Read-only and offline; it emits Markdown and never
touches cloud state. Finding text is untrusted DATA, rendered verbatim.

Usage:
  cloud_report_build.py normalized.json
  cloud_report_build.py normalized.json --title "Prod AWS posture" \\
      --as-of 2026-10-20 -o report.md

Exit: 0 report written, 2 usage/parse error.
"""
from __future__ import annotations

import argparse
import json
import sys

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3,
                  "informational": 4, "info": 4, "unknown": 5}


def _load(doc_text: str) -> list:
    data = json.loads(doc_text)
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return data["findings"]
    if isinstance(data, list):
        return data
    return []


def _sev_rank(sev: str) -> int:
    return SEVERITY_ORDER.get(str(sev).lower(), 5)


def _severity_counts(findings: list) -> dict:
    counts: dict = {}
    for f in findings:
        sev = str(f.get("severity", "unknown")).lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _group_by_service(findings: list) -> list:
    """Return [(service, [findings...])] ordered by worst severity, then name."""
    groups: dict = {}
    for f in findings:
        groups.setdefault(str(f.get("service", "unknown")), []).append(f)
    ordered = []
    for svc, items in groups.items():
        items.sort(key=lambda f: (_sev_rank(f.get("severity", "")),
                                   str(f.get("check", ""))))
        worst = min(_sev_rank(f.get("severity", "")) for f in items)
        ordered.append((worst, svc, items))
    ordered.sort(key=lambda t: (t[0], t[1]))
    return [(svc, items) for _, svc, items in ordered]


def build_report(findings: list, title: str = "Cloud Security Posture Report",
                 as_of=None, include_all: bool = False) -> str:
    scoped = findings if include_all else [
        f for f in findings if str(f.get("status", "")).upper() != "PASS"
    ]
    lines = [f"# {title}", ""]
    if as_of:
        lines += [f"_As of {as_of}._", ""]

    counts = _severity_counts(scoped)
    lines += ["## Summary", ""]
    lines.append(f"- Findings reported: {len(scoped)} "
                 f"(of {len(findings)} total)")
    if counts:
        order = sorted(counts, key=lambda s: SEVERITY_ORDER.get(s, 5))
        sev_line = ", ".join(f"{s} {counts[s]}" for s in order)
        lines.append(f"- By severity: {sev_line}")
    services = sorted({str(f.get("service", "unknown")) for f in scoped})
    if services:
        lines.append(f"- Services affected: {', '.join(services)}")
    lines.append("")

    lines += ["## Findings by Service", ""]
    if not scoped:
        lines += ["_No findings to report._", ""]
        return "\n".join(lines)

    for svc, items in _group_by_service(scoped):
        lines.append(f"### {svc}")
        lines.append("")
        for f in items:
            sev = str(f.get("severity", "unknown")).upper()
            check = f.get("check", "(unnamed check)")
            status = str(f.get("status", "")).upper()
            resource = f.get("resource") or "-"
            lines.append(f"- **[{sev}]** {check} — `{resource}` ({status})")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Build a Markdown cloud posture report")
    ap.add_argument("findings", help="normalized findings JSON")
    ap.add_argument("--title", default="Cloud Security Posture Report")
    ap.add_argument("--as-of", help="date string to stamp on the report")
    ap.add_argument("--all", action="store_true",
                    help="include PASS findings too (default: only non-PASS)")
    ap.add_argument("-o", "--output", help="write report to this file (else stdout)")
    args = ap.parse_args(argv)

    try:
        with open(args.findings, encoding="utf-8-sig") as fh:
            findings = _load(fh.read())
    except (OSError, ValueError) as exc:
        print(f"error reading {args.findings}: {exc}", file=sys.stderr)
        return 2

    report = build_report(findings, title=args.title, as_of=args.as_of,
                          include_all=args.all)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(report)
        except OSError as exc:
            print(f"error writing {args.output}: {exc}", file=sys.stderr)
            return 2
        print(f"wrote {args.output}")
    else:
        sys.stdout.write(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
