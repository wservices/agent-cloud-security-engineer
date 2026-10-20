---
name: cloud-security-reporting
description: Write a cloud posture report with prioritized fixes.
version: 0.2.0
author: Pascal (pascal), Hermes Agent
license: MIT
platforms: [linux]
prerequisites:
  commands: [jq, rg, python3]
metadata:
  hermes:
    tags: [reporting, posture, remediation, iac, least-privilege]
    related_skills: [cloud-posture-review-cspm, iam-least-privilege-review, cloud-network-and-exposure-review, secrets-and-key-management-review, cloud-benchmark-compliance]
---

# Cloud Security Reporting Skill

Consolidate findings from the CSPM, IAM, exposure, secrets/keys, and benchmark
skills into one cloud posture report: an executive summary, findings ranked by
severity × exposure, and a remediation plan where every fix is proposed as
Infrastructure-as-Code or exact console/CLI steps — and is least-privilege by
construction. Reporting only: it describes fixes for a human to apply and never
mutates cloud state.

## When to Use

- A posture review is complete and needs a single, prioritized write-up.
- You need an evidence-backed remediation plan for engineers or leadership.
- **Don't use for:** collecting the findings (use the domain skills first), or
  applying any proposed fix (advisory only).

## Prerequisites

- Triaged findings and evidence under `cases/<id>/evidence/` and drafted fixes
  under `cases/<id>/fixes/` from the other skills.
- Tools: `jq` (aggregate scanner JSON), `rg` (search evidence/fix drafts).
- Optional companion: `markdown-to-pdf` to render the report to PDF.

## How to Run

Aggregate the stored findings and write the report into the case directory, e.g.
`terminal(command="jq -s 'add' cases/<id>/evidence/*/*.ocsf.json > cases/<id>/all-findings.json", timeout=60)`
then build a prioritized Markdown report offline from the normalized findings,
e.g.
`terminal(command="python3 scripts/cloud_report_build.py cases/<id>/evidence/normalized.json --title 'AWS posture' --as-of 2026-10-20 -o cases/<id>/report.md", timeout=60)`
and expand it with the sections below.

## Quick Reference

```
# merge all scanner outputs and count by severity
jq -s 'add | group_by(.severity)[] | {severity: .[0].severity, count: length}' \
  cases/<id>/evidence/*/*.ocsf.json
# list critical/high failing findings with title + resource
jq -r 'select(.status_code=="FAIL" and (.severity=="Critical" or .severity=="High"))
  | [.severity,.finding_info.title,(.resources[0].uid // "-")] | @tsv' \
  cases/<id>/evidence/*/*.ocsf.json | sort
# sanity-check that no draft fix contains a plaintext secret before reporting
rg -n -i 'AKIA[0-9A-Z]{16}|secret|password|BEGIN .*PRIVATE KEY' cases/<id>/fixes/ || echo "clean"
# offline: build a severity-ranked, service-grouped Markdown report
python3 scripts/cloud_report_build.py cases/<id>/evidence/normalized.json \
  --title "AWS posture" --as-of 2026-10-20 -o cases/<id>/report.md
# render to PDF (companion skill)
pandoc cases/<id>/report.md -o cases/<id>/report.pdf --pdf-engine=wkhtmltopdf
```

## Procedure

1. **Aggregate and deduplicate.** Merge findings from all domain skills; collapse
   duplicates (one issue flagged by both CSPM and a domain skill counts once).
   Completion: a single deduplicated finding set.
2. **Rank.** Score each finding by severity × exposure (internet-reachable,
   data-bearing, identity/privilege, blast radius). Completion: an ordered list,
   highest risk first.
3. **Write the executive summary.** State overall posture, the top 3–5 risks, and
   the CIS compliance headline — in plain language, no jargon dump. Completion: a
   summary a non-cloud reader understands.
4. **Detail each finding.** Record: title, affected resources (account/region),
   observed evidence (the read-only command + stored output reference),
   severity + confidence, CIS / Well-Architected reference, and the proposed fix
   as IaC or console steps. Completion: every finding has evidence + a fix.
5. **Build the remediation plan.** Order fixes by risk reduced vs effort; mark
   each as proposed-for-human-apply and least-privilege. Completion: a prioritized
   fix list with owners (cloud/platform engineers).
6. **Redact and finalize.** Confirm no secret values, and that account IDs / ARNs
   are included only as the report's audience permits (rule 7). Optionally render
   to PDF. Completion: `cases/<id>/report.md` (and `report.pdf`) exist, redacted.

## Pitfalls

- **Advisory, not executed.** The report proposes fixes; it must never apply one.
  Label fixes "proposed — apply after review" (Security Policy §2, §4).
- **No secrets in the report.** Redact key/secret material and sanity-check with
  `rg` before finalizing (rule 6).
- **Mind third-party exposure.** Don't paste customer data, internal hostnames,
  or full ARNs into external services; keep enrichment to public references
  (e.g. CVE via `cve-research`) and defang indicators (rule 7).
- **Severity needs exposure context.** A "critical" default with no reachable
  resource may rank below a "high" that's internet-facing — rank by risk, not the
  scanner label alone.
- **Observed vs assumed.** Label each statement observed/inferred/assumed with
  confidence and an evidence reference (§9).

## Verification

- `cases/<id>/report.md` exists with an executive summary, ranked findings (each
  with evidence + a proposed fix), and a prioritized remediation plan.
- `python3 scripts/cloud_report_build.py <normalized>.json` renders Markdown
  grouped by service and ranked by severity (critical services first), excluding
  PASS findings by default; `python3 -m pytest tests -q` covers the rendering
  offline.
- The `rg` secret sanity-check reports `clean`.
- No fix in the report was applied; the command log shows reporting/aggregation
  only.
