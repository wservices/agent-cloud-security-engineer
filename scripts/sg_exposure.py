#!/usr/bin/env python3
"""Flag internet-exposed security-group ingress rules (offline).

Reads an exported security-group JSON (AWS `aws ec2 describe-security-groups
--output json`) and flags ingress rules open to the world — IPv4 `0.0.0.0/0`
and IPv6 `::/0` — with extra weight on sensitive ports and over-broad ranges:

  * world-open-all-ports   : 0.0.0.0/0 to every port / protocol "-1"  (critical)
  * world-open-mgmt        : 0.0.0.0/0 to SSH (22) or RDP (3389)      (critical)
  * world-open-sensitive   : 0.0.0.0/0 to a database/cache/search port (high)
  * world-open-broad-range : 0.0.0.0/0 to a wide port span            (high)
  * world-open-port        : 0.0.0.0/0 to a single non-sensitive port (medium)

Strictly read-only and offline: it parses exported config and never calls AWS and
never touches a rule. Resource names/tags are untrusted DATA, reported as-is.

Usage:
  sg_exposure.py security-groups.json
  sg_exposure.py --json --broad-range 100 security-groups.json

Exit: 0 no exposure, 1 exposures found, 2 usage/parse error.
"""
from __future__ import annotations

import argparse
import json
import sys

# Ports where world-open ingress is especially dangerous.
MGMT_PORTS = {22: "SSH", 3389: "RDP"}
SENSITIVE_PORTS = {
    3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    27017: "MongoDB", 9200: "Elasticsearch",
}
SENSITIVE_PORTS.update(MGMT_PORTS)

WORLD_V4 = "0.0.0.0/0"
WORLD_V6 = "::/0"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def extract_groups(doc) -> list:
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict):
        if "SecurityGroups" in doc:
            return list(doc["SecurityGroups"])
        if "GroupId" in doc or "IpPermissions" in doc:
            return [doc]
    return []


def port_range(perm: dict):
    """Return (from_port, to_port, is_all_ports). None ports => unknown span."""
    proto = str(perm.get("IpProtocol"))
    if proto in ("-1", "all"):
        return 0, 65535, True
    fp = perm.get("FromPort")
    tp = perm.get("ToPort")
    if fp is None or tp is None:
        return None, None, False
    fp, tp = int(fp), int(tp)
    return fp, tp, (fp == 0 and tp == 65535)


def _world_cidrs(perm: dict) -> list:
    cidrs = []
    for r in perm.get("IpRanges", []) or []:
        if r.get("CidrIp") == WORLD_V4:
            cidrs.append(WORLD_V4)
    for r in perm.get("Ipv6Ranges", []) or []:
        if r.get("CidrIpv6") == WORLD_V6:
            cidrs.append(WORLD_V6)
    return cidrs


def _classify(fp, tp, all_ports: bool, broad_range: int):
    """Return (check, severity, sensitive_hit_dict)."""
    if all_ports or fp is None:
        return "world-open-all-ports", "critical", {}
    hits = {p: name for p, name in SENSITIVE_PORTS.items() if fp <= p <= tp}
    mgmt = {p: n for p, n in hits.items() if p in MGMT_PORTS}
    if mgmt:
        return "world-open-mgmt", "critical", hits
    if hits:
        return "world-open-sensitive", "high", hits
    if (tp - fp + 1) >= broad_range:
        return "world-open-broad-range", "high", {}
    return "world-open-port", "medium", {}


def audit_groups(doc, broad_range: int = 100) -> list:
    findings: list = []
    for group in extract_groups(doc):
        if not isinstance(group, dict):
            continue
        gid = group.get("GroupId") or group.get("GroupName") or "<unknown-sg>"
        gname = group.get("GroupName", "")
        for perm in group.get("IpPermissions", []) or []:
            world = _world_cidrs(perm)
            if not world:
                continue
            fp, tp, all_ports = port_range(perm)
            check, severity, hits = _classify(fp, tp, all_ports, broad_range)
            for cidr in world:
                findings.append({
                    "group_id": gid,
                    "group_name": gname,
                    "cidr": cidr,
                    "protocol": str(perm.get("IpProtocol")),
                    "from_port": fp,
                    "to_port": tp,
                    "sensitive_ports": [f"{p} ({n})" for p, n in sorted(hits.items())],
                    "check": check,
                    "severity": severity,
                })
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["group_id"]))
    return findings


def _load(path: str):
    with open(path, encoding="utf-8-sig") as fh:
        return json.load(fh)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Flag world-open security-group ingress")
    ap.add_argument("sg_file", help="exported security-groups JSON")
    ap.add_argument("--broad-range", type=int, default=100,
                    help="port-span size that counts as an over-broad range")
    ap.add_argument("--json", action="store_true", help="emit findings as JSON")
    args = ap.parse_args(argv)

    try:
        doc = _load(args.sg_file)
    except (OSError, ValueError) as exc:
        print(f"error reading {args.sg_file}: {exc}", file=sys.stderr)
        return 2

    findings = audit_groups(doc, broad_range=args.broad_range)
    if args.json:
        print(json.dumps({"total": len(findings), "findings": findings}, indent=2))
    else:
        if not findings:
            print("SG exposure: no world-open ingress found")
        else:
            print(f"SG exposure: {len(findings)} world-open ingress rule(s)")
            for f in findings:
                ports = (",".join(f["sensitive_ports"]) or
                         f"{f['from_port']}-{f['to_port']}")
                print(f"  [{f['severity'].upper()}] {f['group_id']} {f['cidr']} "
                      f"{f['check']} ({ports})")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
