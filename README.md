# cloud-security-engineer

Hermes cybersecurity agent: advisory cloud security engineer. It hardens posture
across AWS, Azure, and GCP — running read-only CSPM scans, reviewing IAM for
least privilege, checking network exposure and public storage, auditing secret
and key management, and assessing CIS Foundations benchmark compliance — then
produces a prioritized posture report whose fixes are proposed as
Infrastructure-as-Code or console steps. Strictly read-only and advisory: it uses
read-only cloud credentials and **never mutates cloud resources**.

See `ROLE.md` for the full role definition, permitted/prohibited actions, and
escalation paths (default escalation: the Security Team Lead).

## Skills

| Skill | What it does |
|---|---|
| `cloud-posture-review-cspm` | Read-only CSPM (prowler/ScoutSuite) + finding triage |
| `iam-least-privilege-review` | Find over-permissive IAM; propose least privilege |
| `cloud-network-and-exposure-review` | Public exposure, security groups/NSGs, open storage |
| `secrets-and-key-management-review` | Key rotation, secret exposure, KMS/Key Vault usage |
| `cloud-benchmark-compliance` | Assess vs CIS AWS/Azure/GCP Foundations |
| `cloud-security-reporting` | Posture report with prioritized, least-privilege fixes |

Additional cloud skills (workload/container/K8s posture, IaC pre-deploy scanning,
drift detection) are tracked as planned in `agents/platform/IMPLEMENTATION.md`.

## Install into Hermes (as a profile)

This repo is a **Hermes profile distribution** (`distribution.yaml` + `SOUL.md` +
`skills/`). Install it as its own agent profile:

```bash
hermes profile install "https://github.com/wservices/agent-cloud-security-engineer.git"
hermes -p cloud-security-engineer chat        # run it (one-off, no sticky change)
hermes profile use cloud-security-engineer     # ...or make it the sticky default, then `hermes chat`
hermes profile update cloud-security-engineer  # re-pull later; keeps your .env/memory
```

Then add the recommended companion skills (install the ones you need):

```bash
# CVE context for vulnerable cloud components / benchmark findings
hermes skills install "https://raw.githubusercontent.com/wservices/skill-cve-research/main/skills/cve-research/SKILL.md" --category security
# install/verify the cloud CLIs + scanners this role drives
hermes skills install "https://raw.githubusercontent.com/wservices/skill-security-tooling/main/skills/security-tooling/SKILL.md" --category security
hermes skills install "https://raw.githubusercontent.com/wservices/skill-tool-intel/main/skills/tool-intel/SKILL.md" --category devops
# render the posture report
hermes skills install "https://raw.githubusercontent.com/wservices/skill-markdown-to-pdf/main/skills/markdown-to-pdf/SKILL.md" --category documents
```

These general skills aren't bundled in the profile but pair well with cloud
posture work — all read-only / analysis-only, in keeping with the role:

| Skill | Why |
|---|---|
| `cve-research` | enrich a CVE behind a vulnerable component or CIS finding across NVD / KEV / EPSS / OSV |
| `security-tooling` | install/verify the cloud CLIs + scanners (`aws`, `az`, `gcloud`, prowler, ScoutSuite) |
| `tool-intel` | learn/verify those CLI tools and detect version drift |
| `markdown-to-pdf` | render the posture report (`report.md` → PDF) |

A `security-reporting` shared skill is **(planned)** and will standardize the
posture report once hosted.

On install, Hermes generates a `.env.EXAMPLE` from `distribution.yaml`'s
`env_requires` (the AWS/Azure/GCP read-only credentials). Copy it to `.env`, fill
in your values, and forward the names into the Kali sandbox via
`docker_forward_env`. `config.yaml` is **not** overwritten (your model/provider is
preserved).

**See [`docs/ENVIRONMENT.md`](docs/ENVIRONMENT.md)** for every variable this role
reads — required/optional, defaults, a copy-ready `.env` template, the
`docker_forward_env` snippet, and the secret-handling rules. That file is
generated from `distribution.yaml` (`agents/platform/scripts/gen_env_doc.py`), so
it never drifts from what the role actually uses. **Every credential must be a
read-only / least-privilege principal** (AWS SecurityAudit/ViewOnlyAccess, Azure
Reader, GCP Viewer).

The companion skills above install from the public mirror; for the internal
pinned (CI) install path and the profile + shared-skill mechanism, see
`agents/platform/docs/GITLAB-ARCHITECTURE.md` and `HERMES-INTEGRATION.md` §6.

## Tools

`tools/packages.txt` + `tools/install.sh` install the apt layer (`awscli` → `aws`,
`jq`, `ripgrep` → `rg`). The remaining cloud CLIs and scanners are **not** apt
packages and are installed separately (see `tools/README.md`): `azure-cli`
(`az`), `google-cloud-sdk` (`gcloud`), `prowler` (pip), `scoutsuite` (pip). All of
them run with **read-only** credentials; the role makes only read-only API calls,
so no container capability is required (never `--privileged`; Security Policy §4).

## Tests

```bash
python3 -m pytest tests -q     # offline scaffold smoke test: manifest + every SKILL.md
```

## Security

Bound by `agents/platform/policies/SECURITY-POLICY.md`: read-only by default, no
cloud writes, least privilege, secrets never printed/logged/committed, untrusted
content (resource names, tags, policy docs, scanner output) treated as data
(never instructions). Proposed fixes are IaC/console steps for a human to apply —
the agent never executes them.

## License

MIT.
