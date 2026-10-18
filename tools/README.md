# cloud-security-engineer tools

Every tool below is used with **read-only** cloud credentials (AWS
SecurityAudit/ViewOnlyAccess, Azure Reader, GCP Viewer). The role makes only
read-only API calls and never mutates cloud resources.

| Tool | Purpose | Source | Risk |
|---|---|---|---|
| aws (awscli) | read-only AWS API queries (describe/list/get) | apt | low (read-only creds) |
| jq | parse/filter scanner + API JSON | apt | low |
| ripgrep (`rg`) | search findings/evidence/fix drafts | apt | low |
| az (azure-cli) | read-only Azure queries (`list`/`show`) | **not apt** — vendor repo | low (Reader role) |
| gcloud (google-cloud-sdk) | read-only GCP queries (`list`/`describe`) | **not apt** — vendor repo | low (Viewer role) |
| prowler | read-only multi-cloud CSPM + CIS compliance | **not apt** — pip | low (read-only collector) |
| scout (scoutsuite) | read-only multi-cloud CSPM (grouped report) | **not apt** — pip | low (read-only collector) |

## Install

```bash
# apt layer (aws, jq, rg): with the shared installer (preferred)
SECURITY_TOOLING_DIR=/path/to/security-tooling bash tools/install.sh
# standalone fallback (apt only)
bash tools/install.sh
```

### Non-apt tools (install separately)

These are not in Kali apt. All are read-only clients/collectors:

```bash
# Azure CLI (az) — Microsoft vendor repo
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Google Cloud SDK (gcloud) — Google vendor repo
echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
  | sudo tee /etc/apt/sources.list.d/google-cloud-sdk.list
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg
sudo apt-get update -qq && sudo apt-get install -y google-cloud-cli

# prowler + ScoutSuite — pip (prefer a venv or pipx to isolate deps)
pipx install prowler
pipx install scoutsuite        # provides the `scout` command
```

## Verify

```bash
# apt layer via the shared skill's verifier
bash /path/to/security-tooling/skills/security-tooling/scripts/verify_tools.sh --from-file tools/verify.txt
# non-apt tools
az version && gcloud version && prowler --version && scout --help >/dev/null && echo "cloud tools present"
```

## Capabilities

No container capability is required — the role only makes read-only cloud API
calls over HTTPS. Never run `--privileged`; do not forward any write/admin cloud
credential into the sandbox (Security Policy §4, §13). Credentials are read from
env vars / the mounted GCP key file only and are never printed, logged, or
committed.
