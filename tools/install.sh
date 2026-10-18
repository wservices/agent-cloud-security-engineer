#!/usr/bin/env bash
# Install the cloud-security-engineer apt tool layer on Kali Rolling, then verify.
# Delegates to the shared installer when available; otherwise falls back to apt.
# NOTE: az, gcloud, prowler, and scoutsuite are NOT apt packages — install them
# per tools/README.md. All cloud access uses READ-ONLY credentials.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${HERE}/packages.txt"
VERIFY="${HERE}/verify.txt"

SHARED_INSTALLER="${SECURITY_TOOLING_DIR:-}/skills/security-tooling/scripts/install_from_manifest.sh"
if [ -n "${SECURITY_TOOLING_DIR:-}" ] && [ -x "$SHARED_INSTALLER" ]; then
  bash "$SHARED_INSTALLER" "$MANIFEST" --verify-bin "$(paste -sd, "$VERIFY")"
else
  SUDO=(); [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1 && SUDO=(sudo -n)
  mapfile -t PKGS < <(grep -vE '^\s*(#|$)' "$MANIFEST" | sed 's/#.*//' | awk 'NF{print $1}')
  "${SUDO[@]}" apt-get update -qq
  DEBIAN_FRONTEND=noninteractive "${SUDO[@]}" apt-get install -y --no-install-recommends "${PKGS[@]}"
  missing=0
  while IFS= read -r b; do command -v "$b" >/dev/null 2>&1 || { echo "MISSING $b" >&2; missing=1; }; done < <(grep -vE '^\s*(#|$)' "$VERIFY")
  [ "$missing" -eq 0 ] && echo "cloud-security-engineer apt tools verified" || { echo "verification failed" >&2; exit 1; }
fi
