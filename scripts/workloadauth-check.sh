#!/usr/bin/env bash
# Checks internal/workloadauth is a byte-for-byte copy of the canonical package
# in sneakers-vault at SNEAKERS_VAULT_REF (proto-refs.env). To take a new
# version, bump the ref and copy the vault's internal/workloadauth/ over this
# one in the same change.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "$root/proto-refs.env"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "workloadauth: comparing with sneakers-vault at $SNEAKERS_VAULT_REF"
curl -sSfL "https://codeload.github.com/Sneakers-PAM/sneakers-vault/tar.gz/$SNEAKERS_VAULT_REF" |
  tar -xz -C "$tmp" --strip-components=1 --wildcards '*/internal/workloadauth/*'

if ! diff -r "$tmp/internal/workloadauth" "$root/internal/workloadauth"; then
  echo "workloadauth: internal/workloadauth differs from sneakers-vault at $SNEAKERS_VAULT_REF; copy it again" >&2
  exit 1
fi
echo "workloadauth: identical"
