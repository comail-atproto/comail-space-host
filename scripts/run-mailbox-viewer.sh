#!/usr/bin/env bash
set -euo pipefail
umask 077

lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"

if [[ "$#" -ne 1 || "$1" != did:* ]]; then
  echo "usage: $0 did:plc:exact-mailbox-owner" >&2
  exit 2
fi

cd "$lab_root"
exec go run ./cmd/comail-mailbox-viewer \
  --listen 127.0.0.1:39093 \
  --happyview-origin http://127.0.0.1:39090 \
  --happyview-base-path /comail-pds-lab \
  --happyview-public-host little-mac.lobster-hake.ts.net \
  --did "$1" \
  --space-key default \
  --login-path /comail-pds-lab/login/
