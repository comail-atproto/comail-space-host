#!/usr/bin/env bash
set -euo pipefail
umask 077

lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
operator_dir="$lab_root/state/operator"
cookie_file="$operator_dir/happyview-cookie"

mkdir -p "$operator_dir"
chmod 0700 "$operator_dir"
if [[ -e "$cookie_file" || -L "$cookie_file" ]]; then
  echo "refusing to overwrite existing cookie file: $cookie_file" >&2
  exit 1
fi

printf 'Paste only the happyview_session cookie value (input hidden): ' >&2
IFS= read -r -s cookie_value
printf '\n' >&2
if [[ "$cookie_value" == happyview_session=* ]]; then
  cookie_value="${cookie_value#happyview_session=}"
fi
if [[ -z "$cookie_value" || "$cookie_value" == *';'* || "$cookie_value" == *$'\r'* || "$cookie_value" == *$'\n'* ]]; then
  echo "invalid HappyView cookie value" >&2
  exit 1
fi

temporary="${cookie_file}.new"
printf 'happyview_session=%s\n' "$cookie_value" > "$temporary"
chmod 0600 "$temporary"
mv "$temporary" "$cookie_file"
echo "Stored owner-only cookie at $cookie_file"
