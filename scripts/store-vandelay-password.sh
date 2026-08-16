#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
output="${1:-${repo_root}/state/operator/vandelay-password}"

[[ "${output}" = /* && "${output}" != / ]] || { echo "password path must be absolute" >&2; exit 2; }
[[ ! -e "${output}" && ! -L "${output}" ]] || { echo "refusing to overwrite password file" >&2; exit 2; }
mkdir -p -m 0700 "$(dirname "${output}")"
parent_mode="$(stat -f '%Lp' "$(dirname "${output}")" 2>/dev/null || stat -c '%a' "$(dirname "${output}")")"
[[ "${parent_mode}" = "700" ]] || { echo "password directory must have mode 700" >&2; exit 2; }

IFS= read -r -s -p "Dedicated Stalwart app password: " password
echo
[[ -n "${password}" && "${password}" != *$'\n'* && "${password}" != *$'\r'* ]] || { echo "password must be non-empty and single-line" >&2; exit 2; }
printf '%s' "${password}" > "${output}"
unset password
chmod 0600 "${output}"
echo "stored dedicated password at ${output}; revoke it and remove this file after export"
