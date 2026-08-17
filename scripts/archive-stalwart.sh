#!/usr/bin/env bash
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
vandelay_bin="${VANDELAY_BIN:-${repo_root}/state/bin/vandelay}"
url=""
user=""
archive=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) url="$2"; shift 2 ;;
    --user) user="$2"; shift 2 ;;
    --archive) archive="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ -x "${vandelay_bin}" ]] || { echo "pinned Vandelay binary not found; run scripts/build-vandelay.sh" >&2; exit 2; }
[[ "${archive}" = /* && "${archive}" != / ]] || { echo "archive must be a new absolute path" >&2; exit 2; }
[[ ! -e "${archive}" && ! -e "${archive}-wal" && ! -e "${archive}-shm" ]] || { echo "refusing to overwrite an archive or sidecar" >&2; exit 2; }

password="${VANDELAY_PASSWORD:-}"
password_file="${VANDELAY_PASSWORD_FILE:-}"
if [[ -z "${password}" ]]; then
  [[ "${password_file}" = /* && -f "${password_file}" && ! -L "${password_file}" ]] || { echo "VANDELAY_PASSWORD or an absolute regular VANDELAY_PASSWORD_FILE is required" >&2; exit 2; }
  password_mode="$(stat -f '%Lp' "${password_file}" 2>/dev/null || stat -c '%a' "${password_file}")"
  password_owner="$(stat -f '%u' "${password_file}" 2>/dev/null || stat -c '%u' "${password_file}")"
  [[ "${password_mode}" = "600" && "${password_owner}" = "$(id -u)" ]] || { echo "password file must be owned by the current user with mode 600" >&2; exit 2; }
  password="$(<"${password_file}")"
fi
[[ -n "${password}" && "${password}" != *$'\n'* && "${password}" != *$'\r'* ]] || { echo "password must be non-empty and single-line" >&2; exit 2; }
export VANDELAY_PASSWORD="${password}"

python3 - "${url}" <<'PY'
import sys
from urllib.parse import urlsplit
u = urlsplit(sys.argv[1])
if u.scheme != "https" or not u.hostname or u.username or u.password or u.fragment:
    raise SystemExit("JMAP URL must be an absolute credential-free HTTPS URL")
PY

parent="$(dirname "${archive}")"
mkdir -p -m 0700 "${parent}"
parent_mode="$(stat -f '%Lp' "${parent}" 2>/dev/null || stat -c '%a' "${parent}")"
[[ "${parent_mode}" = "700" ]] || { echo "archive directory must have mode 700" >&2; exit 2; }

"${vandelay_bin}" import jmap --quiet \
  --url "${url}" --auth-basic "${user}" --account-name "${user}" \
  --objects mailbox,email "${archive}"
unset VANDELAY_PASSWORD password
chmod 0600 "${archive}"
echo "private Stalwart/Vandelay archive created at ${archive}"
