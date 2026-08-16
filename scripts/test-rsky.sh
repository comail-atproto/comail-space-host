#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lock_file="${repo_root}/providers/rsky.lock"
repository="$(sed -n 's/^repository=//p' "${lock_file}")"
commit="$(sed -n 's/^commit=//p' "${lock_file}")"

if [[ -z "${repository}" || -z "${commit}" ]]; then
  echo "rsky lock is incomplete" >&2
  exit 1
fi

checkout="$(mktemp -d "${TMPDIR:-/tmp}/comail-rsky-cert.XXXXXX")"
trap 'rm -rf -- "${checkout}"' EXIT

git clone --quiet --filter=blob:none "${repository}" "${checkout}/rsky"
git -C "${checkout}/rsky" checkout --quiet "${commit}"
actual="$(git -C "${checkout}/rsky" rev-parse HEAD)"
if [[ "${actual}" != "${commit}" ]]; then
  echo "rsky checkout does not match pinned commit" >&2
  exit 1
fi

source_file="${checkout}/rsky/rsky-pds/src/apis/com/atproto/space/mod.rs"
apply_line="$(sed -n '/\.apply_writes(space, writes, oplog_window())/{=;q;}' "${source_file}")"
blob_line="$(sed -n '/\.verify_blob_and_make_permanent(/{=;q;}' "${source_file}")"
if [[ -z "${apply_line}" || -z "${blob_line}" ]]; then
  echo "unable to locate authority-critical write/blob calls" >&2
  exit 1
fi
if (( apply_line < blob_line )); then
  echo "BLOCKED: pinned rsky commits space records before referenced blobs are verified (${source_file}:${apply_line} before :${blob_line})." >&2
  echo "A missing blob can return an error after a record commit; Comail requires a residual-record regression test and atomic fix." >&2
  exit 1
fi

RUSTUP_TOOLCHAIN=stable rustup run stable cargo test \
  --manifest-path "${checkout}/rsky/Cargo.toml" \
  -p rsky-pds --test space_integration_tests -- --test-threads=1

echo "PASS: pinned rsky source audit and upstream space integration suite"
