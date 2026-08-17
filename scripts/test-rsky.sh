#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lock_file="${repo_root}/providers/rsky.lock"
patch_file="${repo_root}/patches/rsky-atomic-referenced-blobs.patch"
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

git -C "${checkout}/rsky" apply --check "${patch_file}"
git -C "${checkout}/rsky" apply "${patch_file}"

source_file="${checkout}/rsky/rsky-pds/src/apis/com/atproto/space/mod.rs"
apply_line="$(sed -n '/\.apply_writes(space, writes, oplog_window())/{=;q;}' "${source_file}")"
blob_line="$(sed -n '/\.verify_blob_and_make_permanent(/{=;q;}' "${source_file}")"
if [[ -z "${apply_line}" || -z "${blob_line}" ]]; then
  echo "unable to locate authority-critical write/blob calls" >&2
  exit 1
fi
if (( apply_line < blob_line )); then
  echo "BLOCKED: patched rsky still commits space records before referenced blobs are verified (${source_file}:${apply_line} before :${blob_line})." >&2
  exit 1
fi

toolchain_bin="$(dirname "$(rustup which --toolchain stable rustc)")"
PATH="${toolchain_bin}:${PATH}" RUSTUP_TOOLCHAIN=stable cargo test \
  --manifest-path "${checkout}/rsky/Cargo.toml" \
  -p rsky-pds --test space_integration_tests -- --test-threads=1

echo "PASS: pinned rsky plus lab atomicity patch and all space integration tests"
