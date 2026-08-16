#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lock_file="${repo_root}/providers/vandelay.lock"
repository="$(sed -n 's/^repository=//p' "${lock_file}")"
commit="$(sed -n 's/^commit=//p' "${lock_file}")"
rust_toolchain="$(sed -n 's/^rust_toolchain=//p' "${lock_file}")"
output="${1:-${repo_root}/state/bin/vandelay}"

[[ "${output}" = /* ]] || { echo "output must be absolute" >&2; exit 2; }
[[ ! -e "${output}" ]] || { echo "refusing to overwrite ${output}" >&2; exit 2; }

checkout="$(mktemp -d "${TMPDIR:-/tmp}/comail-vandelay-build.XXXXXX")"
trap 'rm -rf -- "${checkout}"' EXIT
git clone --quiet --filter=blob:none "${repository}" "${checkout}/vandelay"
git -C "${checkout}/vandelay" checkout --quiet "${commit}"
[[ "$(git -C "${checkout}/vandelay" rev-parse HEAD)" = "${commit}" ]]

toolchain_bin="$(dirname "$(rustup which --toolchain "${rust_toolchain}" rustc)")"
PATH="${toolchain_bin}:${PATH}" RUSTUP_TOOLCHAIN="${rust_toolchain}" cargo build \
  --locked --release --manifest-path "${checkout}/vandelay/Cargo.toml"
mkdir -p -m 0700 "$(dirname "${output}")"
install -m 0700 "${checkout}/vandelay/target/release/vandelay" "${output}"
echo "built pinned Vandelay ${commit} at ${output}"
