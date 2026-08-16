#!/usr/bin/env bash
set -euo pipefail
umask 077

lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
lock_file="$lab_root/providers/happyview.lock"
state_root="$lab_root/state/happyview"

read_lock() {
  local key="$1"
  sed -n "s/^${key}=//p" "$lock_file"
}

repository="$(read_lock repository)"
commit="$(read_lock commit)"
toolchain="$(read_lock rust_toolchain)"
if [[ -z "$repository" || ! "$commit" =~ ^[0-9a-f]{40}$ || -z "$toolchain" ]]; then
  echo "invalid HappyView lock file" >&2
  exit 1
fi
mkdir -p "$state_root"
chmod 0700 "$state_root"
checkout="$(mktemp -d "$state_root/test.XXXXXXXX")"
cleanup() {
  rm -rf "$checkout"
}
trap cleanup EXIT

git -C "$checkout" init --quiet
git -C "$checkout" remote add origin "$repository"
git -C "$checkout" fetch --quiet --depth=1 origin "$commit"
git -C "$checkout" checkout --quiet --detach FETCH_HEAD
if [[ "$(git -C "$checkout" rev-parse HEAD)" != "$commit" || -n "$(git -C "$checkout" status --porcelain)" ]]; then
  echo "HappyView checkout did not match the pinned clean commit" >&2
  exit 1
fi

rustup toolchain install "$toolchain" --profile minimal
rustc_path="$(rustup which --toolchain "$toolchain" rustc)"
rustdoc_path="$(rustup which --toolchain "$toolchain" rustdoc)"
(
  cd "$checkout"
  RUSTC="$rustc_path" RUSTDOC="$rustdoc_path" \
    rustup run "$toolchain" cargo test --locked \
      --test spaces_records \
      --test spaces_list_repos_auth \
      --test spaces_repo_state \
      --test spaces_credential_revocation
)
(
  cd "$lab_root"
  go test ./internal/providers/happyview ./internal/contracts

  live_origin="http://127.0.0.1:39090"
  live_secret="$state_root/runtime/session-secret"
  if [[ -f "$live_secret" ]] && curl --fail --silent --show-error --max-time 2 "$live_origin/" >/dev/null; then
    HAPPYVIEW_LIVE_ORIGIN="$live_origin" \
      HAPPYVIEW_LIVE_SESSION_SECRET_FILE="$live_secret" \
      go test -count=1 -run TestLiveLoopbackSyntheticMailboxAuthority ./internal/providers/happyview
  else
    echo "Live loopback proof skipped; start ./scripts/run-happyview.sh to include it."
  fi
)

echo "Pinned HappyView space/auth and Comail adapter tests passed."
