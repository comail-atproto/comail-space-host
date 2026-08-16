#!/usr/bin/env bash
set -euo pipefail
umask 077

lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
lock_file="$lab_root/providers/happyview.lock"
state_root="$lab_root/state/happyview"
install_root="$state_root/install"
tailnet_base_path="/comail-pds-lab"
tailnet_oauth_client_id="${HAPPYVIEW_OAUTH_CLIENT_ID:-}"
oauth_patch="$lab_root/patches/happyview-tailnet-oauth-client.patch"

read_lock() {
  local key="$1"
  sed -n "s/^${key}=//p" "$lock_file"
}

repository="$(read_lock repository)"
commit="$(read_lock commit)"
version="$(read_lock version)"
toolchain="$(read_lock rust_toolchain)"
if [[ -z "$repository" || ! "$commit" =~ ^[0-9a-f]{40}$ || -z "$version" || -z "$toolchain" ]]; then
  echo "invalid HappyView lock file" >&2
  exit 1
fi
if [[ -L "$state_root" || -L "$install_root" ]]; then
  echo "refusing symlinked HappyView state path" >&2
  exit 1
fi
mkdir -p "$state_root"
chmod 0700 "$state_root"
if [[ -e "$install_root" ]]; then
  echo "HappyView install already exists: $install_root" >&2
  echo "Move it aside explicitly before rebuilding." >&2
  exit 1
fi

build_root="$(mktemp -d "$state_root/build.XXXXXXXX")"
cleanup() {
  rm -rf "$build_root"
}
trap cleanup EXIT

git -C "$build_root" init --quiet
git -C "$build_root" remote add origin "$repository"
git -C "$build_root" fetch --quiet --depth=1 origin "$commit"
git -C "$build_root" checkout --quiet --detach FETCH_HEAD
actual_commit="$(git -C "$build_root" rev-parse HEAD)"
if [[ "$actual_commit" != "$commit" || -n "$(git -C "$build_root" status --porcelain)" ]]; then
  echo "HappyView checkout did not match the pinned clean commit" >&2
  exit 1
fi
git -C "$build_root" apply --check "$oauth_patch"
git -C "$build_root" apply "$oauth_patch"

rustup toolchain install "$toolchain" --profile minimal
rustc_path="$(rustup which --toolchain "$toolchain" rustc)"
rustdoc_path="$(rustup which --toolchain "$toolchain" rustdoc)"

(
  cd "$build_root/web"
  npm ci
  NEXT_PUBLIC_BASE_PATH='' NEXT_PUBLIC_OAUTH_CLIENT_ID='' npm run build
  mkdir "$build_root/web-loopback"
  cp -R out/. "$build_root/web-loopback/"
  NEXT_PUBLIC_BASE_PATH="$tailnet_base_path" \
    NEXT_PUBLIC_OAUTH_CLIENT_ID="$tailnet_oauth_client_id" npm run build
  mkdir "$build_root/web-tailnet"
  cp -R out/. "$build_root/web-tailnet/"
)
(
  cd "$build_root"
  RUSTC="$rustc_path" RUSTDOC="$rustdoc_path" \
    SQLX_OFFLINE=true HAPPYVIEW_VERSION="${version#v}" \
    rustup run "$toolchain" cargo build --release --locked --bin happyview
)

stage="$state_root/install.new"
if [[ -e "$stage" ]]; then
  echo "stale HappyView staging directory exists: $stage" >&2
  exit 1
fi
mkdir -p "$stage/bin" "$stage/web" "$stage/web-tailnet"
install -m 0700 "$build_root/target/release/happyview" "$stage/bin/happyview"
cp -R "$build_root/web-loopback/." "$stage/web/"
cp -R "$build_root/web-tailnet/." "$stage/web-tailnet/"
cp -R "$build_root/migrations" "$stage/migrations"
chmod -R go-rwx "$stage"
{
  echo "repository=$repository"
  echo "commit=$actual_commit"
  echo "version=$version"
  echo "rust_toolchain=$toolchain"
  shasum -a 256 "$stage/bin/happyview"
} > "$stage/receipt.txt"
chmod 0600 "$stage/receipt.txt"
mv "$stage" "$install_root"
trap - EXIT
cleanup

echo "Pinned HappyView installed under $install_root"
