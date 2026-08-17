#!/usr/bin/env bash
set -euo pipefail
umask 077

lab_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
state_root="$lab_root/state/happyview"
install_root="$state_root/install"
runtime_root="$state_root/runtime"
binary="$install_root/bin/happyview"
session_secret_file="$runtime_root/session-secret"
token_key_file="$runtime_root/token-encryption-key"
database_file="$runtime_root/happyview.sqlite"
public_url="${HAPPYVIEW_PUBLIC_URL:-http://127.0.0.1:39090}"

case "$public_url" in
  http://127.0.0.1:39090)
    base_path=""
    static_dir="$install_root/web"
    ;;
  https://little-mac.lobster-hake.ts.net)
    base_path="/comail-pds-lab"
    static_dir="$install_root/web-tailnet"
    ;;
  *)
    echo "refusing HappyView public URL outside the loopback or approved tailnet origins: $public_url" >&2
    exit 1
    ;;
esac

if [[ ! -x "$binary" || ! -d "$static_dir" ]]; then
  echo "HappyView is not built; run ./scripts/build-happyview.sh first" >&2
  exit 1
fi
if [[ -L "$runtime_root" || -L "$database_file" ]]; then
  echo "refusing symlinked HappyView runtime path" >&2
  exit 1
fi
mkdir -p "$runtime_root"
chmod 0700 "$runtime_root"

create_secret() {
  local path="$1"
  local bytes="$2"
  if [[ -e "$path" ]]; then
    if [[ -L "$path" || ! -f "$path" ]]; then
      echo "invalid secret path: $path" >&2
      exit 1
    fi
    chmod 0600 "$path"
    return
  fi
  local temporary="${path}.new"
  if [[ -e "$temporary" ]]; then
    echo "stale secret staging file exists: $temporary" >&2
    exit 1
  fi
  openssl rand -base64 "$bytes" > "$temporary"
  chmod 0600 "$temporary"
  mv "$temporary" "$path"
}

create_secret "$session_secret_file" 48
create_secret "$token_key_file" 32

export DATABASE_URL="sqlite://${database_file}?mode=rwc"
export DATABASE_BACKEND="sqlite"
export PUBLIC_URL="$public_url"
export BASE_PATH="$base_path"
export HOST="127.0.0.1"
export PORT="39090"
export STATIC_DIR="$static_dir"
session_secret="$(tr -d '\r\n' < "$session_secret_file")"
token_encryption_key="$(tr -d '\r\n' < "$token_key_file")"
export SESSION_SECRET="$session_secret"
export TOKEN_ENCRYPTION_KEY="$token_encryption_key"
export FEATURE_SPACES_ENABLED="true"
export APP_NAME="Comail PDS Lab"
export JETSTREAM_URL="ws://127.0.0.1:9"
export RELAY_URL="http://127.0.0.1:9"
export RUST_LOG="happyview=info,tower_http=warn,sqlx=warn"

echo "Starting isolated HappyView at $PUBLIC_URL"
echo "Its SQLite state is private under $runtime_root; Ctrl-C stops it."
cd "$install_root"
exec "$binary"
