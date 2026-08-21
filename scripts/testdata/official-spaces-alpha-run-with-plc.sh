#!/bin/sh
set -eu

node /proof/plc-mock.mjs &
plc_pid=$!
node /proof/tls-proxy.mjs &
tls_pid=$!

cleanup() {
  kill "${tls_pid}" 2>/dev/null || true
  kill "${plc_pid}" 2>/dev/null || true
  wait "${tls_pid}" 2>/dev/null || true
  wait "${plc_pid}" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

node --heapsnapshot-signal=SIGUSR2 --enable-source-maps \
  --import=@atproto/pds/telemetry /app/services/pds/index.ts
