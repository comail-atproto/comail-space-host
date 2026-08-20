#!/usr/bin/env bash
# Runs only against the exact disposable reference-PDS Spaces alpha image.
# It never reads operator credentials or production data. Every owned resource
# is labeled, ownership-checked, removed on exit, and verified absent.
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lock_file="${repo_root}/providers/official-spaces-alpha.lock"

for tool in diff docker jq openssl rg; do
  command -v "${tool}" >/dev/null || {
    printf 'required tool is missing: %s\n' "${tool}" >&2
    exit 1
  }
done

lock_value() {
  local wanted="$1" key value
  while IFS='=' read -r key value; do
    if [[ "${key}" == "${wanted}" ]]; then
      printf '%s' "${value}"
      return 0
    fi
  done <"${lock_file}"
  printf 'missing lock field: %s\n' "${wanted}" >&2
  return 1
}

docker_image="$(lock_value docker_image)"
docker_digest="$(lock_value docker_digest)"
docker_platform="$(lock_value docker_platform)"
epoch="$(lock_value commit)"
docker_config="$(lock_value docker_config)"
proposal_commit="$(lock_value proposal_commit)"
reference_app_commit="$(lock_value reference_app_commit)"
sdk_snapshot="$(lock_value sdk_snapshot)"
image="${docker_image}@${docker_digest}"

runtime_dir="$(mktemp -d /tmp/comail-official-alpha.XXXXXX)"
run_id="${runtime_dir##*.}"
resource_label="comail.proof.run=${run_id}"
pds_container="comail-alpha-pds-${run_id}"
plc_container="comail-alpha-plc-${run_id}"
network="comail-alpha-net-${run_id}"
volume="comail-alpha-data-${run_id}"
account_file="${runtime_dir}/account.json"
cleanup_failed=0

remove_owned() {
  local kind="$1" name="$2" label
  if ! docker "${kind}" inspect "${name}" >/dev/null 2>&1; then
    return 0
  fi
  case "${kind}" in
    container) label="$(docker container inspect --format '{{ index .Config.Labels "comail.proof.run" }}' "${name}" 2>/dev/null || true)" ;;
    network|volume) label="$(docker "${kind}" inspect --format '{{ index .Labels "comail.proof.run" }}' "${name}" 2>/dev/null || true)" ;;
    *) printf 'unexpected cleanup resource kind: %s\n' "${kind}" >&2; cleanup_failed=1; return 0 ;;
  esac
  if [[ "${label}" != "${run_id}" ]]; then
    printf 'refusing to remove unowned %s %s\n' "${kind}" "${name}" >&2
    cleanup_failed=1
    return 0
  fi
  case "${kind}" in
    container) docker rm -f "${name}" >/dev/null || cleanup_failed=1 ;;
    network) docker network rm "${name}" >/dev/null || cleanup_failed=1 ;;
    volume) docker volume rm "${name}" >/dev/null || cleanup_failed=1 ;;
  esac
}

cleanup() {
  local original_status=$?
  trap - EXIT INT TERM
  set +e
  remove_owned container "${pds_container}"
  remove_owned container "${plc_container}"
  remove_owned network "${network}"
  remove_owned volume "${volume}"
  case "${runtime_dir}" in
    /tmp/comail-official-alpha.*) rm -rf -- "${runtime_dir}" || cleanup_failed=1 ;;
    *) printf 'refusing unexpected runtime cleanup path: %s\n' "${runtime_dir}" >&2; cleanup_failed=1 ;;
  esac
  for resource in "container:${pds_container}" "container:${plc_container}" "network:${network}" "volume:${volume}"; do
    if docker "${resource%%:*}" inspect "${resource#*:}" >/dev/null 2>&1; then
      printf 'owned proof resource remains after cleanup: %s\n' "${resource}" >&2
      cleanup_failed=1
    fi
  done
  if [[ -e "${runtime_dir}" ]]; then
    printf 'proof runtime directory remains after cleanup: %s\n' "${runtime_dir}" >&2
    cleanup_failed=1
  fi
  if (( original_status != 0 )); then
    exit "${original_status}"
  fi
  exit "${cleanup_failed}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

rotation_key="$(openssl rand -hex 32)"
dpop_secret="$(openssl rand -hex 32)"
jwt_secret="$(openssl rand -hex 32)"
admin_password="$(openssl rand -hex 32)"
account_password="$(openssl rand -hex 32)"

docker pull --platform "${docker_platform}" "${image}" >/dev/null
docker network create --internal --label "${resource_label}" "${network}" >/dev/null
docker volume create --label "${resource_label}" "${volume}" >/dev/null

docker run -d --platform "${docker_platform}" --name "${plc_container}" \
  --label "${resource_label}" --network "${network}" \
  -v "${repo_root}/scripts/testdata/official-spaces-alpha-plc-mock.mjs:/proof/plc-mock.mjs:ro" \
  --entrypoint node "${image}" /proof/plc-mock.mjs >/dev/null

for _ in $(seq 1 30); do
  if docker exec "${plc_container}" node -e \
    'const r=await fetch("http://127.0.0.1:3001/_health"); const b=await r.json(); if(r.status!==200||b.status!=="ok") process.exit(1)' \
    >/dev/null 2>&1; then
    break
  fi
  if ! docker ps --format '{{.Names}}' | rg -x "${plc_container}" >/dev/null; then
    docker logs "${plc_container}" >&2
    exit 1
  fi
  sleep 1
done
docker exec "${plc_container}" node -e \
  'const r=await fetch("http://127.0.0.1:3001/_health"); const b=await r.json(); if(r.status!==200||b.status!=="ok") process.exit(1)' \
  >/dev/null

docker run --rm --platform "${docker_platform}" --user root --entrypoint sh \
  -v "${volume}:/data" "${image}" \
  -lc 'mkdir -p /data/blobs /data/actors && chown -R node:node /data'

docker run -d --platform "${docker_platform}" --name "${pds_container}" \
  --label "${resource_label}" --network "${network}" \
  -v "${volume}:/data" \
  -e PDS_HOSTNAME=localhost \
  -e PDS_PORT=2583 \
  -e PDS_DEV_MODE=true \
  -e PDS_DATA_DIRECTORY=/data \
  -e PDS_BLOBSTORE_DISK_LOCATION=/data/blobs \
  -e "PDS_PLC_ROTATION_KEY_K256_PRIVATE_KEY_HEX=${rotation_key}" \
  -e "PDS_DPOP_SECRET=${dpop_secret}" \
  -e "PDS_JWT_SECRET=${jwt_secret}" \
  -e "PDS_ADMIN_PASSWORD=${admin_password}" \
  -e PDS_INVITE_REQUIRED=false \
  -e PDS_RATE_LIMITS_ENABLED=false \
  -e PDS_DISABLE_SSRF_PROTECTION=true \
  -e "PDS_DID_PLC_URL=http://${plc_container}:3001" \
  "${image}" >/dev/null

for _ in $(seq 1 60); do
  if docker exec "${pds_container}" node -e \
    'const r=await fetch("http://127.0.0.1:2583/xrpc/com.atproto.server.describeServer"); if(!r.ok) process.exit(1)' \
    >/dev/null 2>&1; then
    break
  fi
  if ! docker ps --format '{{.Names}}' | rg -x "${pds_container}" >/dev/null; then
    docker logs "${pds_container}" >&2
    exit 1
  fi
  sleep 1
done
docker exec "${pds_container}" node -e \
  'const r=await fetch("http://127.0.0.1:2583/xrpc/com.atproto.server.describeServer"); if(!r.ok) process.exit(1)' \
  >/dev/null

docker exec -e "ACCOUNT_PASSWORD=${account_password}" "${pds_container}" node -e '
  const r=await fetch("http://127.0.0.1:2583/xrpc/com.atproto.server.createAccount",{
    method:"POST",
    headers:{"content-type":"application/json"},
    body:JSON.stringify({
      handle:"comail-alpha-proof.test",
      email:"comail-alpha-proof@example.com",
      password:process.env.ACCOUNT_PASSWORD,
    }),
  })
  const body=await r.text()
  if(!r.ok) throw new Error(`createAccount failed with HTTP ${r.status}`)
  process.stdout.write(body)
' >"${account_file}"
chmod 600 "${account_file}"
synthetic_did="$(jq -er '.did | select(startswith("did:plc:"))' "${account_file}")"

docker exec -e "PROOF_DID=${synthetic_did}" "${plc_container}" node -e '
  const r=await fetch(`http://localhost:3001/${encodeURIComponent(process.env.PROOF_DID)}/log/last`)
  const b=await r.json()
  if(r.status!==200||b.type!=="plc_operation") process.exit(1)
' >/dev/null

docker cp "${repo_root}/scripts/testdata/official-spaces-alpha-prepare-proof.mjs" \
  "${pds_container}:/tmp/prepare-proof.mjs"
docker cp "${account_file}" "${pds_container}:/tmp/account.json"

proof="$({
  docker exec --user root \
    -e PDS_ORIGIN=http://localhost:2583 \
    -e ACCOUNT_FILE=/tmp/account.json \
    "${pds_container}" node /tmp/prepare-proof.mjs
})"
printf '%s\n' "${proof}" | jq -e '
  .sourceMessages == 99 and
  .first == {captured:99, skipped:0, verified:99} and
  .second == {captured:0, skipped:99, verified:99} and
  .inventory == {messages:99, states:99} and
  .atomicRollbackVerified and
  .spaceCredentialIssued and .dpopReadVerified and
  .wrongKeyRejected and .wrongSpaceRejected and
  .delegationReplayRejected and .delegationWrongSpaceRejected and
  .staleSwapAccepted and
  (.schemaValidationAttempted == false) and
  (.narrowOAuthGrantAttempted == false) and
  (.compareAndSwap == false) and
  (.authorityCertified == false) and
  (.activationAttempted == false)
' >/dev/null

assessment="$(printf '%s\n' "${proof}" | jq \
  --arg epoch "${epoch}" \
  --arg image "${image}" \
  --arg imageConfig "${docker_config}" \
  --arg platform "${docker_platform}" \
  --arg proposalCommit "${proposal_commit}" \
  --arg referenceAppCommit "${reference_app_commit}" \
  --arg sdkSnapshot "${sdk_snapshot}" '
  {
    version:1,
    provider:"atproto-reference-pds-spaces-alpha",
    repository:"https://github.com/bluesky-social/atproto.git",
    epoch:$epoch,
    image:$image,
    imageConfig:$imageConfig,
    platform:$platform,
    evaluatedAt:"2026-08-20",
    passed:false,
    scope:"Disposable isolated localhost proof with synthetic non-sensitive identities and records only; this is compatibility evidence, not an authority certificate.",
    referencePins:{proposalCommit:$proposalCommit,referenceAppCommit:$referenceAppCommit,sdkSnapshot:$sdkSnapshot,executedByProof:false},
    checks:{
      officialAddressingAndMethods:"pass",
      atomicApplyWrites:"pass: failing two-write batch rolled back its valid create",
      syntheticPrepare:"pass: captured=99 skipped=0 verified=99",
      idempotencyRerun:"pass: captured=0 skipped=99 verified=99",
      canonicalByteReadback:"pass: 99/99 exact RFC 5322 blobs",
      delegationAndDpop:"pass",
      delegationReplay:"pass: exact JwtReplayed rejection",
      wrongKeyAndSpace:"pass: exact DpopKeyMismatch, InvalidCredential, and InvalidDelegationToken rejections",
      mailboxLexiconValidation:"not attempted: alpha writes used validate=false",
      narrowOAuthGrant:"not attempted: synthetic account credential used",
      staleCompareAndSwap:"fail: the alpha lexicons expose no write precondition and the reference PDS accepted a stale swapRecord field while overwriting the newer record",
      authorityAdmission:"fail-closed",
      activation:"not attempted"
    },
    limitations:{
      production:"Real member mail remains on unchanged Stalwart authority; the upstream alpha explicitly excludes production and sensitive data.",
      mutableState:"The current Comail mailbox contract requires provider-enforced compare-and-swap; client-side read/check/write is not an acceptable substitute.",
      oauth:"The local protocol probe used the synthetic account legacy access JWT to request delegation tokens; narrow interactive OAuth scope proof and a reusable writer-repo lifecycle remain required.",
      schema:"Writes used validate=false because the unpublished email.atmos mailbox lexicons were not installed in the disposable PDS; mailbox-schema validation remains required.",
      durability:"The alpha has no security-review, backup, stable-schema, or non-destructive-upgrade guarantee."
    }
  }')"

if ! diff -u \
  <(jq -S . "${repo_root}/providers/official-spaces-alpha-assessment.json") \
  <(printf '%s\n' "${assessment}" | jq -S .); then
  printf 'committed assessment does not match this exact proof run\n' >&2
  exit 1
fi
printf '%s\n' "${assessment}" | jq .
