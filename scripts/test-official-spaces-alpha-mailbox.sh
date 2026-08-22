#!/usr/bin/env bash
# Proves the exact five-schema Comail v3 mailbox contract against a disposable
# image derived only from the pinned official Spaces alpha PDS. The unmodified
# base is tested first and must reject validate=true. No operator credentials,
# real identities, real mail, hosted PDS, or activation surface are touched.
set -euo pipefail
umask 077

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
lock_file="${repo_root}/providers/official-spaces-alpha-mailbox-validation.lock"

for tool in awk diff docker go jq mktemp openssl rg shasum; do
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

file_sha256() {
  shasum -a 256 "$1" | awk '{print $1}'
}

base_commit="$(lock_value base_commit)"
base_image_name="$(lock_value base_image)"
base_digest="$(lock_value base_digest)"
platform="$(lock_value platform)"
base_prepare_sha256="$(lock_value base_prepare_sha256)"
patched_prepare_sha256="$(lock_value patched_prepare_sha256)"
installer="$(lock_value installer)"
installer_sha256="$(lock_value installer_sha256)"
recipe="$(lock_value recipe)"
recipe_sha256="$(lock_value recipe_sha256)"
wrapper="$(lock_value wrapper)"
wrapper_sha256="$(lock_value wrapper_sha256)"
proof_source="$(lock_value proof_source)"
proof_source_sha256="$(lock_value proof_source_sha256)"
container_runner="$(lock_value container_runner)"
container_runner_sha256="$(lock_value container_runner_sha256)"
plc_mock="$(lock_value plc_mock)"
plc_mock_sha256="$(lock_value plc_mock_sha256)"
tls_proxy="$(lock_value tls_proxy)"
tls_proxy_sha256="$(lock_value tls_proxy_sha256)"
schema_bundle_sha256="$(lock_value schema_bundle_sha256)"
base_image="${base_image_name}@${base_digest}"

for key in schema_message schema_message_state_revision schema_message_state_operation schema_folder_revision schema_folder_operation; do
  path="$(lock_value "${key}_path")"
  expected="$(lock_value "${key}_sha256")"
  actual="$(file_sha256 "${repo_root}/${path}")"
  if [[ "${actual}" != "${expected}" ]]; then
    printf 'pinned schema hash mismatch: %s\n' "${path}" >&2
    exit 1
  fi
done
if [[ "$(file_sha256 "${repo_root}/${installer}")" != "${installer_sha256}" ]]; then
  printf 'schema installer hash mismatch\n' >&2
  exit 1
fi
if [[ "$(file_sha256 "${repo_root}/${recipe}")" != "${recipe_sha256}" ]]; then
  printf 'schema recipe hash mismatch\n' >&2
  exit 1
fi
for pinned_file in \
  "${wrapper}:${wrapper_sha256}" \
  "${proof_source}:${proof_source_sha256}" \
  "${container_runner}:${container_runner_sha256}" \
  "${plc_mock}:${plc_mock_sha256}" \
  "${tls_proxy}:${tls_proxy_sha256}"; do
  pinned_path="${pinned_file%%:*}"
  pinned_sha256="${pinned_file#*:}"
  if [[ "$(file_sha256 "${repo_root}/${pinned_path}")" != "${pinned_sha256}" ]]; then
    printf 'proof input hash mismatch: %s\n' "${pinned_path}" >&2
    exit 1
  fi
done
computed_bundle_sha256="$({
  printf '%s\n' \
    'email.atmos.message=dfec09b66d2b64b856bf24f9165f4f1a3b0b6912589f955e5266d2ad632eafbd' \
    'email.atmos.messageStateRevision=24e5e48598bd32cba97240b19c09c3576a43a62a13592f77ada55df06ebe17f8' \
    'email.atmos.messageStateOperation=0c0d12ec2f818b40a85ebecf14af1fa1fc4a44e260f3ba490cb996639429326b' \
    'email.atmos.folderRevision=7b04352914ab168d69f54b0656b741e50c07287f3d9c3bac20a911407afbd136' \
    'email.atmos.folderOperation=7c2e1a4c144c1c114b627c815d88cf95306240561a748bb5b0aa589582b8986b'
} | shasum -a 256 | awk '{print $1}')"
if [[ "${computed_bundle_sha256}" != "${schema_bundle_sha256}" ]]; then
  printf 'schema bundle hash mismatch\n' >&2
  exit 1
fi

proof_docker_host="$(docker context inspect --format '{{.Endpoints.docker.Host}}')"
case "${proof_docker_host}" in
  unix:///*) ;;
  *) printf 'proof requires a local Unix-socket Docker context\n' >&2; exit 1 ;;
esac

runtime_dir="$(mktemp -d /tmp/comail-official-mailbox.XXXXXX)"
run_id="${runtime_dir##*.}"
proof_docker_config="${runtime_dir}/docker-config"
proof_container_inputs="${runtime_dir}/container-inputs"
mkdir -p "${proof_docker_config}" "${proof_container_inputs}"
cp "${repo_root}/scripts/testdata/official-spaces-alpha-plc-mock.mjs" \
  "${proof_container_inputs}/plc-mock.mjs"
cp "${repo_root}/scripts/testdata/official-spaces-alpha-run-with-plc.sh" \
  "${proof_container_inputs}/run-with-plc.sh"
cp "${repo_root}/scripts/testdata/official-spaces-alpha-tls-proxy.mjs" \
  "${proof_container_inputs}/tls-proxy.mjs"
export DOCKER_CONFIG="${proof_docker_config}"
export DOCKER_HOST="${proof_docker_host}"
resource_label="comail.proof.run=${run_id}"
network="comail-mailbox-net-${run_id}"
base_container="comail-mailbox-base-${run_id}"
patched_container="comail-mailbox-patched-${run_id}"
base_volume="comail-mailbox-base-data-${run_id}"
patched_volume="comail-mailbox-patched-data-${run_id}"
patched_image="comail-official-alpha-mailbox-proof:${run_id}"
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

remove_owned_image() {
  local label
  if ! docker image inspect "${patched_image}" >/dev/null 2>&1; then
    return 0
  fi
  label="$(docker image inspect --format '{{ index .Config.Labels "comail.proof.run" }}' "${patched_image}" 2>/dev/null || true)"
  if [[ "${label}" != "${run_id}" ]]; then
    printf 'refusing to remove unowned image %s\n' "${patched_image}" >&2
    cleanup_failed=1
    return 0
  fi
  docker image rm "${patched_image}" >/dev/null || cleanup_failed=1
}

cleanup() {
  local original_status=$?
  trap - EXIT INT TERM
  set +e
  remove_owned container "${base_container}"
  remove_owned container "${patched_container}"
  remove_owned network "${network}"
  remove_owned volume "${base_volume}"
  remove_owned volume "${patched_volume}"
  remove_owned_image
  case "${runtime_dir}" in
    /tmp/comail-official-mailbox.*) rm -rf -- "${runtime_dir}" || cleanup_failed=1 ;;
    *) printf 'refusing unexpected runtime cleanup path: %s\n' "${runtime_dir}" >&2; cleanup_failed=1 ;;
  esac
  for resource in "container:${base_container}" "container:${patched_container}" "network:${network}" "volume:${base_volume}" "volume:${patched_volume}"; do
    if docker "${resource%%:*}" inspect "${resource#*:}" >/dev/null 2>&1; then
      printf 'owned proof resource remains after cleanup: %s\n' "${resource}" >&2
      cleanup_failed=1
    fi
  done
  if docker image inspect "${patched_image}" >/dev/null 2>&1; then
    printf 'owned proof image remains after cleanup: %s\n' "${patched_image}" >&2
    cleanup_failed=1
  fi
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
trap 'printf "mailbox proof stopped at wrapper line %d (status %d)\n" "${LINENO}" "$?" >&2' ERR

printf 'mailbox proof: verifying and deriving the pinned image\n' >&2
docker pull --platform "${platform}" "${base_image}" >/dev/null
pulled_manifest="$(docker image inspect --format '{{.Descriptor.digest}}' "${base_image}")"
pulled_platform="$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "${base_image}")"
pulled_commit="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "${base_image}")"
if [[ "${pulled_manifest}" != "${base_digest}" || "${pulled_platform}" != "${platform}" || "${pulled_commit}" != "${base_commit}" ]]; then
  printf 'pinned official base image identity drifted\n' >&2
  exit 1
fi
prepare_hash="$(docker run --rm --platform "${platform}" --entrypoint sha256sum "${base_image}" /app/packages/pds/dist/repo/prepare.js | awk '{print $1}')"
if [[ "${prepare_hash}" != "${base_prepare_sha256}" ]]; then
  printf 'pinned official base validator drifted\n' >&2
  exit 1
fi

docker build --platform "${platform}" --pull=false \
  -f "${repo_root}/${recipe}" \
  --build-arg "BASE_IMAGE=${base_image}" \
  --build-arg "BASE_COMMIT=${base_commit}" \
  --build-arg "PATCHED_PREPARE_SHA256=${patched_prepare_sha256}" \
  --build-arg "INSTALLER_SHA256=${installer_sha256}" \
  --build-arg "RECIPE_SHA256=${recipe_sha256}" \
  --build-arg "SCHEMA_BUNDLE_SHA256=${schema_bundle_sha256}" \
  --build-arg "RUN_ID=${run_id}" \
  -t "${patched_image}" "${repo_root}" >/dev/null

for label_key in base-commit patched-prepare-sha256 installer-sha256 recipe-sha256 schema-bundle-sha256; do
  case "${label_key}" in
    base-commit) expected="${base_commit}" ;;
    patched-prepare-sha256) expected="${patched_prepare_sha256}" ;;
    installer-sha256) expected="${installer_sha256}" ;;
    recipe-sha256) expected="${recipe_sha256}" ;;
    schema-bundle-sha256) expected="${schema_bundle_sha256}" ;;
  esac
  actual="$(docker image inspect --format "{{ index .Config.Labels \"comail.proof.${label_key}\" }}" "${patched_image}")"
  if [[ "${actual}" != "${expected}" ]]; then
    printf 'derived proof image label mismatch: %s\n' "${label_key}" >&2
    exit 1
  fi
done
if [[ "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "${patched_image}")" != "${platform}" ]]; then
  printf 'derived proof image platform mismatch\n' >&2
  exit 1
fi
actual_patched_prepare_sha256="$(docker run --rm --platform "${platform}" --entrypoint sha256sum \
  "${patched_image}" /app/packages/pds/dist/repo/prepare.js | awk '{print $1}')"
if [[ "${actual_patched_prepare_sha256}" != "${patched_prepare_sha256}" ]]; then
  printf 'derived proof validator hash mismatch\n' >&2
  exit 1
fi

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath \
  -o "${runtime_dir}/mailbox-proof" ./scripts/testdata/official-spaces-alpha-mailbox-proof
chmod 700 "${runtime_dir}/mailbox-proof"

openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "${runtime_dir}/tls-key.pem" \
  -out "${runtime_dir}/tls-cert.pem" \
  -days 1 -subj '/CN=pds-proof.test' \
  -addext 'subjectAltName=DNS:pds-proof.test' \
  -addext 'basicConstraints=critical,CA:TRUE' >/dev/null 2>&1
chmod 644 "${runtime_dir}/tls-key.pem" "${runtime_dir}/tls-cert.pem"

docker network create --internal --subnet 192.0.2.0/24 \
  --label "${resource_label}" "${network}" >/dev/null
docker volume create --label "${resource_label}" "${base_volume}" >/dev/null
docker volume create --label "${resource_label}" "${patched_volume}" >/dev/null

rotation_key="$(openssl rand -hex 32)"
dpop_secret="$(openssl rand -hex 32)"
jwt_secret="$(openssl rand -hex 32)"
admin_password="$(openssl rand -hex 32)"
base_account_password="$(openssl rand -hex 32)"
patched_account_password="$(openssl rand -hex 32)"

initialize_volume() {
  local image="$1" volume="$2"
  docker run --rm --platform "${platform}" --user root --entrypoint sh \
    -v "${volume}:/data" "${image}" \
    -lc 'mkdir -p /data/blobs /data/actors && chown -R node:node /data'
}

start_pds() {
  local name="$1" volume="$2" image="$3"
  docker create --platform "${platform}" --name "${name}" --user root \
    --label "${resource_label}" --network "${network}" --ip 192.0.2.10 \
    --add-host pds-proof.test:192.0.2.10 \
    -v "${volume}:/data" \
    -e PDS_HOSTNAME=pds-proof.test \
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
    -e PDS_DID_PLC_URL=http://127.0.0.1:3001 \
    -e TLS_KEY_FILE=/tmp/comail-tls-key.pem \
    -e TLS_CERT_FILE=/tmp/comail-tls-cert.pem \
    -e SSL_CERT_FILE=/tmp/comail-tls-cert.pem \
    --entrypoint dumb-init "${image}" -- /bin/sh -c \
    'chmod -R a+rX /proof && exec /bin/su node -s /bin/sh -c "exec /bin/sh /proof/run-with-plc.sh"' >/dev/null
  docker cp "${proof_container_inputs}/." "${name}:/proof" >/dev/null
  docker cp "${runtime_dir}/tls-key.pem" "${name}:/tmp/comail-tls-key.pem" >/dev/null
  docker cp "${runtime_dir}/tls-cert.pem" "${name}:/tmp/comail-tls-cert.pem" >/dev/null
  docker start "${name}" >/dev/null
  for _ in $(seq 1 90); do
    if docker exec "${name}" node -e \
      'const r=await fetch("http://127.0.0.1:2583/xrpc/com.atproto.server.describeServer"); if(!r.ok) process.exit(1)' \
      >/dev/null 2>&1; then
      if docker exec "${name}" node -e '
        const fs=require("node:fs"),https=require("node:https")
        const request=https.get("https://pds-proof.test/xrpc/com.atproto.server.describeServer",{ca:fs.readFileSync("/tmp/comail-tls-cert.pem")},response=>process.exit(response.statusCode===200?0:1))
        request.on("error",()=>process.exit(1))
      ' >/dev/null 2>&1; then
        return 0
      fi
      docker logs "${name}" >&2
      return 1
    fi
    if ! docker ps --format '{{.Names}}' | rg -x "${name}" >/dev/null; then
      docker container inspect --format \
        'PDS container stopped: exit={{.State.ExitCode}} oom={{.State.OOMKilled}} error={{json .State.Error}} entrypoint={{json .Config.Entrypoint}} command={{json .Config.Cmd}}' \
        "${name}" >&2 || true
      docker logs "${name}" >&2
      return 1
    fi
    sleep 1
  done
  docker logs "${name}" >&2
  return 1
}

create_account() {
  local name="$1" password="$2" output="$3"
  docker exec -e "ACCOUNT_PASSWORD=${password}" "${name}" node -e '
    const r=await fetch("http://127.0.0.1:2583/xrpc/com.atproto.server.createAccount",{
      method:"POST",headers:{"content-type":"application/json"},
      body:JSON.stringify({handle:"comail-alpha-proof.pds-proof.test",email:"comail-alpha-proof@example.com",password:process.env.ACCOUNT_PASSWORD}),
    })
    const body=await r.text()
    if(!r.ok) throw new Error(`createAccount failed with HTTP ${r.status}`)
    process.stdout.write(body)
  ' >"${output}"
  chmod 600 "${output}"
}

run_proof() {
  local name="$1" account_file="$2" mode="$3"
  docker cp "${runtime_dir}/mailbox-proof" "${name}:/tmp/mailbox-proof" >/dev/null
  docker cp "${account_file}" "${name}:/tmp/account.json" >/dev/null
  docker exec --user root "${name}" /tmp/mailbox-proof \
    --mode="${mode}" --account-file=/tmp/account.json \
    --origin=https://pds-proof.test --plc-origin=http://127.0.0.1:3001 \
    --projection-dir=/tmp/comail-projections
}

initialize_volume "${base_image}" "${base_volume}"
start_pds "${base_container}" "${base_volume}" "${base_image}"
create_account "${base_container}" "${base_account_password}" "${runtime_dir}/base-account.json"
base_proof="$(run_proof "${base_container}" "${runtime_dir}/base-account.json" base-rejection)"
printf '%s\n' "${base_proof}" | jq -e '
  .mode == "base-rejection" and
  (.schemaValidationAttempted == true) and
  .unmodifiedBaseRejectsStrictSchemas and
  (.unmodifiedBaseCommittedRecord == false) and
  (.authorityCertified == false) and
  (.hostedBlueskyAcceptance == false) and
  (.activationAttempted == false)
' >/dev/null
printf 'mailbox proof: unmodified base rejected validate=true and committed nothing\n' >&2
remove_owned container "${base_container}"
remove_owned volume "${base_volume}"

initialize_volume "${patched_image}" "${patched_volume}"
start_pds "${patched_container}" "${patched_volume}" "${patched_image}"
create_account "${patched_container}" "${patched_account_password}" "${runtime_dir}/patched-account.json"
patched_did="$(jq -er '.did | select(startswith("did:plc:"))' "${runtime_dir}/patched-account.json")"
docker exec -e "PROOF_DID=${patched_did}" "${patched_container}" node -e '
  const r=await fetch(`http://127.0.0.1:3001/${encodeURIComponent(process.env.PROOF_DID)}/log/last`)
  if(!r.ok) throw new Error(`PLC read failed with HTTP ${r.status}`)
  process.stdout.write(await r.text())
' >"${runtime_dir}/plc-operation.json"
chmod 600 "${runtime_dir}/plc-operation.json"

full_proof="$(run_proof "${patched_container}" "${runtime_dir}/patched-account.json" full)"
printf '%s\n' "${full_proof}" | jq -e '
  .mode == "full" and .sourceMessages == 99 and
  .first == {captured:99,skipped:0,verified:99} and
  .second == {captured:0,skipped:99,verified:99} and
  .inventory == {messages:99,messageStateRevisions:99,messageStateOperations:99,folderRevisions:7,folderOperations:7} and
  .validReceipts == 311 and (.schemaValidationAttempted == true) and
  .invalidKnownSchemaRejected and .unknownSchemaRejected and .atomicRollbackVerified and
  .spaceCredentialIssued and .dpopReadVerified and .sourceAuthenticatedRecovery and
  .recoveredMessages == 99 and .recoveredFolders == 7 and .recoveredStates == 99 and
  .freshProjectionRebuild and .projectionManifestsEqual and .projectionMode0600 and
  (.projectionManifestSHA256 | test("^[0-9a-f]{64}$")) and
  (.authorityCertified == false) and (.hostedBlueskyAcceptance == false) and (.activationAttempted == false)
' >/dev/null
full_projection_manifest="$(printf '%s\n' "${full_proof}" | jq -er '.projectionManifestSHA256')"
printf 'mailbox proof: five-schema writes, DPoP read, CAR recovery, and projection passed\n' >&2

remove_owned container "${patched_container}"
start_pds "${patched_container}" "${patched_volume}" "${patched_image}"
docker cp "${runtime_dir}/plc-operation.json" "${patched_container}:/tmp/plc-operation.json" >/dev/null
docker exec --user root "${patched_container}" node --input-type=module -e '
  import fs from "node:fs/promises"
  import {didForCreateOp} from "/app/node_modules/@did-plc/lib/dist/index.js"
  const operation=JSON.parse(await fs.readFile("/tmp/plc-operation.json","utf8"))
  const did=await didForCreateOp(operation)
  const r=await fetch(`http://127.0.0.1:3001/${encodeURIComponent(did)}`,{
    method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(operation),
  })
  if(!r.ok) throw new Error(`PLC restore failed with HTTP ${r.status}`)
' >/dev/null
restart_proof="$(run_proof "${patched_container}" "${runtime_dir}/patched-account.json" recovery-only)"
printf '%s\n' "${restart_proof}" | jq -e --arg expectedManifest "${full_projection_manifest}" '
  .mode == "recovery-only" and .sourceMessages == 99 and
  .spaceCredentialIssued and .dpopReadVerified and .sourceAuthenticatedRecovery and
  .recoveredMessages == 99 and .recoveredFolders == 7 and .recoveredStates == 99 and
  .freshProjectionRebuild and .projectionManifestsEqual and .projectionMode0600 and
  .projectionManifestSHA256 == $expectedManifest and
  (.authorityCertified == false) and (.hostedBlueskyAcceptance == false) and (.activationAttempted == false)
' >/dev/null
printf 'mailbox proof: persisted-volume restart recovery and projection passed\n' >&2

assessment="$(jq -n \
  --arg baseCommit "${base_commit}" \
  --arg baseImage "${base_image}" \
  --arg platform "${platform}" \
  --arg patchedPrepareSHA256 "${patched_prepare_sha256}" \
  --arg installerSHA256 "${installer_sha256}" \
  --arg recipeSHA256 "${recipe_sha256}" \
  --arg schemaBundleSHA256 "${schema_bundle_sha256}" '
  {
    version:1,
    provider:"atproto-reference-pds-spaces-alpha",
    evaluatedAt:"2026-08-21",
    passed:true,
    scope:"Disposable isolated local-Docker proof using only synthetic non-sensitive identities, RFC 5322 bytes, records, and fresh projections; this is exact compatibility evidence, not hosted-provider or authority certification.",
    pins:{baseCommit:$baseCommit,baseImage:$baseImage,platform:$platform,patchedPrepareSHA256:$patchedPrepareSHA256,installerSHA256:$installerSHA256,recipeSHA256:$recipeSHA256,schemaBundleSHA256:$schemaBundleSHA256},
    checks:{
      unmodifiedBaseRejectsStrictSchemas:"pass: validate=true rejected the unregistered third-party record and committed nothing",
      mailboxLexiconValidation:"pass: all 311 create receipts returned validationStatus=valid across the exact five schemas",
      failClosedValidation:"pass: invalid known-schema and unknown-schema writes were rejected without residual records",
      atomicApplyWrites:"pass: a failing two-create batch rolled back its valid first create",
      syntheticPrepare:"pass: captured=99 skipped=0 verified=99",
      idempotencyRerun:"pass: captured=0 skipped=99 verified=99",
      sourceAuthenticatedRecovery:"pass: signed stable CAR, complete five-collection reduction, and 99/99 exact blobs before and after PDS restart",
      freshProjectionRebuild:"pass: fresh SQLite projections committed with mode 0600; source-derived semantic manifests matched within each run and across restart",
      delegationAndDpop:"pass",
      hostedBlueskyAcceptance:false,
      authorityCertified:false,
      activationAttempted:false
    },
    limitations:{
      schemas:"The exact five record schemas are bundled only into this isolated image and are not published at the live Lexicon authority yet.",
      oauth:"Synthetic account legacy access JWT was used for the writer lane; the exact narrow steady OAuth grant was proven separately against the hosted alpha account.",
      mail:"There is no real mail, real member identity, Stalwart authority switch, hosted write, or production activation in this proof.",
      durability:"The upstream alpha still has no stable-schema, backup, security-review, or non-destructive-upgrade guarantee."
    }
  }
')"

if ! diff -u \
  <(jq -S . "${repo_root}/providers/official-spaces-alpha-mailbox-validation-assessment.json") \
  <(printf '%s\n' "${assessment}" | jq -S .); then
  printf 'committed assessment does not match this exact proof run\n' >&2
  exit 1
fi
printf '%s\n' "${assessment}" | jq .
