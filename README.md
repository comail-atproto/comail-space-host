# Comail PDS Mailbox Lab

An isolated proof that a complete Comail mailbox can use one AT Protocol
permissioned-data space as its authority while the existing JMAP/IMAP server is
a rebuildable projection.

This repository does **not** modify or deploy Comail. It uses synthetic data by
default and refuses to migrate a live SQLite database. A real mailbox can be
considered only after the local proof, the pinned rsky certification, and an
explicit snapshot review are green.

## Intended result

For one gated account:

```text
one Atmosphere DID
        |
        +-- one email.atmos.mailbox permissioned space
                |
                +-- email.atmos.folder records
                +-- immutable email.atmos.message records
                +-- mutable email.atmos.messageState records
                +-- message/rfc822 blobs
                         |
                         +-- rebuildable standards projection
```

The canonical RFC 5322 bytes and mailbox state live in the permissioned space.
SQLite/Stalwart may retain only a projection and a small stable identity
checkpoint. Permissioned data is access control, not end-to-end encryption.

## Safety boundary

- No production hosts, routes, flags, secrets, or databases are changed.
- Authenticated HTTP redirects are refused.
- Migration evidence contains counts, sizes, hashes, and pass/fail results only.
- The migration command is dry-run unless `--commit` is given.
- A source must be a consistent SQLite snapshot, never the live database.
- One failed provider write cannot trigger fallback to another mailbox.

See [architecture](docs/architecture.md), [threat model](docs/threat-model.md),
and [promotion gates](docs/promotion-gates.md). Current operator-specific
findings and the one remaining private input are in
[operator readiness](docs/operator-readiness.md).

## Development

```bash
go test ./...
go vet ./...
```

Run the complete local proof in a new disposable directory:

```bash
go run ./cmd/comail-pds-lab synthetic-proof \
  --work-dir /absolute/path/to/new-proof-directory
```

The command creates a synthetic Comail SQLite snapshot, migrates it into an
exact permissioned-space model, verifies the destination, rebuilds a brand-new
SQLite standards projection using only permissioned records/blobs, and writes
create-only redacted `evidence.json`.

For an operator-supplied snapshot, inspection and dry-run are deliberately
separate from provider writes:

```bash
go run ./cmd/comail-pds-lab inspect \
  --snapshot /absolute/path/to/consistent-copy.sqlite \
  --did did:plc:example --space-key primary

go run ./cmd/comail-pds-lab dry-run \
  --snapshot /absolute/path/to/consistent-copy.sqlite \
  --did did:plc:example --space-key primary \
  --evidence /private/directory/dry-run.json
```

Never make that snapshot with a plain copy of a running SQLite file. Use a
service-owned backup/checkpoint operation, stop the writer, or use SQLite's
online backup API, then place the resulting regular file in a private local
directory with no non-empty WAL/journal sidecars.

The current production mailbox is Stalwart-backed, so its supported read-only
source is a Vandelay JMAP archive. Build the pinned tool once, then place a
dedicated member app-password in an ignored owner-only file so it never enters
chat or shell history:

```bash
./scripts/build-vandelay.sh
./scripts/store-vandelay-password.sh

VANDELAY_PASSWORD_FILE="$PWD/state/operator/vandelay-password" \
  ./scripts/archive-stalwart.sh \
  --url https://inbox.comail.at --user scott@comail.at \
  --archive "$PWD/state/operator/mailbox.sqlite"

go run ./cmd/comail-pds-lab dry-run-vandelay \
  --archive "$PWD/state/operator/mailbox.sqlite" \
  --did did:plc:dy67wyyakm7u4v2lthy5zwbn --space-key primary \
  --evidence "$PWD/evidence/operator-dry-run.json"

go run ./cmd/comail-pds-lab prove-vandelay \
  --archive "$PWD/state/operator/mailbox.sqlite" \
  --did did:plc:dy67wyyakm7u4v2lthy5zwbn --space-key primary \
  --work-dir "$PWD/state/operator/proof"
```

`state/` is ignored, private, and must never be committed. Revoke the dedicated
app-password and remove its file after the archive succeeds. The archive wrapper
refuses non-HTTPS sources, pre-existing outputs, broad parent permissions, and
anything except mailbox/email objects.

## Current HappyView result

The preferred own-PDS proof now uses a pinned local HappyView v2.13.0 backend.
The backend stays unmodified; an isolated frontend-only patch supplies a
separate OAuth client ID when the UI is reached through the tailnet. Your
existing PDS remains the identity and OAuth server;
HappyView is a separate loopback-only `space_host` backed by private SQLite.
No DID document, Comail service, or production repository changes are needed
for this proof.

HappyView's native `uploadBlob` route is deliberately not used: it proxies to
the ordinary PDS and does not make private permissioned-space durability a safe
email authority. The adapter stores canonical RFC 5322 bytes as deterministic,
bounded private chunk records plus a manifest inside the same mailbox space.
The normal Comail message record still receives an opaque repository `BlobRef`,
and projection/rebuild code is unchanged above the adapter.

Build and start the exact loopback instance:

```bash
./scripts/build-happyview.sh
./scripts/run-happyview.sh
```

Open `http://127.0.0.1:39090/login`, sign in as `scottlanoue.com`, and approve
the normal AT Protocol OAuth request at your current PDS. In another terminal,
capture the HttpOnly local session without developer tools:

For a browser on Scott's tailnet, the same loopback-bound process may instead
advertise the allowlisted standard-port HTTPS origin by starting it with
`HAPPYVIEW_PUBLIC_URL=https://little-mac.lobster-hake.ts.net`. Serve the
`/comail-pds-lab` path through Tailscale to `http://127.0.0.1:39090`; the
separate base-path frontend is installed under `web-tailnet`. Do not enable
Funnel: the pinned frontend remains an alpha lab surface.

Because an AT Protocol authorization server must fetch the client metadata
from public HTTPS, a tailnet build also accepts `HAPPYVIEW_OAUTH_CLIENT_ID` at
build time. It is compiled only into the tailnet frontend and must identify a
non-secret JSON document whose only redirect URI is the tailnet callback. The
app, callbacks, session cookies, mailbox records, and blobs remain tailnet-only.

```bash
go run ./cmd/comail-pds-lab capture-happyview-session \
  --out "$PWD/state/operator/happyview-cookie"
```

Open the one-use URL printed by that command in the same browser. After a
closed Vandelay archive has passed `dry-run-vandelay`, the only live provider
write command is:

```bash
go run ./cmd/comail-pds-lab prove-happyview \
  --provider happyview --commit \
  --origin http://127.0.0.1:39090 \
  --epoch f50b2afdaf207a2ba91d76cdad7a981a87785294 \
  --cookie-file "$PWD/state/operator/happyview-cookie" \
  --archive "$PWD/state/operator/mailbox.sqlite" \
  --did did:plc:dy67wyyakm7u4v2lthy5zwbn \
  --space-key primary \
  --work-dir "$PWD/state/operator/happyview-proof"
```

It creates or verifies an explicitly private space with an exact six-collection
allowlist, imports idempotently, reads every message back through HappyView,
and rebuilds a fresh SQLite projection before producing redacted evidence.
Run `./scripts/test-happyview.sh` to repeat the 31 upstream space/auth tests and
the Comail adapter/contract tests. When the local runtime is already running,
it also performs a real synthetic mailbox import, full readback/rebuild, and
second-identity denial through its HTTP routes. The certificate is
`providers/happyview-certification.json`. The pinned frontend currently reports
21 npm audit findings, so the UI remains restricted to loopback or the private
tailnet Serve route; Funnel and public app exposure stay prohibited.

For a closed legacy inboxd SQLite snapshot, `prove-happyview` accepts
`--snapshot` instead of `--archive`; the two source flags are mutually
exclusive and pass through the same destination checks, idempotent writer,
full readback, and fresh-projection rebuild.

HappyView's `/dashboard/records/` page lists ordinary public-repository
records, not permissioned-space records, so an imported mailbox correctly
appears empty there. The lab includes a separate mailbox-state viewer for the
private space. It accepts only the existing signed HappyView browser cookie,
verifies that `/auth/me` is the exact mailbox DID, pins the exact space, and
reads records and RFC 5322 blobs through HappyView's authenticated XRPC routes.
Read/unread, flag, move, and delete controls update only the mutable state
record using provider-enforced compare-and-swap; deletion is a non-destructive
lab tombstone whose canonical bytes remain verifiable but are omitted from
projections.
State POSTs require an exact same-origin request plus a strict HttpOnly CSRF
cookie. The viewer does not read HappyView's SQLite database or hold another
session.

With the tailnet HappyView process running, start the loopback-only viewer:

```bash
./scripts/run-mailbox-viewer.sh did:plc:dy67wyyakm7u4v2lthy5zwbn
```

In another terminal, attach only its loopback listener to a distinct tailnet
path, preserving the existing root and HappyView routes:

```bash
tailscale serve --bg --https=443 \
  --set-path=/comail-pds-mailbox --yes http://127.0.0.1:39093
```

Then open
`https://little-mac.lobster-hake.ts.net/comail-pds-mailbox/` in the browser
already signed into the isolated HappyView instance. The viewer sends
`Cache-Control: no-store`, a restrictive content security policy, refuses
non-GET methods, and returns 401 without the HappyView session. Keep this route
tailnet-only; never enable Funnel.

## Shadow delivery agent

The lab also exposes a narrow provider-adapter protocol for a future Comail
relay shadow. The agent holds the provider session locally; the relay receives
only a separate bearer token and an exact provider/repository/space binding.
It supports two authenticated POSTs: a capability probe and an idempotent
store-plus-readback operation. It never accepts a target from SMTP input.

Live writes require both an explicit provider and `--commit`, and the listener
is restricted to exact IPv4 loopback:

```bash
go run ./cmd/comail-pds-agent \
  --provider happyview --commit \
  --did did:plc:example \
  --cookie-file "$PWD/state/operator/happyview-cookie" \
  --token-file "$PWD/state/operator/shadow-agent-token"
```

The current operator proof used a separate private validation space, wrote one
synthetic RFC 5322 message twice, and received byte-exact authenticated
readback receipts both times with the same fingerprint. The ordinary `default`
mailbox space was not used for that write. The long-running default-space agent
has passed its live capability probe but remains disconnected from production.

Provider support is contract-based, not name-based:

- HappyView: live adapter and isolated write/readback proof complete.
- Habitat: the separate ODS proof remains useful; it needs a small adapter that
  satisfies this repository contract before it can receive shadow mail.
- Blacksky/rsky: the new hosted implementation reports permissioned-spaces
  interoperability, but this lab certifies writes only against its pinned,
  patched disposable rsky build. Hosted rsky is not eligible for shadow writes
  until an authenticated conformance run passes against its exact deployed
  epoch.
- Other PDS hosts: eligible after proving private records, referenced blobs,
  idempotent writes, authenticated read-after-write, exact target binding, and
  redirect refusal. Atomic state writes are additionally required before any
  future authority cutover.

## Mutable authority certification

The lab now tests the part that immutable shadow delivery cannot prove:
conflict-safe mailbox state and deletion recovery. The command below refuses
the real `default` and `primary` spaces, requires a new empty
`comail-cert-*` space, writes one synthetic message, and produces redacted
evidence only:

```bash
go run ./cmd/comail-pds-lab certify-happyview-authority \
  --provider happyview --commit \
  --origin http://127.0.0.1:39090 \
  --base-path /comail-pds-lab \
  --public-host little-mac.lobster-hake.ts.net \
  --cookie-file "$PWD/state/operator/happyview-cookie" \
  --did did:plc:example \
  --space-key comail-cert-unique-run \
  --work-dir "$PWD/state/operator/authority-cert-unique-run"
```

It proves byte-exact readback, atomic message-plus-state creation, rejection of
a stale provider CAS, idempotent retry of the winning state mutation, folder
movement, a clean projection rebuild, tombstoning, and a second rebuild that
does not resurrect the deleted message. The live pinned HappyView run on
2026-08-16 passed every check. This certifies the storage/state primitive; it
does not by itself authorize production routing or prove that Bulwark/Stalwart
state synchronization is complete.

## Current rsky result

The unmodified pinned rsky epoch is **not certified for mailbox writes**: its
`apply_space_writes` path commits the space transaction before it verifies a
referenced blob. The lab carries a narrow patch and regression proving that a
rejected missing-blob write leaves no durable record. With that patch, all 16
space integration tests pass, including the lab's exact Comail mailbox-space
record/blob round-trip and cross-account blob-read denial.

```bash
./scripts/test-rsky.sh
```

The machine-readable result is recorded in
`providers/rsky-certification.json`. It certifies only the pinned source plus
the exact lab patch for disposable local testing; it is not an approval of an
upstream or hosted rsky release. Normal provider writes remain hard-disabled
until a client epoch is explicitly bound to a certified build.

OAuth plumbing is present but does not bypass that write block. `vault-init`
creates a private AES-256-GCM vault and separate key; `oauth-login` requests an
exact DID/PDS/mailbox-space grant over a fixed loopback callback and stores
access tokens, refresh tokens, PKCE material, and DPoP keys only in that vault.

The Blacksky/rsky provider is pinned in `providers/rsky.lock`. Its upstream
permissioned-space integration tests are invoked by `scripts/test-rsky.sh` in a
temporary checkout after applying the reviewed patch; rsky source is not
vendored here.
