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
21 npm audit findings, so the lab remains loopback-only.

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
