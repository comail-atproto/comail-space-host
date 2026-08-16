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
and [promotion gates](docs/promotion-gates.md).

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

## Current rsky result

The pinned rsky epoch is **not certified for mailbox writes**. Its
`apply_space_writes` path commits the space transaction before it verifies and
promotes referenced blobs. A missing blob can therefore produce an error after
a record was committed, violating Comail's SMTP/delivery atomicity contract.
The rsky client hard-disables normal write mode and reports
`atomicApplyWrites=false`; only an explicitly named certification probe can
exercise writes.

```bash
./scripts/test-rsky.sh
```

The source audit intentionally exits non-zero at this epoch. The provider gate
can move only after rsky verifies blobs before committing and carries a test
which proves an errored batch leaves no residual record.
The machine-readable result is recorded in
`providers/rsky-certification.json`; it is a failed certificate, not approval.

OAuth plumbing is present but does not bypass that write block. `vault-init`
creates a private AES-256-GCM vault and separate key; `oauth-login` requests an
exact DID/PDS/mailbox-space grant over a fixed loopback callback and stores
access tokens, refresh tokens, PKCE material, and DPoP keys only in that vault.

The Blacksky/rsky provider is pinned in `providers/rsky.lock`. Its upstream
permissioned-space integration tests are invoked by `scripts/test-rsky.sh` in a
temporary checkout; rsky source is not vendored or modified here.
