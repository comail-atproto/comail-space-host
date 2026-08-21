# Architecture

Status: laboratory design, not production approval.

## Authority boundary

The permissioned PDS repository is authoritative for:

- canonical RFC 5322 bytes;
- immutable delivery identity and integrity metadata;
- folders and folder roles;
- flags, keywords, moves, drafts, sent copies, and tombstones.

The standards projection is authoritative only for transient protocol/session
state. Stable UID/UIDVALIDITY migration hints are retained in permissioned
records so deleting and rebuilding a projection does not unnecessarily reset
existing IMAP clients.

## Provider-neutral repository contract

The lab talks to a provider through five operations:

1. create or discover an exact mailbox space;
2. upload one RFC 5322 blob into the authenticated user's repo;
3. atomically create records with `applyWrites`;
4. update mutable records using CID compare-and-swap;
5. list records and fetch only blobs referenced by that exact space.

Full rebuild requires only authenticated `listRecords` and `getBlob`. Oplog,
CAR export, and notifications are certified accelerators, not correctness
requirements.

The unmodified pinned rsky epoch does not satisfy operation 3 for records which
reference blobs. The lab's exact pinned patch verifies/promotes referenced
blobs before the record transaction, and a regression proves rejected writes
leave no record. Write mode requires that exact epoch+patch certification and
remains disabled for normal or hosted rsky clients.

### HappyView compatibility provider

For the own-PDS experiment, the user's ordinary PDS provides DID resolution and
AT Protocol OAuth while a pinned local HappyView instance provides the separate
permissioned space host. This does not claim that the ordinary PDS stores the
mailbox. A future portable deployment advertises `#atproto_space_host` in the
DID document or uses a PDS with native permissioned-space support.

HappyView's standard blob upload proxies to the ordinary PDS, while its space
records live in the HappyView database. Therefore the compatibility provider
does not use native blobs for canonical email. It divides each message into
384-KiB `email.atmos.blobChunk` records in the private mailbox space, binds them
to an `email.atmos.blobManifest`, and uses an `email.atmos.blobIndex` to resolve
the manifest CID exposed through the repository abstraction. Every chunk and
the reconstructed message are verified with SHA-256 and bounded at 10 MiB.

This shim preserves the provider-neutral Comail mailbox model and proves the
full migration/rebuild path today. It is not a proposal to standardize chunked
email records; a ratified private-blob facility can replace only this adapter.

## Data model

### `email.atmos.message` v1

Immutable. The rkey is a versioned SHA-256 delivery fingerprint over recipient
DID, stable source identity, and canonical bytes. The source identity prevents
distinct entries with identical bytes from collapsing. It contains the blob reference, byte hash and size,
initial mailbox, optional delivery timestamp, and optional RFC 5322 threading
metadata. Legacy SQLite imports leave delivery time absent rather than inventing
one from the untrusted message `Date` header.

### `email.atmos.messageState` v0

Mutable and deliberately experimental until provider CAS tests pass. It holds
folder IDs, JMAP-compatible keywords, IMAP delete-pending state, tombstone
state, a logical revision, and an optional single-folder migration identity
(`uid`, `uidValidity`, `modSeq`). Multi-folder JMAP entries receive stable
per-folder identities when a projection is rebuilt. Updates require the prior record CID.

### `email.atmos.folder` v0

Mutable and experimental. Folder rkeys are deterministic hashes of the
case-preserved source collection name. The record holds name, optional role,
UIDVALIDITY, and revision.

## Delivery transaction

For the future authority flip, but not enabled by this lab:

1. Resolve recipient to an exact `(DID, PDS epoch, space URI, repo DID)` target.
2. Persist an encrypted per-recipient transaction spool entry.
3. Upload the RFC 5322 blob.
4. Atomically create immutable message and initial state records.
5. Verify the committed record and blob hash.
6. Return SMTP `250`; otherwise return `451` and leave retry ownership with the
   sending MTA.
7. Project asynchronously and idempotently.

No accepted message silently falls back to SQLite or another provider.

## Source migration

Migration reads either a consistent legacy Comail snapshot or a closed
one-account Vandelay archive in immutable/query-only mode. It streams live
messages without writing mail content to an intermediate manifest:

1. enumerate folders and non-expunged messages for one exact DID/space;
2. validate JSON columns, sizes, hashes, and RFC 5322 presence;
3. create folder records;
4. upload each blob and create its message/state pair idempotently;
5. rebuild into a fresh projection target;
6. compare source and destination fingerprints, flags, folders, and stable IDs;
7. emit redacted evidence.

The source snapshot is never modified or deleted. Promotion, if ever approved,
would keep it as a rollback artifact under the existing retention policy.

## OAuth session boundary

The official Spaces profile uses two separate browser authorizations. A
one-time provisioning grant is bound to the exact authority DID and exact
mailbox key and carries only `action=read_self&manage=create`. It creates or
reconciles a member-list/open-app space, proves that the fresh space has zero
explicit members (the owner is implicit), then revokes both OAuth tokens and
deletes the encrypted local session before reporting success.

The steady grant is separately bound to that exact DID and key. It carries
only `read` and `create` over the five append-only mailbox collections plus a
`message/rfc822` blob scope. It has no wildcard, update, delete, or space
management permission. Refresh is fail-closed because provider-normalized
replacement scopes cannot be independently verified; an expired or invalid
token requires interactive reauthorization.

OAuth discovery, token exchange, refresh, and authenticated XRPC calls use one
operator-pinned origin. HTTPS addresses are resolved once, private/link-local
answers are rejected, proxies are disabled, TLS uses the original hostname,
and redirects are refused. The callback is an exact IPv4 loopback URL.
Session and pending-flow state are stored in an AES-256-GCM file with a
separate 32-byte key; both files and their directory are private and updates
are fsync/rename atomic under a cross-process lock. The production adapter
never receives or persists these browser OAuth credentials.

The HappyView proof uses HappyView's own OAuth flow against the user's current
PDS. Its signed HttpOnly dashboard cookie is captured through a random one-use
URL on a second exact IPv4 loopback port (cookies are host-scoped, not
port-scoped), then stored create-only with mode 0600. Provider requests disable
proxies and redirects and refuse any non-loopback destination.

## Production service-grant boundary

The production adapter does not retain the lab browser OAuth session. The
space owner grants the published adapter `did:web` identity write membership
in one exact private mailbox space. The adapter signs a provider-audience and
XRPC-method-bound ES256 service JWT with a 60-second lifetime for each request.
There is no refresh token: membership is the durable provider-owned grant, and
removing or downgrading it makes the next target verification fail closed.

The relay binding ledger supplies a credential-free
`(DID, provider, epoch, origin, repo, space, certificate)` tuple. The adapter
admits it only when provider, epoch, origin, and certificate equal the globally
certified HappyView registration, the space URI is the exact mailbox space for
the same DID, and live provider responses prove both owner-only private policy
and exactly one resolved `write` membership for the configured adapter service
DID. Read-only, missing, duplicated, or revoked service membership fails before
the adapter exposes mailbox capabilities. Target mismatch is rejected before a
provider call. Successful resolution is intentionally not cached, so grant
revocation, downgrade, and space-policy drift take effect on the next operation.
