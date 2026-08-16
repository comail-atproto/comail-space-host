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

The current pinned rsky epoch does not satisfy operation 3 for records which
reference blobs: the record transaction commits before referenced-blob
verification. Normal rsky write mode is therefore disabled in code. This is a
provider certification result, not a reason to weaken the mailbox contract.

## Data model

### `email.atmos.message` v1

Immutable. The rkey is a versioned SHA-256 delivery fingerprint over recipient
DID and canonical bytes. It contains the blob reference, byte hash and size,
initial mailbox, optional delivery timestamp, and optional RFC 5322 threading
metadata. Legacy SQLite imports leave delivery time absent rather than inventing
one from the untrusted message `Date` header.

### `email.atmos.messageState` v0

Mutable and deliberately experimental until provider CAS tests pass. It holds
folder IDs, JMAP-compatible keywords, IMAP delete-pending state, tombstone
state, a logical revision, and optional migration identity (`uid`,
`uidValidity`, `modSeq`). Updates require the prior record CID.

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

## SQLite migration

Migration reads a consistent snapshot in immutable/query-only mode. It streams
live messages without writing mail content to an intermediate manifest:

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

The lab requests one exact `space:email.atmos.mailbox` grant bound to
`authority=self` and one explicit space key. Record mutations are restricted
to the three mailbox collections; whole-space read is requested because the
pinned provider's referenced-blob read path currently authorizes an
unqualified read request. Blob upload is limited to `message/rfc822`.

OAuth discovery, token exchange, refresh, and authenticated XRPC calls use one
operator-pinned origin. HTTPS addresses are resolved once, private/link-local
answers are rejected, proxies are disabled, TLS uses the original hostname,
and redirects are refused. The callback is an exact IPv4 loopback URL.
Session and pending-flow state are stored in an AES-256-GCM file with a separate
32-byte key; both files and their directory are private and updates are
fsync/rename atomic under a cross-process lock.
