# Threat model

## Protected assets

- RFC 5322 content and attachments;
- OAuth access/refresh tokens and DPoP private keys;
- folder, keyword, correspondent, and timing metadata;
- correct binding between email address, account DID, PDS, space, and repo;
- SMTP acceptance integrity and Comail's sending reputation.

## Trust boundaries

The user's PDS and authorized Comail services can read plaintext mail. Network
peers, other PDS accounts/spaces, public relays/firehoses, evidence artifacts,
logs, and unauthenticated clients must not.

## Required mitigations

- Exact DID/space/repo/provider binding; caller input never selects a target at
  SMTP time.
- Space-scoped OAuth grants, durable DPoP keys, serialized refresh rotation,
  proactive refresh, and explicit reconnect/revocation behavior.
- Authenticated requests never follow redirects and use bounded bodies/timeouts.
- The operator-selected PDS origin is clean and exact; HTTPS DNS is resolved
  once, non-public answers and proxies are rejected, and TLS remains bound to
  the selected hostname.
- Blob reads require a live reference from a record in the authorized space;
  possession of a CID alone is insufficient.
- Immutable record hashes are checked before projection.
- Mutable writes use CID compare-and-swap or an append-only alternative.
- Projectors use cross-process fencing and poison-record quarantine.
- Queue and vault encryption keys live outside their databases and rotate.
- Logs and evidence reject tokens and message-derived text; hashes and counts
  are allowed.
- Deletion covers PDS records/blobs, queues, projection, search, checkpoints,
  logs, and backups according to the existing Comail GDPR policy.

## Explicitly untrusted input

SMTP content, RFC 5322 headers, Message-ID, blob CIDs found in records, PDS
errors, OAuth metadata, redirects, notification endpoints, cursor values, and
all snapshot JSON/text columns are attacker-controlled.

## Failure policy

Unknown provider/auth/quota errors are transient. Before production authority,
Comail must reject in-band with `451`, not accept and later emit a warmed-pool
backscatter DSN. Revoked or mismatched authorization fails closed. A projector
failure never changes the authoritative PDS commit.

The pinned rsky epoch is fail-closed in this lab because it promotes referenced
blobs after committing space records. Returning an error after partial durable
state is unacceptable for SMTP acceptance or migration idempotency; normal
rsky write mode remains impossible until the ordering and residual-record test
are fixed.
