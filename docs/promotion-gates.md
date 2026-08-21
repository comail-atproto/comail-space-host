# Promotion gates

The isolated lab may proceed with synthetic identities. No production code,
mailbox, routing, or flag changes are authorized by passing these gates.

## Gate A — provider capability

- [x] Pinned rsky source was resolved and audited at the locked commit.
- [x] The isolated pinned rsky build plus the exact lab patch verifies
      referenced blobs before committing space records and carries a residual
      record regression. The unmodified upstream epoch still fails this gate.
- [x] All 16 space integration tests pass after applying the patch, including
      an exact Comail mailbox authority round-trip and cross-account blob deny.
- [ ] OAuth grants enforce the requested space, actions, and collections.
- [ ] Refresh survives restart and concurrent refresh is single-flight.
- [ ] Revocation stops reads and writes within the declared SLO.
- [x] Pinned local HappyView `applyWrites` atomically creates the message/state
      pair and `putRecord` rejects a stale CID in the live authority
      certification. Hosted providers must repeat this check independently.
- [ ] Message-size and quota limits are measured and compatible.
- [ ] Mailbox Lexicons are provider-registered and server validation is
      enabled, or an equivalently strict certified validation path is approved.
- [x] The exact official-alpha digest plus an isolated install of the five
      byte-pinned alpha-candidate schemas
      accepts 311 `validate=true` creates, rejects invalid/unknown schemas, and
      rolls back a failing mixed batch. This does not satisfy hosted registration.

## Gate B — confidentiality and integrity

- [ ] Authorized referenced blob succeeds.
- [ ] Unreferenced CID fails.
- [ ] Wrong-space credential fails even for a known CID.
- [ ] Wrong-account credential fails.
- [ ] Permissioned records/blobs are absent from public sync/firehose paths.
- [ ] Record/blob hashes, repo DID, and space URI are verified on every read.

## Gate C — migration and recovery

- [x] Synthetic Comail SQLite snapshot migrates with zero mismatches.
- [x] Repeating migration creates no duplicate messages.
- [x] Interrupted migration resumes safely.
- [x] Fresh projection rebuild matches source folders, flags, hashes, and
      stable IMAP identity hints.
- [x] Deleted/expunged source rows are not resurrected.
- [ ] Poison records are quarantined without wedging other messages.
- [x] Multi-folder JMAP messages retain every membership; fresh projections
      allocate stable per-folder UIDs when the source has no IMAP identity.
- [x] Conflict-safe read/flag/move state survives a clean rebuild; a tombstoned
      message remains verifiable but is omitted from the rebuilt projection.
- [x] The official v3 source-authenticated path recovers 99/99 synthetic blobs
      and seven canonical folders into identical fresh mode-0600 SQLite
      projections before and after a persisted-volume PDS restart.

## Gate D — operator-only readiness

- [ ] Explicit operator strategy decision is recorded.
- [ ] A consistent, encrypted snapshot of the operator mailbox is supplied.
- [ ] Dry-run evidence is reviewed before any provider write.
- [ ] Provider target, DID, space, quota, and rollback snapshot are approved.
- [ ] Vault, queue, fencing, monitoring, deletion, and reconnect drills pass.

Only after Gate D may a later Comail PR add dormant, default-off integration.
