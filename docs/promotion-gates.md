# Promotion gates

The isolated lab may proceed with synthetic identities. No production code,
mailbox, routing, or flag changes are authorized by passing these gates.

## Gate A — provider capability

- [x] Pinned rsky source was resolved and audited at the locked commit.
- [ ] rsky verifies referenced blobs before committing space records. **Blocked
      at the pinned epoch: commit currently happens first.**
- [ ] Pinned rsky build and upstream space integration suite pass after the
      authority-critical source audit.
- [ ] OAuth grants enforce the requested space, actions, and collections.
- [ ] Refresh survives restart and concurrent refresh is single-flight.
- [ ] Revocation stops reads and writes within the declared SLO.
- [ ] `applyWrites` is atomic and `putRecord` rejects stale CIDs.
- [ ] Message-size and quota limits are measured and compatible.
- [ ] Mailbox Lexicons are provider-registered and server validation is
      enabled, or an equivalently strict certified validation path is approved.

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
- [ ] Multi-folder messages and post-migration UID allocation are specified;
      the current importer intentionally accepts exactly one source folder per
      message and requires preserved projection identity.

## Gate D — operator-only readiness

- [ ] Explicit operator strategy decision is recorded.
- [ ] A consistent, encrypted snapshot of the operator mailbox is supplied.
- [ ] Dry-run evidence is reviewed before any provider write.
- [ ] Provider target, DID, space, quota, and rollback snapshot are approved.
- [ ] Vault, queue, fencing, monitoring, deletion, and reconnect drills pass.

Only after Gate D may a later Comail PR add dormant, default-off integration.
