# Operator mailbox readiness

Observed 2026-08-16; no production state was changed.

## Official Spaces alpha compatibility (2026-08-20)

The disposable proof in `scripts/test-official-spaces-alpha.sh` executes the
exact `linux/amd64` reference-PDS image recorded in
`providers/official-spaces-alpha.lock`. The proposal, Bulletin reference app,
and SDK snapshot are review pins, not code executed by this proof. The wrapper
uses a synthetic account, an in-memory PLC directory, random per-run secrets,
an internal Docker network, and a fresh PDS volume. It ownership-checks and
verifies cleanup of its containers, token-bearing files, database, network,
and volume on exit. It never reads operator credentials or production data.

The exact alpha accepted official `at://.../space/...` addressing,
`com.atproto.simplespace.*` management, and `com.atproto.space.*` records. A
bounded prepare captured and byte-verified 99 synthetic RFC 5322 messages; the
immediate rerun reported `captured=0 skipped=99 verified=99`. A deliberately
failing two-write batch rolled back its valid create, proving transaction
atomicity. Delegation-token exchange, DPoP-bound reads, and exact wrong-key,
wrong-space, and replay errors also passed. No activation path exists in the
proof.

These writes used `validate=false`: they prove the official record transport
and the app's data shape, not validation of Comail's unpublished mailbox
lexicons. The proof also uses the synthetic account's legacy access JWT, not
the alpha SDK's narrow interactive OAuth grant. Both rows remain explicitly
`not attempted` in the assessment and remain promotion blockers.

This is deliberately a failing authority assessment. The alpha lexicons do
not expose a record-CID or commit precondition. The reference PDS accepted an
unknown stale `swapRecord` field and overwrote the newer state. The redacted
result is recorded in `providers/official-spaces-alpha-assessment.json` with
`compareAndSwap=false`, `authorityCertified=false`, and `passed=false`.
Client-side read/check/write is not a substitute for provider-enforced CAS.

The reusable production adapter also still needs the narrow OAuth grant and
writer-repo lifecycle; the disposable proof currently uses only a synthetic
account credential to exercise the official delegation and DPoP protocol.
Real member mail therefore remains on unchanged Stalwart authority. The
official alpha must not be wired into `cmd/comail-space-host`, admitted by the
authority certificate loader, or used with sensitive data.

## Current bindings

- Atmosphere identity: `did:plc:dy67wyyakm7u4v2lthy5zwbn`
  (`scottlanoue.com`).
- Current personal PDS: `https://pds.scottlanoue.com`.
- Current mailbox: `scott@comail.at`, served by Stalwart and exported safely
  over the public authenticated JMAP surface at `https://inbox.comail.at`.
- The current personal PDS does not natively advertise permissioned-space
  scopes, but it can authenticate the operator to a separate local HappyView
  permissioned space host. It is the identity/OAuth server in this proof, not
  the mailbox storage server.

## Isolated result

- Pinned rsky plus the exact lab patch passes 16/16 space integration tests.
- The exact Comail folder/message/state graph and RFC 5322 blob round-trip.
- A different authenticated account is denied even with the exact blob CID.
- A real pinned Vandelay archive passes import, integrity validation,
  permissioned-authority migration, post-write verification, and clean
  projection rebuild using synthetic mail.
- Main Comail repositories and all production services remain untouched.
- Pinned HappyView v2.13.0 passes 31/31 selected upstream permission, record,
  CAS, revocation, commit, and CAR tests. Its loopback SQLite runtime is built
  and starts successfully with owner-only secrets; anonymous private routes
  are denied.
- The real running HTTP adapter imports and rebuilds a synthetic mailbox, and a
  second signed synthetic identity is denied access to its private records.
- The closed legacy inboxd SQLite mailbox was copied read-only from
  `atmos-inbox` with matching SHA-256, then imported into the operator's
  `default` HappyView mailbox space: 3 folders, 15 live messages, 3 expunged
  messages skipped, and 13,863 RFC 5322 bytes. Full readback and a fresh SQLite
  projection passed, and a second run created nothing while verifying the same
  15 messages.
- The resulting space is owned and authorized by the operator DID, has one
  member, uses `member-list` minting, and keeps both membership and records
  non-public. The tailnet UI uses a frontend-only OAuth client shim; HappyView
  itself remains bound to loopback.
- A separate owner-only shadow-agent token now fronts the exact default-space
  target through a loopback listener and private tailnet Serve path. Its live
  capability probe reports private records, referenced blobs, idempotent
  writes, authenticated read-after-write, and atomic state writes.
- A second short-lived agent created an isolated `shadow-validation` private
  space, wrote one synthetic message twice, and verified identical byte-exact
  receipts. It was then stopped. The test did not add synthetic mail to the
  operator's normal `default` mailbox.
- A fresh `comail-cert-20260816-source-v1` space passed the expanded
  mutable-authority
  certification: byte-exact readback, atomic message/state creation, stale-CID
  rejection, idempotent mutation retry, flagging, folder movement, atomic
  source-version replacement for edited draft/sent bytes, clean rebuild,
  tombstoning, and a second rebuild with no resurrection. Evidence is redacted
  under ignored owner-only state; the real `default` mailbox was not mutated by
  this test.
- A separate `comail-capture-validation-20260816-a` space then exercised the
  running certificate-gated `/v2/capture` adapter with two synthetic versions
  of one stable JMAP draft source. Authenticated inventory returned exactly one
  live edited version and one byte-free tombstone. The agent was stopped after
  the proof; the real `default` mailbox was not mutated.

## Remaining optional comparison artifact

The interactive PDS OAuth approval and legacy SQLite authority proof are
complete. A dedicated member-scoped Stalwart app-password is needed only to
archive and compare the current Stalwart/JMAP projection against the migrated
legacy mailbox.
It should be named for this export, exposed only to Vandelay as
`VANDELAY_PASSWORD`, and
revoked after the private archive is captured. The wrapper can load it from an
ignored owner-only `VANDELAY_PASSWORD_FILE`, keeping it out of chat and shell
history. The lab found no existing
credential in the local Keychain and cannot decrypt the production SOPS file;
it deliberately did not substitute a broad administrator secret.

If that comparison is desired, run `archive-stalwart.sh`, then
`dry-run-vandelay` and `prove-vandelay`. The resulting archive and proof remain
under ignored, mode-0700 `state/`; the source archive is retained as rollback.

## Why production eventually changes

Production changes only after the operator proof is green. They are needed to:

1. bind a gated account to a provider epoch and exact mailbox space;
2. provision the adapter service-DID write membership at login and verify its
   exact resolved `write` access on every adapter operation, without retaining
   the browser OAuth session in the adapter;
3. make the PDS space authoritative while Stalwart becomes a rebuildable JMAP,
   IMAP, and SMTP projection;
4. add fencing, retry spool, monitoring, revocation, deletion, and rollback;
5. keep every path dormant behind the existing signup/account flags until the
   provider and recovery drills pass.

Those changes belong in small reviewed Comail PRs later. None are part of this
lab branch.
