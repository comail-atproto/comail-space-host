# Operator mailbox readiness

Observed 2026-08-16; no production state was changed.

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

## Remaining operator artifact

The remaining private actions are one interactive PDS OAuth approval and a
dedicated member-scoped Stalwart app-password.
It should be named for this export, exposed only to Vandelay as
`VANDELAY_PASSWORD`, and
revoked after the private archive is captured. The wrapper can load it from an
ignored owner-only `VANDELAY_PASSWORD_FILE`, keeping it out of chat and shell
history. The lab found no existing
credential in the local Keychain and cannot decrypt the production SOPS file;
it deliberately did not substitute a broad administrator secret.

Once that one-time credential is available, run `archive-stalwart.sh`, then
`dry-run-vandelay` and `prove-vandelay`. The resulting archive and proof remain
under ignored, mode-0700 `state/`; the source archive is retained as rollback.

## Why production eventually changes

Production changes only after the operator proof is green. They are needed to:

1. bind a gated account to a provider epoch and exact mailbox space;
2. request and retain the permissioned-space OAuth grant at login;
3. make the PDS space authoritative while Stalwart becomes a rebuildable JMAP,
   IMAP, and SMTP projection;
4. add fencing, retry spool, monitoring, revocation, deletion, and rollback;
5. keep every path dormant behind the existing signup/account flags until the
   provider and recovery drills pass.

Those changes belong in small reviewed Comail PRs later. None are part of this
lab branch.
