# Comail PDS Lab

This repository is an isolated, non-production laboratory. It must not import
runtime configuration from, deploy into, or modify any Comail production
repository or service.

Safety invariants:

- Never open a live mailbox SQLite database for migration. Accept only an
  explicit, consistent snapshot path supplied by the operator.
- Never log or serialize OAuth tokens, DPoP private keys, RFC 5322 bytes,
  subjects, senders, recipients, or message bodies into evidence.
- All provider targets are exact: PDS origin, account DID, space URI, and repo
  DID must agree. Refuse redirects on authenticated requests.
- The default command mode is dry-run. A live write requires both an explicit
  provider and `--commit`.
- Tests use synthetic identities and messages only.
- Production promotion is out of scope. Results from this repository are input
  to a later Comail feature-branch review.

Use test-first changes, `gofmt`, `go test ./...`, and `go vet ./...`.
