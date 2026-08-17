# Comail Space Host

This is the separately deployable permissioned-mailbox provider for Comail. It
is production-capable code, but every deployment remains default-off and
limited to explicitly provisioned DIDs and spaces.

Safety invariants:

- Never persist browser cookies or user OAuth tokens in the adapter.
- Provider access uses short-lived AT Protocol service-auth JWTs and an exact
  service DID, audience fragment, provider origin, mailbox DID, and space URI.
- The relay-to-adapter bearer secret and adapter signing key are separate,
  owner-only credentials. Neither belongs in Git, Nix store paths, logs, or
  error responses.
- One process may serve multiple explicitly configured mailboxes, but request
  input can never select an unconfigured target.
- Authenticated HTTP requests never follow redirects. Production requires
  certificate-verified HTTPS; loopback HTTP exists only in tests.
- Deploy through a reviewed branch, green CI, and the Comail GitOps path.
- Tests use synthetic identities and message bytes only.

Use test-first changes, `gofmt`, `go test ./...`, and `go vet ./...`.
