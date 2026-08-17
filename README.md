# Comail Space Host

Separately deployable permissioned mailbox storage for Comail. A gated mailbox
uses one private AT Protocol space as its canonical mail authority while
Stalwart remains the disposable JMAP/IMAP/SMTP projection used by the complete
Comail Inbox UI and ordinary mail clients.

This repository was promoted from the isolated `comail-pds-lab` proof. The lab
remains independent and cannot deploy this service or Comail production.

## Production boundary

`comail-space-host` sits between the relay and a certified permissioned-space
provider such as HappyView:

```text
Comail relay -- separate bearer --> comail-space-host
                                      |
                                      +-- 60-second ES256 service-auth JWT
                                      +-- exact configured DID + private space
                                      +-- HappyView permissioned records
```

- The adapter never stores browser cookies or user OAuth tokens.
- Its public `did:web` document contains only the service signing public key.
- The adapter service DID must be granted write membership in each user-owned
  mailbox space. Request input can select only a preconfigured target.
- HappyView, the adapter, and their SQLite state run separately from the relay.
- Permissioned data is access-controlled plaintext, not end-to-end encryption.
- Contacts, calendars, files, filters, vacation replies, and native-client
  access remain Stalwart/Comail projection features; changing mail authority
  does not remove them.

## Service configuration

The binary accepts only an absolute JSON config path and binds exact IPv4
loopback. TLS termination and the public adapter/service-DID route belong to
the deployment layer.

```json
{
  "listen": "127.0.0.1:39094",
  "providerOrigin": "https://spaces.inbox.comail.at",
  "serviceIssuerDid": "did:web:mailbox-adapter.comail.at",
  "serviceAudience": "did:web:spaces.inbox.comail.at#mailbox",
  "serviceKeyFile": "/run/credentials/comail-space-host/service-key.pem",
  "relayTokenFile": "/run/credentials/comail-space-host/relay-token",
  "mailboxes": [
    {
      "did": "did:plc:example",
      "spaceKey": "default",
      "authorityCertificateSha256": "<64 lowercase hex>",
      "evidenceFile": "/run/credentials/comail-space-host/example-evidence.json"
    }
  ]
}
```

Each evidence file is the fully passing, owner-only authority certification
for the exact pinned HappyView epoch. Startup verifies the private space,
membership, collection allowlist, certificate digest, and every configured
target before opening the listener.

## Development

```bash
go test ./...
go vet ./...
go build ./cmd/comail-space-host
```

The historical synthetic proof, migrations, projection tests, lexicons, and
provider certifications are intentionally retained here as regression and
interoperability fixtures. Production deployment remains branch → review →
green CI → GitOps activation.
