// Package spacecredential implements Comail's fail-closed personal-mailbox
// profile of the pinned AT Protocol Spaces alpha credential flow.
//
// This first profile is intentionally narrower than the general protocol:
// the mailbox authority PDS is also the sole record-repository host, and the
// space must use com.atproto.simplespace.defs#open app access. Cross-PDS member
// repositories and #allowList client attestations are rejected until they have
// separate resolution, pinning, redaction, and conformance evidence.
//
// Credential parsing also requires the exact canonical shape emitted by the
// pinned alpha: no extension claims, a 32-character lowercase-hex jti, no aud,
// and a lifetime no longer than the alpha issuer's two-hour default. These are
// Comail safety invariants, not claims about the upstream verifier's minimums.
// If an authority publishes #atproto_space, this profile also rejects fallback
// credential signatures under its general #atproto key.
package spacecredential
