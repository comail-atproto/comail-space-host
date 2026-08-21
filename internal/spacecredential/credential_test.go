package spacecredential

import (
	"context"
	"crypto/elliptic"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

func TestValidateCredentialAcceptsExactP256AndK256Signatures(t *testing.T) {
	for _, algorithm := range []string{"ES256", "ES256K"} {
		t.Run(algorithm, func(t *testing.T) {
			var key atcrypto.PrivateKey
			var err error
			if algorithm == "ES256" {
				key, err = atcrypto.GeneratePrivateKeyP256()
			} else {
				key, err = atcrypto.GeneratePrivateKeyK256()
			}
			if err != nil {
				t.Fatal(err)
			}
			public, _ := key.PublicKey()
			claims := exactTestClaims()
			token := signCredentialWith(t, key, credentialHeader{Algorithm: algorithm, Type: credentialTokenType, KeyID: "#atproto"}, claims)
			resolver := &staticSigningResolver{did: testSpaceDID, kid: "#atproto", key: public}
			got, err := validateCredential(context.Background(), token, testSpaceDID, testSpaceURI, claims.Confirmation.JKT, resolver, testNow)
			if err != nil {
				t.Fatal(err)
			}
			if got.ExpiresAt != claims.ExpiresAt || resolver.force != 0 {
				t.Fatalf("claims = %#v, forced refreshes = %d", got, resolver.force)
			}
		})
	}
}

func TestValidateCredentialRejectsTargetLifetimeAndHeaderDrift(t *testing.T) {
	key, _ := atcrypto.GeneratePrivateKeyP256()
	public, _ := key.PublicKey()
	baseHeader := credentialHeader{Algorithm: "ES256", Type: credentialTokenType, KeyID: "#atproto"}
	baseClaims := exactTestClaims()
	tests := []struct {
		name   string
		header credentialHeader
		claims credentialClaims
	}{
		{name: "wrong type", header: credentialHeader{Algorithm: "ES256", Type: "JWT", KeyID: "#atproto"}, claims: baseClaims},
		{name: "wrong algorithm", header: credentialHeader{Algorithm: "ES256K", Type: credentialTokenType, KeyID: "#atproto"}, claims: baseClaims},
		{name: "noncanonical kid", header: credentialHeader{Algorithm: "ES256", Type: credentialTokenType, KeyID: "atproto"}, claims: baseClaims},
		{name: "unknown kid", header: credentialHeader{Algorithm: "ES256", Type: credentialTokenType, KeyID: "#other"}, claims: baseClaims},
		{name: "wrong issuer", header: baseHeader, claims: withClaims(baseClaims, func(c *credentialClaims) { c.Issuer = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa" })},
		{name: "wrong subject", header: baseHeader, claims: withClaims(baseClaims, func(c *credentialClaims) { c.Subject += "-other" })},
		{name: "audience", header: baseHeader, claims: withClaims(baseClaims, func(c *credentialClaims) { c.Audience = json.RawMessage(`"unexpected"`) })},
		{name: "wrong thumbprint", header: baseHeader, claims: withClaims(baseClaims, func(c *credentialClaims) { c.Confirmation.JKT = strings.Repeat("x", 43) })},
		{name: "missing jti", header: baseHeader, claims: withClaims(baseClaims, func(c *credentialClaims) { c.JWTID = "" })},
		{name: "future issued", header: baseHeader, claims: withClaims(baseClaims, func(c *credentialClaims) {
			c.IssuedAt = testNow.Add(6 * time.Second).Unix()
			c.ExpiresAt = c.IssuedAt + 3600
		})},
		{name: "expired", header: baseHeader, claims: withClaims(baseClaims, func(c *credentialClaims) {
			c.IssuedAt = testNow.Add(-time.Hour).Unix()
			c.ExpiresAt = testNow.Add(-6 * time.Second).Unix()
		})},
		{name: "reversed lifetime", header: baseHeader, claims: withClaims(baseClaims, func(c *credentialClaims) { c.ExpiresAt = c.IssuedAt })},
		{name: "overlong lifetime", header: baseHeader, claims: withClaims(baseClaims, func(c *credentialClaims) { c.ExpiresAt = c.IssuedAt + 7201 })},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := signCredentialWith(t, key, test.header, test.claims)
			resolver := &staticSigningResolver{did: testSpaceDID, kid: "#atproto", key: public}
			if _, err := validateCredential(context.Background(), token, testSpaceDID, testSpaceURI, baseClaims.Confirmation.JKT, resolver, testNow); err == nil {
				t.Fatal("expected credential rejection")
			}
		})
	}
}

func TestValidateCredentialRejectsUnknownClaimsAndHighSSignature(t *testing.T) {
	key, _ := atcrypto.GeneratePrivateKeyP256()
	public, _ := key.PublicKey()
	resolver := &staticSigningResolver{did: testSpaceDID, kid: "#atproto", key: public}
	header := credentialHeader{Algorithm: "ES256", Type: credentialTokenType, KeyID: "#atproto"}
	claims := exactTestClaims()

	unknownClaims := map[string]any{
		"iss": claims.Issuer, "sub": claims.Subject, "iat": claims.IssuedAt,
		"exp": claims.ExpiresAt, "jti": claims.JWTID, "cnf": claims.Confirmation,
		"unexpected": true,
	}
	unknownToken, err := signCompactJWT(key, header, unknownClaims)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateCredential(context.Background(), unknownToken, testSpaceDID, testSpaceURI, claims.Confirmation.JKT, resolver, testNow); err == nil {
		t.Fatal("unknown credential claim was accepted")
	}

	lowToken := signCredentialWith(t, key, header, claims)
	parts := strings.Split(lowToken, ".")
	signature, _ := base64.RawURLEncoding.DecodeString(parts[2])
	s := new(big.Int).SetBytes(signature[32:])
	highS := new(big.Int).Sub(elliptic.P256().Params().N, s)
	highS.FillBytes(signature[32:])
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	if _, err := validateCredential(context.Background(), strings.Join(parts, "."), testSpaceDID, testSpaceURI, claims.Confirmation.JKT, resolver, testNow); err == nil {
		t.Fatal("high-S credential signature was accepted")
	}
}

func TestValidateCredentialRetriesOnlyWithChangedRotatedKey(t *testing.T) {
	oldKey, _ := atcrypto.GeneratePrivateKeyP256()
	newKey, _ := atcrypto.GeneratePrivateKeyP256()
	oldPublic, _ := oldKey.PublicKey()
	newPublic, _ := newKey.PublicKey()
	claims := exactTestClaims()
	token := signCredentialWith(t, newKey, credentialHeader{Algorithm: "ES256", Type: credentialTokenType, KeyID: "#atproto"}, claims)
	resolver := &rotatingSigningResolver{did: testSpaceDID, kid: "#atproto", old: oldPublic, fresh: newPublic}
	if _, err := validateCredential(context.Background(), token, testSpaceDID, testSpaceURI, claims.Confirmation.JKT, resolver, testNow); err != nil {
		t.Fatal(err)
	}
	if resolver.force != 1 {
		t.Fatalf("forced refreshes = %d", resolver.force)
	}
}

func exactTestClaims() credentialClaims {
	return credentialClaims{
		Issuer: testSpaceDID, Subject: testSpaceURI,
		Confirmation: confirmationClaim{JKT: "nJ6rN1JbM-dummy-thumbprint-value-123456789"},
		IssuedAt:     testNow.Unix(), ExpiresAt: testNow.Add(2 * time.Hour).Unix(),
		JWTID: "0123456789abcdef0123456789abcdef",
	}
}

func withClaims(base credentialClaims, change func(*credentialClaims)) credentialClaims {
	change(&base)
	return base
}

func signCredentialWith(t *testing.T, key atcrypto.PrivateKey, header credentialHeader, claims any) string {
	t.Helper()
	token, err := signCompactJWT(key, header, claims)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

type rotatingSigningResolver struct {
	did   string
	kid   string
	old   atcrypto.PublicKey
	fresh atcrypto.PublicKey
	force int
}

func (r *rotatingSigningResolver) ResolveSpaceHost(_ context.Context, did syntax.DID, _ bool) (string, error) {
	if did.String() != r.did {
		return "", errors.New("unexpected target")
	}
	return "https://spaces.example", nil
}

func (r *rotatingSigningResolver) ResolveCredentialKey(_ context.Context, did syntax.DID, kid string, force bool) (atcrypto.PublicKey, error) {
	if did.String() != r.did || kid != r.kid {
		return nil, errors.New("unexpected target")
	}
	if force {
		r.force++
		return r.fresh, nil
	}
	return r.old, nil
}
