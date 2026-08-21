package spacecredential

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
)

func TestDPoPProofMatchesOfficialExchangeAndCredentialShapes(t *testing.T) {
	key, err := atcrypto.GeneratePrivateKeyP256()
	if err != nil {
		t.Fatal(err)
	}
	exchange, err := newDPoPProof(key, "POST", "HTTPS://SPACES.EXAMPLE:443/xrpc/com.atproto.space.getSpaceCredential?ignored=yes#fragment", nil, testNow)
	if err != nil {
		t.Fatal(err)
	}
	credential := "header.payload.signature"
	use, err := newDPoPProof(key, "GET", "https://spaces.example/xrpc/com.atproto.space.listRecords?space=private", &credential, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if exchange == use {
		t.Fatal("DPoP proofs were reused")
	}

	exchangeHeader, exchangeClaims := parseAndVerifyDPoP(t, exchange)
	useHeader, useClaims := parseAndVerifyDPoP(t, use)
	if exchangeHeader.Type != dpopProofType || exchangeHeader.Algorithm != "ES256" || exchangeClaims.HTTPMethod != "POST" || exchangeClaims.TargetURI != "https://spaces.example/xrpc/com.atproto.space.getSpaceCredential" || exchangeClaims.TokenHash != "" {
		t.Fatalf("exchange proof = %#v %#v", exchangeHeader, exchangeClaims)
	}
	wantHash := sha256.Sum256([]byte(credential))
	if useClaims.HTTPMethod != "GET" || useClaims.TargetURI != "https://spaces.example/xrpc/com.atproto.space.listRecords" || useClaims.TokenHash != base64.RawURLEncoding.EncodeToString(wantHash[:]) {
		t.Fatalf("credential proof = %#v %#v", useHeader, useClaims)
	}
	if exchangeClaims.JWTID == useClaims.JWTID || exchangeHeader.JWK != useHeader.JWK {
		t.Fatal("proof identifier was reused or bound JWK changed")
	}
	if _, err := jwkThumbprint(exchangeHeader.JWK); err != nil {
		t.Fatal(err)
	}
}

func TestDPoPProofRejectsAmbiguousMethodOrTarget(t *testing.T) {
	key, _ := atcrypto.GeneratePrivateKeyP256()
	for _, test := range []struct {
		method string
		target string
	}{
		{method: "get", target: "https://spaces.example/xrpc/test"},
		{method: "GET", target: "/relative"},
		{method: "GET", target: "https://user@spaces.example/xrpc/test"},
	} {
		if _, err := newDPoPProof(key, test.method, test.target, nil, testNow); err == nil {
			t.Fatalf("accepted %q %q", test.method, test.target)
		}
	}
}

func parseAndVerifyDPoP(t *testing.T, token string) (dpopHeader, dpopClaims) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("proof parts = %d", len(parts))
	}
	decode := func(part string, output any) {
		data, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil || json.Unmarshal(data, output) != nil {
			t.Fatal("malformed DPoP JWT")
		}
	}
	var header dpopHeader
	var claims dpopClaims
	decode(parts[0], &header)
	decode(parts[1], &claims)
	public, err := atcrypto.ParsePublicJWK(atcrypto.JWK{
		KeyType: header.JWK.KeyType, Curve: header.JWK.Curve,
		X: header.JWK.X, Y: header.JWK.Y,
	})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || public.HashAndVerify([]byte(parts[0]+"."+parts[1]), signature) != nil {
		t.Fatal("invalid DPoP signature")
	}
	return header, claims
}
