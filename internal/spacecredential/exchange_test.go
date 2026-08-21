package spacecredential

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-space-host/internal/repository"
)

const (
	testSpaceDID = "did:plc:rfwhywgeym2ek7ioeyxkvsn6"
	testSpaceURI = "at://did:plc:rfwhywgeym2ek7ioeyxkvsn6/space/email.atmos.mailbox/primary"
)

var testNow = time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

func TestAcquireUsesFreshBoundKeyAndCredentialUseDPoP(t *testing.T) {
	issuerKey, err := atcrypto.GeneratePrivateKeyP256()
	if err != nil {
		t.Fatal(err)
	}
	issuerPublic, err := issuerKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	resolver := &staticSigningResolver{did: testSpaceDID, kid: "#atproto", key: issuerPublic}
	delegations := &fakeDelegationSource{tokens: []string{"delegation-one", "delegation-two"}}
	var server *httptest.Server
	var exchangeJKT []string
	var issuedCredential string
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/xrpc/com.atproto.space.getSpaceCredential":
			if request.Method != http.MethodPost || request.URL.RawQuery != "" {
				t.Errorf("exchange target = %s %s", request.Method, request.URL.String())
			}
			wantAuthorization := "Bearer delegation-" + []string{"one", "two"}[len(exchangeJKT)]
			if request.Header.Get("Authorization") != wantAuthorization {
				t.Errorf("authorization = %q", request.Header.Get("Authorization"))
			}
			body, _ := io.ReadAll(request.Body)
			if string(body) != `{"space":"`+testSpaceURI+`"}` {
				t.Errorf("exchange body = %s", body)
			}
			proofHeader, proofClaims := decodeTestJWT(t, request.Header.Get("DPoP"))
			if proofHeader.Typ != "dpop+jwt" || proofHeader.Alg != "ES256" || proofClaims.HTM != http.MethodPost || proofClaims.HTU != server.URL+request.URL.Path || proofClaims.ATH != "" {
				t.Errorf("exchange DPoP = %#v %#v", proofHeader, proofClaims)
			}
			jkt := testJWKThumbprint(t, proofHeader.JWK)
			exchangeJKT = append(exchangeJKT, jkt)
			issuedCredential = signTestCredential(t, issuerKey, credentialClaims{
				Issuer: testSpaceDID, Subject: testSpaceURI,
				Confirmation: confirmationClaim{JKT: jkt},
				IssuedAt:     testNow.Unix(), ExpiresAt: testNow.Add(2 * time.Hour).Unix(),
				JWTID: "0123456789abcdef0123456789abcdef",
			})
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{"credential": issuedCredential})
		case "/xrpc/com.atproto.space.listRecords":
			if request.Header.Get("Authorization") != "DPoP "+issuedCredential {
				t.Error("credential request omitted exact authorization")
			}
			proofHeader, proofClaims := decodeTestJWT(t, request.Header.Get("DPoP"))
			credentialHash := sha256.Sum256([]byte(issuedCredential))
			wantATH := base64.RawURLEncoding.EncodeToString(credentialHash[:])
			if proofHeader.Typ != "dpop+jwt" || proofClaims.HTM != http.MethodGet || proofClaims.HTU != server.URL+request.URL.Path || proofClaims.ATH != wantATH {
				t.Errorf("credential DPoP = %#v %#v", proofHeader, proofClaims)
			}
			if testJWKThumbprint(t, proofHeader.JWK) != exchangeJKT[len(exchangeJKT)-1] {
				t.Error("credential proof key changed after exchange")
			}
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request path %q", request.URL.Path)
			http.NotFound(w, request)
		}
	}))
	defer server.Close()
	resolver.origin = server.URL

	exchanger, err := New(Config{
		SpaceURI: testSpaceURI, SpaceHostOrigin: server.URL, SigningKeys: resolver,
		AllowHTTP: true, AppAccess: AppAccessOpen, Now: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := exchanger.Acquire(context.Background(), delegations)
	if err != nil {
		t.Fatal(err)
	}
	if first.ExpiresAt() != testNow.Add(2*time.Hour) || first.NeedsRenewal(testNow) {
		t.Fatalf("unexpected credential lifetime: %s", first.ExpiresAt())
	}
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/xrpc/com.atproto.space.listRecords?space=ignored-by-htu", nil)
	response, err := first.Do(context.Background(), request, "com.atproto.space.listRecords")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("credential status = %d", response.StatusCode)
	}
	first.Close()
	if _, err := first.Do(context.Background(), request, "com.atproto.space.listRecords"); !errors.Is(err, ErrCredentialClosed) {
		t.Fatalf("closed credential error = %v", err)
	}

	second, err := exchanger.Acquire(context.Background(), delegations)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if delegations.calls != 2 || len(exchangeJKT) != 2 || exchangeJKT[0] == exchangeJKT[1] {
		t.Fatalf("delegations=%d exchange keys=%v", delegations.calls, exchangeJKT)
	}
}

func TestFailedExchangeRequiresNewDelegationAndKey(t *testing.T) {
	issuerKey, _ := atcrypto.GeneratePrivateKeyP256()
	issuerPublic, _ := issuerKey.PublicKey()
	delegations := &fakeDelegationSource{tokens: []string{"first-token", "second-token"}}
	var attempts int
	var jkts []string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		attempts++
		header, _ := decodeTestJWT(t, request.Header.Get("DPoP"))
		jkts = append(jkts, testJWKThumbprint(t, header.JWK))
		if attempts == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"InvalidDelegationToken","message":"do-not-leak"}`))
			return
		}
		credential := signTestCredential(t, issuerKey, credentialClaims{
			Issuer: testSpaceDID, Subject: testSpaceURI,
			Confirmation: confirmationClaim{JKT: jkts[len(jkts)-1]},
			IssuedAt:     testNow.Unix(), ExpiresAt: testNow.Add(time.Hour).Unix(),
			JWTID: "0123456789abcdef0123456789abcdef",
		})
		_ = json.NewEncoder(w).Encode(map[string]string{"credential": credential})
	}))
	defer server.Close()
	exchanger, err := New(Config{
		SpaceURI: testSpaceURI, SpaceHostOrigin: server.URL,
		SigningKeys: &staticSigningResolver{did: testSpaceDID, kid: "#atproto", key: issuerPublic, origin: server.URL},
		AllowHTTP:   true, AppAccess: AppAccessOpen, Now: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exchanger.Acquire(context.Background(), delegations); err == nil || strings.Contains(err.Error(), "do-not-leak") {
		t.Fatalf("first exchange error = %v", err)
	}
	credential, err := exchanger.Acquire(context.Background(), delegations)
	if err != nil {
		t.Fatal(err)
	}
	defer credential.Close()
	if delegations.calls != 2 || attempts != 2 || jkts[0] == jkts[1] {
		t.Fatalf("delegations=%d attempts=%d keys=%v", delegations.calls, attempts, jkts)
	}
}

func TestAcquireMintsExchangeProofAfterDelegation(t *testing.T) {
	issuerKey, _ := atcrypto.GeneratePrivateKeyP256()
	issuerPublic, _ := issuerKey.PublicKey()
	now := testNow
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		header, claims := decodeTestJWT(t, request.Header.Get("DPoP"))
		if claims.IssuedAt != now.Unix() {
			t.Errorf("proof iat = %d, want %d", claims.IssuedAt, now.Unix())
		}
		credential := signTestCredential(t, issuerKey, credentialClaims{
			Issuer: testSpaceDID, Subject: testSpaceURI,
			Confirmation: confirmationClaim{JKT: testJWKThumbprint(t, header.JWK)},
			IssuedAt:     now.Unix(), ExpiresAt: now.Add(time.Hour).Unix(),
			JWTID: "0123456789abcdef0123456789abcdef",
		})
		_ = json.NewEncoder(w).Encode(map[string]string{"credential": credential})
	}))
	defer server.Close()
	source := &fakeDelegationSource{
		tokens: []string{"synthetic-delegation"},
		before: func() { now = now.Add(30 * time.Second) },
	}
	exchanger, err := New(Config{
		SpaceURI: testSpaceURI, SpaceHostOrigin: server.URL,
		SigningKeys: &staticSigningResolver{did: testSpaceDID, kid: "#atproto", key: issuerPublic, origin: server.URL},
		AllowHTTP:   true, AppAccess: AppAccessOpen, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := exchanger.Acquire(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	credential.Close()
}

func TestAcquireRejectsUnsafeResponsesWithoutLeakingBody(t *testing.T) {
	issuerKey, _ := atcrypto.GeneratePrivateKeyP256()
	issuerPublic, _ := issuerKey.PublicKey()
	tests := []struct {
		name   string
		status int
		body   string
		header http.Header
	}{
		{name: "non success", status: http.StatusUnauthorized, body: `{"error":"InvalidToken","message":"SECRET-UPSTREAM-TEXT"}`},
		{name: "missing credential", status: http.StatusOK, body: `{}`},
		{name: "unknown field", status: http.StatusOK, body: `{"credential":"a.b.c","extra":true}`},
		{name: "trailing object", status: http.StatusOK, body: `{"credential":"a.b.c"}{}`},
		{name: "oversized", status: http.StatusOK, body: strings.Repeat("x", maxCredentialResponseBytes+1)},
		{name: "redirect", status: http.StatusFound, header: http.Header{"Location": []string{"https://example.com/escape"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for name, values := range test.header {
					for _, value := range values {
						w.Header().Add(name, value)
					}
				}
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			source := &fakeDelegationSource{tokens: []string{"synthetic-delegation"}}
			exchanger, err := New(Config{
				SpaceURI: testSpaceURI, SpaceHostOrigin: server.URL,
				SigningKeys: &staticSigningResolver{did: testSpaceDID, kid: "#atproto", key: issuerPublic, origin: server.URL},
				AllowHTTP:   true, AppAccess: AppAccessOpen, Now: func() time.Time { return testNow },
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := exchanger.Acquire(context.Background(), source); err == nil {
				t.Fatal("expected unsafe response rejection")
			} else if strings.Contains(err.Error(), "SECRET-UPSTREAM-TEXT") || (test.body != "" && strings.Contains(err.Error(), test.body)) {
				t.Fatalf("error leaked upstream body: %v", err)
			}
			if source.calls != 1 {
				t.Fatalf("delegation uses = %d", source.calls)
			}
		})
	}
}

func TestAcquireRejectsResolvedHostMismatchBeforeMintingDelegation(t *testing.T) {
	issuerKey, _ := atcrypto.GeneratePrivateKeyP256()
	issuerPublic, _ := issuerKey.PublicKey()
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	source := &fakeDelegationSource{tokens: []string{"must-not-be-used"}}
	exchanger, err := New(Config{
		SpaceURI: testSpaceURI, SpaceHostOrigin: server.URL,
		SigningKeys: &staticSigningResolver{did: testSpaceDID, kid: "#atproto", key: issuerPublic, origin: "https://different.example"},
		AllowHTTP:   true, AppAccess: AppAccessOpen, Now: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exchanger.Acquire(context.Background(), source); err == nil {
		t.Fatal("expected resolved host mismatch")
	}
	if source.calls != 0 {
		t.Fatalf("delegation minted before host verification: %d", source.calls)
	}
}

func TestAcquireRevalidatesCachedSpaceHostBeforeMintingDelegation(t *testing.T) {
	issuerKey, _ := atcrypto.GeneratePrivateKeyP256()
	issuerPublic, _ := issuerKey.PublicKey()
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	source := &fakeDelegationSource{tokens: []string{"must-not-be-used"}}
	resolver := &rotatedHostResolver{did: testSpaceDID, cached: server.URL, fresh: "https://rotated.example", key: issuerPublic}
	exchanger, err := New(Config{
		SpaceURI: testSpaceURI, SpaceHostOrigin: server.URL, SigningKeys: resolver,
		AllowHTTP: true, AppAccess: AppAccessOpen, Now: func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exchanger.Acquire(context.Background(), source); err == nil {
		t.Fatal("expected freshly resolved host mismatch")
	}
	if resolver.force != 1 || source.calls != 0 {
		t.Fatalf("forced refreshes=%d delegation uses=%d", resolver.force, source.calls)
	}
}

func TestSameOriginRejectsAmbiguousTargets(t *testing.T) {
	origin := "https://spaces.example"
	tests := []string{
		"https://user@spaces.example/xrpc/test",
		"https://spaces.example:444/xrpc/test",
		"http://spaces.example/xrpc/test",
	}
	for _, raw := range tests {
		target, err := url.Parse(raw)
		if err != nil {
			t.Fatal(err)
		}
		if sameOrigin(target, origin) {
			t.Errorf("accepted ambiguous target %q", raw)
		}
	}
}

func TestCredentialDoRejectsEndpointDrift(t *testing.T) {
	credential := &Credential{origin: "https://spaces.example"}
	request, err := http.NewRequest(http.MethodGet, "https://spaces.example/xrpc/com.atproto.space.listRecords", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := credential.Do(context.Background(), request, "com.atproto.space.getRecord"); !errors.Is(err, repository.ErrTarget) {
		t.Fatalf("endpoint drift error = %v", err)
	}
	request.Host = "foreign.example"
	if _, err := credential.Do(context.Background(), request, "com.atproto.space.listRecords"); !errors.Is(err, repository.ErrTarget) {
		t.Fatalf("host override error = %v", err)
	}
}

func TestNewRequiresExplicitOpenAppProfile(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	_, err := New(Config{
		SpaceURI: testSpaceURI, SpaceHostOrigin: server.URL,
		SigningKeys: &staticSigningResolver{did: testSpaceDID, origin: server.URL},
		AllowHTTP:   true,
	})
	if err == nil {
		t.Fatal("missing open-app admission profile was accepted")
	}
}

func TestResolvedOriginComparisonCanonicalizesEquivalentHTTPSOrigins(t *testing.T) {
	if !exactResolvedOrigin("HTTPS://SPACES.EXAMPLE:443/", "https://spaces.example") {
		t.Fatal("equivalent canonical HTTPS origin was rejected")
	}
}

var _ interface {
	Do(context.Context, *http.Request, string) (*http.Response, error)
} = (*Credential)(nil)

type fakeDelegationSource struct {
	tokens []string
	calls  int
	before func()
}

func (s *fakeDelegationSource) WithDelegation(_ context.Context, exchange func(string) error) error {
	if s.calls >= len(s.tokens) {
		return errors.New("no synthetic delegation remaining")
	}
	token := s.tokens[s.calls]
	s.calls++
	if s.before != nil {
		s.before()
	}
	return exchange(token)
}

type staticSigningResolver struct {
	did    string
	kid    string
	key    atcrypto.PublicKey
	origin string
	force  int
}

type rotatedHostResolver struct {
	did    string
	cached string
	fresh  string
	key    atcrypto.PublicKey
	force  int
}

func (r *rotatedHostResolver) ResolveSpaceHost(_ context.Context, did syntax.DID, force bool) (string, error) {
	if did.String() != r.did {
		return "", errors.New("unexpected space-host target")
	}
	if force {
		r.force++
		return r.fresh, nil
	}
	return r.cached, nil
}

func (r *rotatedHostResolver) ResolveCredentialKey(_ context.Context, did syntax.DID, _ string, _ bool) (atcrypto.PublicKey, error) {
	if did.String() != r.did {
		return nil, errors.New("unexpected signing-key target")
	}
	return r.key, nil
}

func (r *staticSigningResolver) ResolveSpaceHost(_ context.Context, did syntax.DID, forceRefresh bool) (string, error) {
	if did.String() != r.did || r.origin == "" {
		return "", errors.New("unexpected space-host target")
	}
	if forceRefresh {
		r.force++
	}
	return r.origin, nil
}

func (r *staticSigningResolver) ResolveCredentialKey(_ context.Context, did syntax.DID, kid string, forceRefresh bool) (atcrypto.PublicKey, error) {
	if did.String() != r.did || kid != r.kid {
		return nil, errors.New("unexpected signing-key target")
	}
	if forceRefresh {
		r.force++
	}
	return r.key, nil
}

type testProofHeader struct {
	Alg string    `json:"alg"`
	Typ string    `json:"typ"`
	JWK publicJWK `json:"jwk"`
}

type testProofClaims struct {
	JWTID    string `json:"jti"`
	HTM      string `json:"htm"`
	HTU      string `json:"htu"`
	ATH      string `json:"ath,omitempty"`
	IssuedAt int64  `json:"iat"`
}

func decodeTestJWT(t *testing.T, token string) (testProofHeader, testProofClaims) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT parts = %d", len(parts))
	}
	var header testProofHeader
	var claims testProofClaims
	decode := func(part string, output any) {
		data, err := base64.RawURLEncoding.DecodeString(part)
		if err != nil || json.Unmarshal(data, output) != nil {
			t.Fatal("invalid synthetic JWT")
		}
	}
	decode(parts[0], &header)
	decode(parts[1], &claims)
	return header, claims
}

func testJWKThumbprint(t *testing.T, jwk publicJWK) string {
	t.Helper()
	thumbprint, err := jwkThumbprint(jwk)
	if err != nil {
		t.Fatal(err)
	}
	return thumbprint
}

func signTestCredential(t *testing.T, key atcrypto.PrivateKey, claims credentialClaims) string {
	t.Helper()
	header := credentialHeader{Algorithm: "ES256", Type: credentialTokenType, KeyID: "#atproto"}
	token, err := signCompactJWT(key, header, claims)
	if err != nil {
		t.Fatal(err)
	}
	return token
}
