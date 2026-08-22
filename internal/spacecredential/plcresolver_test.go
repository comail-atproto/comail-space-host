package spacecredential

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

func TestPLCResolverPinsDIDKeyHostAndForceRefresh(t *testing.T) {
	first, _ := atcrypto.GeneratePrivateKeyP256()
	second, _ := atcrypto.GeneratePrivateKeyP256()
	firstPublic, _ := first.PublicKey()
	secondPublic, _ := second.PublicKey()
	current := firstPublic
	requests := 0
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path != "/"+testSpaceDID {
			t.Errorf("PLC path = %q", request.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(testDIDDocument(testSpaceDID, current.Multibase(), server.URL, ""))
	}))
	defer server.Close()
	resolver, err := NewPLCSigningKeyResolver(server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	did := syntax.DID(testSpaceDID)
	key, err := resolver.ResolveCredentialKey(context.Background(), did, "#atproto", false)
	if err != nil || !key.Equal(firstPublic) {
		t.Fatalf("initial key = %v, error = %v", key, err)
	}
	host, err := resolver.ResolveSpaceHost(context.Background(), did, false)
	if err != nil || host != server.URL || requests != 1 {
		t.Fatalf("host=%q requests=%d error=%v", host, requests, err)
	}
	current = secondPublic
	key, err = resolver.ResolveCredentialKey(context.Background(), did, "#atproto", true)
	if err != nil || !key.Equal(secondPublic) || requests != 2 {
		t.Fatalf("rotated key=%v requests=%d error=%v", key, requests, err)
	}
}

func TestPLCResolverRejectsMismatchOversizeRedirectAndKeyDowngrade(t *testing.T) {
	key, _ := atcrypto.GeneratePrivateKeyP256()
	public, _ := key.PublicKey()
	tests := []struct {
		name    string
		handler http.HandlerFunc
		check   func(*PLCSigningKeyResolver) error
	}{
		{
			name: "wrong document DID",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(testDIDDocument("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", public.Multibase(), "https://spaces.example", ""))
			},
			check: func(r *PLCSigningKeyResolver) error {
				_, err := r.ResolveSpaceHost(context.Background(), syntax.DID(testSpaceDID), false)
				return err
			},
		},
		{
			name: "oversized",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(strings.Repeat("x", maxDIDDocumentBytes+1)))
			},
			check: func(r *PLCSigningKeyResolver) error {
				_, err := r.ResolveSpaceHost(context.Background(), syntax.DID(testSpaceDID), false)
				return err
			},
		},
		{
			name: "redirect",
			handler: func(w http.ResponseWriter, request *http.Request) {
				http.Redirect(w, request, "https://example.com/escape", http.StatusFound)
			},
			check: func(r *PLCSigningKeyResolver) error {
				_, err := r.ResolveSpaceHost(context.Background(), syntax.DID(testSpaceDID), false)
				return err
			},
		},
		{
			name: "dedicated key downgrade",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(testDIDDocument(testSpaceDID, public.Multibase(), "https://spaces.example", public.Multibase()))
			},
			check: func(r *PLCSigningKeyResolver) error {
				_, err := r.ResolveCredentialKey(context.Background(), syntax.DID(testSpaceDID), "#atproto", false)
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(test.handler)
			defer server.Close()
			resolver, err := NewPLCSigningKeyResolver(server.URL, true)
			if err != nil {
				t.Fatal(err)
			}
			if err := test.check(resolver); err == nil {
				t.Fatal("expected resolver rejection")
			}
		})
	}
}

func TestPLCResolverUsesGeneralAtprotoKeyForRepoCommit(t *testing.T) {
	general, _ := atcrypto.GeneratePrivateKeyP256()
	dedicated, _ := atcrypto.GeneratePrivateKeyP256()
	generalPublic, _ := general.PublicKey()
	dedicatedPublic, _ := dedicated.PublicKey()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(testDIDDocument(
			testSpaceDID, generalPublic.Multibase(), "https://spaces.example", dedicatedPublic.Multibase(),
		))
	}))
	defer server.Close()
	resolver, err := NewPLCSigningKeyResolver(server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	host, key, err := resolver.ResolveRepoSource(context.Background(), syntax.DID(testSpaceDID), false)
	if err != nil || host != "https://spaces.example" || !key.Equal(generalPublic) {
		t.Fatalf("repo host=%q key=%v error=%v", host, key, err)
	}
	if _, err := resolver.ResolveCredentialKey(context.Background(), syntax.DID(testSpaceDID), "#atproto", false); err == nil {
		t.Fatal("credential downgrade guard must remain distinct from repo signing-key lookup")
	}
}

func testDIDDocument(did, atprotoKey, pds, spaceKey string) map[string]any {
	methods := []map[string]string{{
		"id": did + "#atproto", "type": "Multikey", "controller": did,
		"publicKeyMultibase": atprotoKey,
	}}
	if spaceKey != "" {
		methods = append(methods, map[string]string{
			"id": did + "#atproto_space", "type": "Multikey", "controller": did,
			"publicKeyMultibase": spaceKey,
		})
	}
	return map[string]any{
		"id": did, "verificationMethod": methods,
		"service": []map[string]string{{
			"id": "#atproto_pds", "type": "AtprotoPersonalDataServer", "serviceEndpoint": pds,
		}},
	}
}
