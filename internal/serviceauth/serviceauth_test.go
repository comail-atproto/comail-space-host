package serviceauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDoMintsShortLivedEndpointBoundServiceJWT(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("token parts=%d", len(parts))
		}
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil || json.Unmarshal(payload, &claims) != nil {
			t.Fatalf("decode claims: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()
	signer, err := New(Config{
		IssuerDID: "did:web:adapter.example.test", Audience: "did:web:spaces.example.test#mailbox",
		Key: key, Origin: server.URL + "/spaces", HTTPClient: server.Client(), AllowLoopbackHTTP: true, Now: func() time.Time { return time.Unix(1_700_000_000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodPost, server.URL+"/spaces/xrpc/com.atproto.space.applyWrites", nil)
	resp, err := signer.Do(context.Background(), req, "com.atproto.space.applyWrites")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if claims["iss"] != "did:web:adapter.example.test" || claims["aud"] != "did:web:spaces.example.test#mailbox" || claims["lxm"] != "com.atproto.space.applyWrites" || claims["exp"] != float64(1_700_000_060) {
		t.Fatalf("claims=%#v", claims)
	}
	escaped, _ := http.NewRequest(http.MethodPost, server.URL+"/other/xrpc/com.atproto.space.applyWrites", nil)
	if _, err := signer.Do(context.Background(), escaped, "com.atproto.space.applyWrites"); err == nil {
		t.Fatal("signer accepted XRPC request outside pinned provider base path")
	}
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("request escaped pinned provider origin")
	}))
	defer other.Close()
	wrongOrigin, _ := http.NewRequest(http.MethodPost, other.URL+"/spaces/xrpc/com.atproto.space.applyWrites", nil)
	if _, err := signer.Do(context.Background(), wrongOrigin, "com.atproto.space.applyWrites"); err == nil {
		t.Fatal("signer accepted XRPC request on a different origin")
	}
}

func TestDIDDocumentPublishesExactP256AtprotoKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, err := New(Config{IssuerDID: "did:web:adapter.example.test", Audience: "did:web:spaces.example.test#mailbox", Key: key})
	if err != nil {
		t.Fatal(err)
	}
	doc := signer.DIDDocument()
	if doc.ID != "did:web:adapter.example.test" || len(doc.VerificationMethod) != 1 || doc.VerificationMethod[0].ID != "did:web:adapter.example.test#atproto" || !strings.HasPrefix(doc.VerificationMethod[0].PublicKeyMultibase, "z") {
		t.Fatalf("doc=%#v", doc)
	}
}

func TestNewRejectsUnpinnedServiceIdentity(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, config := range []Config{
		{IssuerDID: "did:plc:not-web", Audience: "did:web:spaces.example.test#mailbox", Key: key},
		{IssuerDID: "did:web:adapter.example.test", Audience: "did:web:spaces.example.test", Key: key},
		{IssuerDID: "did:web:adapter.example.test", Audience: "did:web:spaces.example.test#mailbox", Key: nil},
	} {
		if _, err := New(config); err == nil {
			t.Fatalf("accepted config=%#v", config)
		}
	}
}

func TestNewDefaultClientDoesNotInheritProxySettings(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, err := New(Config{
		IssuerDID: "did:web:adapter.example.test", Audience: "did:web:spaces.example.test#mailbox",
		Origin: "https://spaces.example.test/spaces", Key: key,
	})
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := signer.http.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil || transport.TLSClientConfig == nil || transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("default transport is not hardened: %#v", signer.http.Transport)
	}
}

func TestLoadPrivateKeyRejectsBroadPermissions(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	path := writeTestPrivateKey(t, key, 0o644)
	if _, err := LoadPrivateKey(path); err == nil {
		t.Fatal("accepted group/world-readable signing key")
	}
}

func TestLoadPrivateKeyAcceptsSystemdCredentialACLModeOnlyInCredentialDirectory(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := writeTestPrivateKeyIn(t, dir, key, 0o440)

	t.Setenv("CREDENTIALS_DIRECTORY", "")
	if _, err := LoadPrivateKey(path); err == nil {
		t.Fatal("accepted group-readable signing key outside the systemd credential directory")
	}

	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if _, err := LoadPrivateKey(path); err != nil {
		t.Fatalf("load systemd credential signing key: %v", err)
	}

	broadDir := filepath.Join(t.TempDir(), "broad-credential-directory")
	if err := os.Mkdir(broadDir, 0o755); err != nil {
		t.Fatal(err)
	}
	broadPath := writeTestPrivateKeyIn(t, broadDir, key, 0o440)
	t.Setenv("CREDENTIALS_DIRECTORY", broadDir)
	if _, err := LoadPrivateKey(broadPath); err == nil {
		t.Fatal("accepted systemd-style key from a traversable credential directory")
	}
}

func writeTestPrivateKey(t *testing.T, key *ecdsa.PrivateKey, mode os.FileMode) string {
	t.Helper()
	return writeTestPrivateKeyIn(t, t.TempDir(), key, mode)
}

func writeTestPrivateKeyIn(t *testing.T, dir string, key *ecdsa.PrivateKey, mode os.FileMode) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "service-key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), mode); err != nil {
		t.Fatal(err)
	}
	return path
}
