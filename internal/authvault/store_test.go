package authvault

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/bluesky-social/indigo/atproto/auth/oauth"
	"github.com/bluesky-social/indigo/atproto/syntax"
)

func TestEncryptedStoreRoundTripAndNoPlaintext(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "vault.key")
	vaultPath := filepath.Join(dir, "oauth.vault")
	store, err := Create(vaultPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	did := syntax.DID("did:plc:encrypted-test")
	session := oauth.ClientSessionData{
		AccountDID: did, SessionID: "session-1", HostURL: "https://pds.example.test",
		AccessToken: "access-super-secret", RefreshToken: "refresh-super-secret",
		DPoPPrivateKeyMultibase: "private-key-super-secret", Scopes: []string{"atproto"},
	}
	request := oauth.AuthRequestData{
		State: "state-1", AuthServerURL: "https://pds.example.test",
		PKCEVerifier: "pkce-super-secret", DPoPPrivateKeyMultibase: "request-key-super-secret",
	}
	if err := store.SaveSession(context.Background(), session); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAuthRequestInfo(context.Background(), request); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range [][]byte{[]byte(session.AccessToken), []byte(session.RefreshToken), []byte(session.DPoPPrivateKeyMultibase), []byte(request.PKCEVerifier)} {
		if bytes.Contains(data, secret) {
			t.Fatalf("vault leaked plaintext %q", secret)
		}
	}
	for _, path := range []string{vaultPath, keyPath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s mode = %o", path, got)
		}
	}

	reopened, err := Open(vaultPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	gotSession, err := reopened.GetSession(context.Background(), did, session.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if gotSession.AccessToken != session.AccessToken || gotSession.RefreshToken != session.RefreshToken {
		t.Fatalf("session did not round-trip: %#v", gotSession)
	}
	gotRequest, err := reopened.GetAuthRequestInfo(context.Background(), request.State)
	if err != nil {
		t.Fatal(err)
	}
	if gotRequest.PKCEVerifier != request.PKCEVerifier {
		t.Fatalf("request did not round-trip: %#v", gotRequest)
	}
}

func TestEncryptedStoreRejectsWrongKeyAndDuplicateRequest(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := Create(filepath.Join(dir, "vault"), filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	info := oauth.AuthRequestData{State: "once", PKCEVerifier: "secret"}
	if err := store.SaveAuthRequestInfo(context.Background(), info); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveAuthRequestInfo(context.Background(), info); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate error = %v", err)
	}
	wrongKey := filepath.Join(dir, "wrong-key")
	if err := writeNewKey(wrongKey); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(dir, "vault"), wrongKey); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong-key error = %v", err)
	}
}

func TestEncryptedStoreDeleteAndMissing(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := Create(filepath.Join(dir, "vault"), filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	did := syntax.DID("did:plc:delete-test")
	if _, err := store.GetSession(context.Background(), did, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing session error = %v", err)
	}
	if err := store.SaveSession(context.Background(), oauth.ClientSessionData{AccountDID: did, SessionID: "one", AccessToken: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteSession(context.Background(), did, "one"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetSession(context.Background(), did, "one"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted session error = %v", err)
	}
}

func TestEncryptedStoreExpiresAbandonedAuthRequests(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := Create(filepath.Join(dir, "vault"), filepath.Join(dir, "key"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	info := oauth.AuthRequestData{State: "abandoned", PKCEVerifier: "secret"}
	if err := store.SaveAuthRequestInfo(context.Background(), info); err != nil {
		t.Fatal(err)
	}
	now = now.Add(authRequestTTL + time.Second)
	if _, err := store.GetAuthRequestInfo(context.Background(), info.State); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired request error = %v", err)
	}
	if err := store.SaveAuthRequestInfo(context.Background(), info); err != nil {
		t.Fatalf("expired state was not pruned: %v", err)
	}
}
