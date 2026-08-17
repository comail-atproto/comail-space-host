package happyview

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSessionDoerUsesOwnerOnlyCookieFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "happyview-cookie")
	if err := os.WriteFile(path, []byte("happyview_session=signed-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Cookie"); got != "happyview_session=signed-value" {
			t.Fatalf("cookie = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer server.Close()

	doer, err := NewSessionDoer(path)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, server.URL+"/xrpc/test", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := doer.Do(context.Background(), request, "test")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
}

func TestSessionDoerRejectsBroadOrLinkedSecretFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission invariant")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	broad := filepath.Join(dir, "broad")
	if err := os.WriteFile(broad, []byte("happyview_session=signed-value\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSessionDoer(broad); err == nil {
		t.Fatal("accepted broadly readable cookie file")
	}
	private := filepath.Join(dir, "private")
	if err := os.WriteFile(private, []byte("happyview_session=signed-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(dir, "linked")
	if err := os.Symlink(private, linked); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSessionDoer(linked); err == nil {
		t.Fatal("accepted symlinked cookie file")
	}
}

func TestSessionDoerRefusesRedirects(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "happyview-cookie")
	if err := os.WriteFile(path, []byte("happyview_session=signed-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	destinationReached := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/destination" {
			destinationReached = true
		}
		http.Redirect(w, request, "/destination", http.StatusFound)
	}))
	defer server.Close()
	doer, err := NewSessionDoer(path)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodGet, server.URL+"/start", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := doer.Do(context.Background(), request, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound || destinationReached {
		t.Fatalf("redirect followed: status=%d destination=%t", response.StatusCode, destinationReached)
	}
}
