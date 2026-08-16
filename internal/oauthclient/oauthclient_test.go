package oauthclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/comail-atproto/comail-pds-lab/internal/mailbox"
)

func TestMailboxScopesAreExactAndCollectionLimited(t *testing.T) {
	scopes, err := MailboxScopes("primary")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(scopes, " ")
	for _, required := range []string{
		"atproto", "blob:message/rfc822", "space:" + mailbox.MailboxSpaceType,
		"authority=self", "skey=primary", "action=read", "action=create", "action=update", "action=delete",
		"collection=" + mailbox.MessageCollection,
		"collection=" + mailbox.MessageStateCollection,
		"collection=" + mailbox.FolderCollection,
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("scope omitted %q: %s", required, joined)
		}
	}
	if strings.Contains(joined, "authority=*") || strings.Contains(joined, "collection=*") || strings.Contains(joined, "space:*") {
		t.Fatalf("scope widened unexpectedly: %s", joined)
	}
}

func TestPinnedHTTPClientAllowsOnlyExactLoopbackOriginAndRefusesRedirect(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = io.WriteString(w, "ok")
		case "/redirect":
			http.Redirect(w, r, server.URL+"/ok", http.StatusFound)
		}
	}))
	defer server.Close()
	client, origin, err := newPinnedHTTPClient(server.URL, true)
	if err != nil {
		t.Fatal(err)
	}
	if origin != server.URL {
		t.Fatalf("origin = %s", origin)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/ok", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	redirect, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL+"/redirect", nil)
	if _, err := client.Do(redirect); err == nil {
		t.Fatal("authenticated redirect was followed")
	}
	other, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://127.0.0.1:1/escape", nil)
	if _, err := client.Do(other); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("wrong-origin error = %v", err)
	}
}
