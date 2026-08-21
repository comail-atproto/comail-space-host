package oauthclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMintDelegationUsesPinnedExactSpaceAndBoundedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/xrpc/com.atproto.space.getDelegationToken" {
			t.Errorf("request target = %s %s", request.Method, request.URL.Path)
		}
		wantSpace := "at://" + testMemberDID + "/space/email.atmos.mailbox/primary"
		if request.URL.Query().Get("space") != wantSpace || len(request.URL.Query()) != 1 {
			t.Errorf("space query = %q", request.URL.RawQuery)
		}
		if request.Header.Get("Authorization") != "DPoP opaque-access" || request.Header.Get("DPoP") == "" {
			t.Error("delegation request omitted OAuth DPoP authorization")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"token":"eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiJzeW50aGV0aWMifQ.c2lnbmF0dXJl"}`))
	}))
	defer server.Close()
	doer, _ := newTestSessionDoer(t, server.URL)

	delegation, err := doer.MintDelegation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	used := 0
	if err := delegation.Use(func(token string) error {
		used++
		if token != "eyJhbGciOiJFUzI1NiJ9.eyJqdGkiOiJzeW50aGV0aWMifQ.c2lnbmF0dXJl" {
			t.Fatal("delegation token did not match bounded response")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if used != 1 {
		t.Fatalf("delegation uses = %d", used)
	}
	if err := delegation.Use(func(string) error { return nil }); !errors.Is(err, ErrDelegationConsumed) {
		t.Fatalf("second use error = %v, want ErrDelegationConsumed", err)
	}
}

func TestMintDelegationRejectsUnsafeResponsesWithoutLeakingBody(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "non success", status: http.StatusUnauthorized, body: `{"error":"InvalidToken","message":"SECRET-UPSTREAM-TEXT"}`},
		{name: "missing token", status: http.StatusOK, body: `{}`},
		{name: "unknown field", status: http.StatusOK, body: `{"token":"a.b.c","extra":true}`},
		{name: "trailing object", status: http.StatusOK, body: `{"token":"a.b.c"}{}`},
		{name: "not jwt", status: http.StatusOK, body: `{"token":"opaque token"}`},
		{name: "oversized", status: http.StatusOK, body: fmt.Sprintf(`{"token":"%s.a.b"}`, strings.Repeat("a", maxDelegationResponseBytes))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			doer, _ := newTestSessionDoer(t, server.URL)
			if _, err := doer.MintDelegation(context.Background()); err == nil {
				t.Fatal("expected response rejection")
			} else if strings.Contains(err.Error(), "SECRET-UPSTREAM-TEXT") || strings.Contains(err.Error(), test.body) {
				t.Fatalf("error leaked upstream body: %v", err)
			}
		})
	}
}
