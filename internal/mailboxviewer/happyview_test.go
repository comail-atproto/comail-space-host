package mailboxviewer

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHappyViewLoaderPinsVirtualHostPathAndDID(t *testing.T) {
	const (
		publicHost = "happyview.example.test"
		cookie     = "signed-session"
	)
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Host != publicHost {
			t.Errorf("Host = %q", request.Host)
			http.Error(response, "wrong host", http.StatusMisdirectedRequest)
			return
		}
		if got := request.Header.Get("Cookie"); got != "happyview_session="+cookie {
			t.Errorf("Cookie = %q", got)
			http.Error(response, "wrong cookie", http.StatusUnauthorized)
			return
		}
		switch request.URL.Path {
		case "/base/auth/me":
			_, _ = fmt.Fprintf(response, `{"did":%q}`, testDID)
		case "/base/xrpc/test.endpoint":
			response.Header().Set("Content-Type", "application/json")
			_, _ = response.Write([]byte(`{}`))
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()

	loader, err := NewHappyViewLoader(HappyViewConfig{
		Origin: server.URL, BasePath: "/base", PublicHost: publicHost, DID: testDID, SpaceKey: "default",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := loader.authenticate(context.Background(), cookie); err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	doer := &cookieDoer{origin: server.URL, basePath: "/base", publicHost: publicHost, cookie: cookie, client: server.Client()}
	request, err := http.NewRequest(http.MethodGet, server.URL+"/xrpc/test.endpoint", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := doer.Do(context.Background(), request, "test.endpoint")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", response.StatusCode)
	}
}

func TestHappyViewLoaderRejectsWrongAuthenticatedDID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		_, _ = response.Write([]byte(`{"did":"did:plc:someoneelse"}`))
	}))
	defer server.Close()
	loader, err := NewHappyViewLoader(HappyViewConfig{
		Origin: server.URL, BasePath: "/base", PublicHost: "happyview.example.test", DID: testDID, SpaceKey: "default",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := loader.authenticate(context.Background(), "signed-session"); err == nil {
		t.Fatal("wrong authenticated DID was accepted")
	}
}

func TestHappyViewLoaderRequiresValidPinnedIdentity(t *testing.T) {
	for _, config := range []HappyViewConfig{
		{Origin: "http://127.0.0.1:39090", BasePath: "/base", PublicHost: "happyview.example.test", DID: "not-a-did", SpaceKey: "default"},
		{Origin: "http://127.0.0.1:39090", BasePath: "/base", PublicHost: "happyview.example.test", DID: testDID, SpaceKey: "../other"},
	} {
		if _, err := NewHappyViewLoader(config); err == nil {
			t.Fatalf("invalid config was accepted: %#v", config)
		}
	}
}
