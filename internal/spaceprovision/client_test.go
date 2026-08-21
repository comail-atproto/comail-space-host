package spaceprovision

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

const (
	testDID      = "did:plc:rfwhywgeym2ek7ioeyxkvsn6"
	testSpaceURI = "at://did:plc:rfwhywgeym2ek7ioeyxkvsn6/space/email.atmos.mailbox/primary"
)

func TestEnsureCreatesExactPrivateOpenMailboxAndIsIdempotent(t *testing.T) {
	created := false
	doer := scriptedDoer{handle: func(request *http.Request, endpoint string) *http.Response {
		switch endpoint {
		case createSpaceEndpoint:
			body, _ := io.ReadAll(request.Body)
			want := `{"type":"email.atmos.mailbox","skey":"primary","policy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}`
			if request.Method != http.MethodPost || request.URL.RawQuery != "" || string(body) != want {
				t.Errorf("create request = %s %s %s", request.Method, request.URL.String(), body)
			}
			if created {
				return jsonResponse(request, http.StatusBadRequest, `{"error":"SpaceAlreadyExists","message":"synthetic"}`)
			}
			created = true
			return jsonResponse(request, http.StatusOK, `{"uri":"`+testSpaceURI+`"}`)
		case getSpaceEndpoint:
			if request.Method != http.MethodGet || request.URL.Query().Get("space") != testSpaceURI || len(request.URL.Query()) != 1 {
				t.Errorf("get request = %s %s", request.Method, request.URL.String())
			}
			return jsonResponse(request, http.StatusOK, `{"uri":"`+testSpaceURI+`","policy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}`)
		case listMembersEndpoint:
			if request.Method != http.MethodGet || request.URL.Query().Get("space") != testSpaceURI || request.URL.Query().Get("limit") != "1000" || len(request.URL.Query()) != 2 {
				t.Errorf("members request = %s %s", request.Method, request.URL.String())
			}
			return jsonResponse(request, http.StatusOK, `{"members":[]}`)
		default:
			t.Fatalf("unexpected endpoint %q", endpoint)
			return nil
		}
	}}
	client, err := New(Config{Origin: "https://spaces.example", DID: testDID, SpaceKey: "primary"}, &doer)
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.Ensure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.Ensure(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !first.Created || second.Created || first.SpaceURI != testSpaceURI || second.SpaceURI != testSpaceURI || len(doer.endpoints) != 6 {
		t.Fatalf("first=%#v second=%#v endpoints=%v", first, second, doer.endpoints)
	}
}

func TestEnsureRejectsConfigurationAndMemberDrift(t *testing.T) {
	tests := []struct {
		name string
		get  string
		list string
	}{
		{name: "wrong uri", get: `{"uri":"at://did:plc:rfwhywgeym2ek7ioeyxkvsn6/space/email.atmos.mailbox/other","policy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}`, list: `{"members":[]}`},
		{name: "public policy", get: `{"uri":"` + testSpaceURI + `","policy":{"$type":"com.atproto.simplespace.defs#publicPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}`, list: `{"members":[]}`},
		{name: "allow list", get: `{"uri":"` + testSpaceURI + `","policy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#allowList"}}`, list: `{"members":[]}`},
		{name: "foreign member", get: `{"uri":"` + testSpaceURI + `","policy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}`, list: `{"members":[{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"}]}`},
		{name: "owner member", get: `{"uri":"` + testSpaceURI + `","policy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}`, list: `{"members":[{"did":"` + testDID + `"}]}`},
		{name: "missing members", get: `{"uri":"` + testSpaceURI + `","policy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}`, list: `{}`},
		{name: "cursor on empty members", get: `{"uri":"` + testSpaceURI + `","policy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"}}`, list: `{"members":[],"cursor":"unexpected"}`},
		{name: "unknown config field", get: `{"uri":"` + testSpaceURI + `","policy":{"$type":"com.atproto.simplespace.defs#memberListPolicy"},"appAccess":{"$type":"com.atproto.simplespace.defs#open"},"extra":true}`, list: `{"members":[]}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			doer := scriptedDoer{handle: func(request *http.Request, endpoint string) *http.Response {
				switch endpoint {
				case createSpaceEndpoint:
					return jsonResponse(request, http.StatusBadRequest, `{"error":"SpaceAlreadyExists"}`)
				case getSpaceEndpoint:
					return jsonResponse(request, http.StatusOK, test.get)
				case listMembersEndpoint:
					return jsonResponse(request, http.StatusOK, test.list)
				default:
					t.Fatalf("unexpected endpoint %q", endpoint)
					return nil
				}
			}}
			client, err := New(Config{Origin: "https://spaces.example", DID: testDID, SpaceKey: "primary"}, &doer)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Ensure(context.Background()); err == nil {
				t.Fatal("expected drift rejection")
			}
		})
	}
}

func TestEnsureRejectsUnsafeProviderResponsesWithoutLeakingBody(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "unexpected error", status: http.StatusForbidden, body: `{"error":"Denied","message":"SECRET-UPSTREAM-TEXT"}`},
		{name: "wrong already-exists status", status: http.StatusConflict, body: `{"error":"SpaceAlreadyExists"}`},
		{name: "unknown success field", status: http.StatusOK, body: `{"uri":"` + testSpaceURI + `","extra":true}`},
		{name: "oversized", status: http.StatusOK, body: strings.Repeat("x", maxJSONResponseBytes+1)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			doer := scriptedDoer{handle: func(request *http.Request, _ string) *http.Response {
				return jsonResponse(request, test.status, test.body)
			}}
			client, err := New(Config{Origin: "https://spaces.example", DID: testDID, SpaceKey: "primary"}, &doer)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Ensure(context.Background()); err == nil {
				t.Fatal("expected unsafe response rejection")
			} else if strings.Contains(err.Error(), "SECRET-UPSTREAM-TEXT") || strings.Contains(err.Error(), test.body) {
				t.Fatalf("error leaked provider body: %v", err)
			}
		})
	}
}

type scriptedDoer struct {
	handle    func(*http.Request, string) *http.Response
	endpoints []string
}

func (d *scriptedDoer) Do(_ context.Context, request *http.Request, endpoint string) (*http.Response, error) {
	d.endpoints = append(d.endpoints, endpoint)
	return d.handle(request, endpoint), nil
}

func jsonResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status, Header: make(http.Header), Request: request,
		Body: io.NopCloser(strings.NewReader(body)),
	}
}
