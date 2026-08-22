package spaceproof

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

func TestProveReadUsesExactMetadataOnlyCredentialRequest(t *testing.T) {
	doer := scriptedDoer{handle: func(request *http.Request, endpoint string) *http.Response {
		query := request.URL.Query()
		if endpoint != listRecordsEndpoint || request.Method != http.MethodGet ||
			request.URL.Path != "/xrpc/"+listRecordsEndpoint || query.Get("space") != testSpaceURI ||
			query.Get("repo") != testDID || query.Get("collection") != "email.atmos.message" ||
			query.Get("limit") != "1" || query.Get("excludeValues") != "true" || len(query) != 5 {
			t.Fatalf("request = %s %s endpoint=%q", request.Method, request.URL.String(), endpoint)
		}
		return jsonResponse(request, http.StatusOK, `{"records":[]}`)
	}}
	client, err := New(Config{Origin: "https://spaces.example", DID: testDID, SpaceKey: "primary"}, &doer)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.ProveRead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.RepoState != RepoReady || result.RecordMetadataPresent {
		t.Fatalf("result = %#v", result)
	}
}

func TestProveReadValidatesOneMetadataRecordWithoutReturningItsIdentifiers(t *testing.T) {
	doer := scriptedDoer{handle: func(request *http.Request, _ string) *http.Response {
		return jsonResponse(request, http.StatusOK, `{"cursor":"`+testSpaceURI+`/`+testDID+`/email.atmos.message/one","records":[{"collection":"email.atmos.message","rkey":"one","cid":"bafyreid3uyzt4jcdm5b5x7czizehgqbxp4pmztqv55c4n3z7s2xmq2lm2e"}]}`)
	}}
	client, err := New(Config{Origin: "https://spaces.example", DID: testDID, SpaceKey: "primary"}, &doer)
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.ProveRead(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.RepoState != RepoReady || !result.RecordMetadataPresent {
		t.Fatalf("result = %#v", result)
	}
}

func TestProveReadRejectsUntrustedResponsesWithoutLeakingBody(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "RepoNotFound", status: http.StatusBadRequest, body: `{"error":"RepoNotFound","message":"synthetic"}`},
		{name: "wrong RepoNotFound status", status: http.StatusNotFound, body: `{"error":"RepoNotFound"}`},
		{name: "unauthorized", status: http.StatusUnauthorized, body: `{"error":"AuthMissing"}`},
		{name: "missing records", status: http.StatusOK, body: `{}`},
		{name: "unknown top-level field", status: http.StatusOK, body: `{"records":[],"extra":true}`},
		{name: "value unexpectedly included", status: http.StatusOK, body: `{"records":[{"collection":"email.atmos.message","rkey":"one","cid":"bafyreid3uyzt4jcdm5b5x7czizehgqbxp4pmztqv55c4n3z7s2xmq2lm2e","value":{"secret":"DO-NOT-LEAK"}}]}`},
		{name: "invalid collection", status: http.StatusOK, body: `{"records":[{"collection":"not valid","rkey":"one","cid":"bafyreid3uyzt4jcdm5b5x7czizehgqbxp4pmztqv55c4n3z7s2xmq2lm2e"}]}`},
		{name: "wrong collection", status: http.StatusOK, body: `{"records":[{"collection":"email.atmos.folderOperation","rkey":"one","cid":"bafyreid3uyzt4jcdm5b5x7czizehgqbxp4pmztqv55c4n3z7s2xmq2lm2e"}]}`},
		{name: "invalid rkey", status: http.StatusOK, body: `{"records":[{"collection":"email.atmos.message","rkey":"bad/key","cid":"bafyreid3uyzt4jcdm5b5x7czizehgqbxp4pmztqv55c4n3z7s2xmq2lm2e"}]}`},
		{name: "invalid cid", status: http.StatusOK, body: `{"records":[{"collection":"email.atmos.message","rkey":"one","cid":"not-a-cid"}]}`},
		{name: "missing one-record cursor", status: http.StatusOK, body: `{"records":[{"collection":"email.atmos.message","rkey":"one","cid":"bafyreid3uyzt4jcdm5b5x7czizehgqbxp4pmztqv55c4n3z7s2xmq2lm2e"}]}`},
		{name: "trailing JSON", status: http.StatusOK, body: `{"records":[]} {}`},
		{name: "too many records", status: http.StatusOK, body: `{"records":[{"collection":"email.atmos.message","rkey":"one","cid":"bafyreid3uyzt4jcdm5b5x7czizehgqbxp4pmztqv55c4n3z7s2xmq2lm2e"},{"collection":"email.atmos.message","rkey":"two","cid":"bafyreid3uyzt4jcdm5b5x7czizehgqbxp4pmztqv55c4n3z7s2xmq2lm2e"}]}`},
		{name: "oversized", status: http.StatusOK, body: strings.Repeat("x", maxResponseBytes+1)},
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
			if _, err := client.ProveRead(context.Background()); err == nil {
				t.Fatal("expected response rejection")
			} else if strings.Contains(err.Error(), "DO-NOT-LEAK") || strings.Contains(err.Error(), test.body) {
				t.Fatalf("error leaked response body: %v", err)
			}
		})
	}
}

type scriptedDoer struct {
	handle func(*http.Request, string) *http.Response
}

func (d *scriptedDoer) Do(_ context.Context, request *http.Request, endpoint string) (*http.Response, error) {
	return d.handle(request, endpoint), nil
}

func jsonResponse(request *http.Request, status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status, Header: make(http.Header), Request: request,
		Body: io.NopCloser(strings.NewReader(body)),
	}
}
