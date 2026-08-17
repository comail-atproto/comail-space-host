package rsky

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/repository"
)

const (
	rskyDID    = "did:plc:rskytest"
	rskyOrigin = "http://127.0.0.1:18080"
	rskyEpoch  = "2918753b1f32ae99022bc2c5cc9a0cc645095337"
)

type capturedRequest struct {
	Method   string
	Endpoint string
	URL      string
	Body     []byte
	Header   http.Header
}

type scriptedDoer struct {
	mu        sync.Mutex
	requests  []capturedRequest
	responses []scriptedResponse
}

type scriptedResponse struct {
	status      int
	contentType string
	body        string
}

func (d *scriptedDoer) Do(_ context.Context, req *http.Request, endpoint string) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.requests = append(d.requests, capturedRequest{Method: req.Method, Endpoint: endpoint, URL: req.URL.String(), Body: body, Header: req.Header.Clone()})
	if len(d.responses) == 0 {
		return nil, errors.New("no scripted response")
	}
	next := d.responses[0]
	d.responses = d.responses[1:]
	header := make(http.Header)
	if next.contentType != "" {
		header.Set("Content-Type", next.contentType)
	}
	return &http.Response{
		StatusCode: next.status,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(next.body)),
		Request:    req,
	}, nil
}

func newTestClient(t *testing.T, doer Doer) *Client {
	t.Helper()
	client, err := New(Config{Origin: rskyOrigin, DID: rskyDID, Epoch: rskyEpoch, AllowHTTP: true, AllowWrites: true, CertificationProbe: true, CertificationPatch: CertifiedPatchID}, doer)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestPinnedEpochRefusesMailboxWriteMode(t *testing.T) {
	_, err := New(Config{Origin: rskyOrigin, DID: rskyDID, Epoch: rskyEpoch, AllowHTTP: true, AllowWrites: true}, &scriptedDoer{})
	if !errors.Is(err, repository.ErrUnsupported) {
		t.Fatalf("write-mode error = %v", err)
	}
	client, err := New(Config{Origin: rskyOrigin, DID: rskyDID, Epoch: rskyEpoch, AllowHTTP: true}, &scriptedDoer{})
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err := client.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if capabilities.AtomicApplyWrites {
		t.Fatal("unsafe pinned epoch advertised atomic applyWrites")
	}
	patched, err := New(Config{Origin: rskyOrigin, DID: rskyDID, Epoch: rskyEpoch, AllowHTTP: true, AllowWrites: true, CertificationProbe: true, CertificationPatch: CertifiedPatchID}, &scriptedDoer{})
	if err != nil {
		t.Fatal(err)
	}
	capabilities, err = patched.Capabilities(context.Background())
	if err != nil || !capabilities.AtomicApplyWrites {
		t.Fatalf("patched capabilities=%#v err=%v", capabilities, err)
	}
	_, err = New(Config{Origin: "https://hosted.example.test", DID: rskyDID, Epoch: rskyEpoch, AllowWrites: true, CertificationProbe: true, CertificationPatch: CertifiedPatchID}, &scriptedDoer{})
	if !errors.Is(err, repository.ErrUnsupported) {
		t.Fatalf("hosted certification probe error = %v", err)
	}
}

func target() repository.Target {
	return repository.Target{
		ProviderOrigin: rskyOrigin,
		SpaceURI:       "at://" + rskyDID + "/space/" + mailbox.MailboxSpaceType + "/primary",
		RepoDID:        rskyDID,
		Epoch:          rskyEpoch,
	}
}

func TestEnsureMailboxDiscoversOrCreatesExactSpace(t *testing.T) {
	doer := &scriptedDoer{responses: []scriptedResponse{
		{status: 200, body: `{"spaces":[]}`},
		{status: 200, body: `{"uri":"at://did:plc:rskytest/space/email.atmos.mailbox/primary"}`},
		{status: 200, body: `{"spaces":[{"uri":"at://did:plc:rskytest/space/email.atmos.mailbox/primary","isOwner":true,"isMember":true,"createdAt":"2026-08-15T00:00:00Z"}]}`},
	}}
	client := newTestClient(t, doer)
	got, err := client.EnsureMailbox(context.Background(), rskyDID, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if got != target() {
		t.Fatalf("target = %#v", got)
	}
	if _, err := client.EnsureMailbox(context.Background(), rskyDID, "primary"); err != nil {
		t.Fatal(err)
	}
	if len(doer.requests) != 3 || doer.requests[1].Endpoint != "com.atproto.simplespace.createSpace" {
		t.Fatalf("requests = %#v", doer.requests)
	}
	var body map[string]any
	if err := json.Unmarshal(doer.requests[1].Body, &body); err != nil {
		t.Fatal(err)
	}
	if body["type"] != mailbox.MailboxSpaceType || body["skey"] != "primary" {
		t.Fatalf("create body = %#v", body)
	}
}

func TestMailboxRoundTripRequestShapes(t *testing.T) {
	raw := []byte("Subject: rsky synthetic\r\n\r\nhello\r\n")
	doer := &scriptedDoer{responses: []scriptedResponse{
		{status: 200, body: fmt.Sprintf(`{"blob":{"$type":"blob","ref":{"$link":"bafkraw"},"mimeType":"message/rfc822","size":%d}}`, len(raw))},
		{status: 200, body: `{"commit":{"rev":"r1","hash":"h1"},"results":[{"$type":"com.atproto.space.applyWrites#createResult","uri":"at://did:plc:rskytest/space/email.atmos.mailbox/primary/did:plc:rskytest/email.atmos.message/rk","cid":"c1"},{"$type":"com.atproto.space.applyWrites#createResult","uri":"at://did:plc:rskytest/space/email.atmos.mailbox/primary/did:plc:rskytest/email.atmos.messageState/rk","cid":"c2"}]}`},
		{status: 200, body: `{"uri":"at://did:plc:rskytest/space/email.atmos.mailbox/primary/did:plc:rskytest/email.atmos.messageState/rk","cid":"c3","commit":{"rev":"r2","hash":"h2"}}`},
		{status: 200, body: `{"uri":"at://did:plc:rskytest/space/email.atmos.mailbox/primary/did:plc:rskytest/email.atmos.message/rk","cid":"c1","value":{"$type":"email.atmos.message","raw":{"$type":"blob","ref":{"$link":"bafkraw"},"mimeType":"message/rfc822","size":36},"sha256":"x","size":36,"deliveryFingerprint":"y","initialMailbox":"INBOX"}}`},
		{status: 200, body: `{"records":[{"collection":"email.atmos.message","rkey":"rk","cid":"c1","value":{"x":1}}]}`},
		{status: 200, contentType: "message/rfc822", body: string(raw)},
	}}
	client := newTestClient(t, doer)
	blob, err := client.UploadBlob(context.Background(), target(), raw, mailbox.MessageMIMEType)
	if err != nil {
		t.Fatal(err)
	}
	if blob.Ref.Link != "bafkraw" || blob.Size != int64(len(raw)) {
		t.Fatalf("blob = %#v", blob)
	}
	commit, err := client.ApplyWrites(context.Background(), target(), []repository.Write{
		{Action: repository.Create, Collection: mailbox.MessageCollection, RKey: "rk", Value: map[string]any{"x": 1}},
		{Action: repository.Create, Collection: mailbox.MessageStateCollection, RKey: "rk", Value: map[string]any{"x": 2}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if commit.Rev != "r1" || len(commit.Results) != 2 {
		t.Fatalf("commit = %#v", commit)
	}
	if _, err := client.PutRecordCAS(context.Background(), target(), mailbox.MessageStateCollection, "rk", map[string]any{"x": 3}, "c2"); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetRecord(context.Background(), target(), mailbox.MessageCollection, "rk"); err != nil {
		t.Fatal(err)
	}
	if records, err := client.ListRecords(context.Background(), target(), mailbox.MessageCollection); err != nil || len(records) != 1 {
		t.Fatalf("records=%d err=%v", len(records), err)
	}
	if got, err := client.GetBlob(context.Background(), target(), "bafkraw"); err != nil || string(got) != string(raw) {
		t.Fatalf("blob bytes=%q err=%v", got, err)
	}
	if got := doer.requests[0]; got.Endpoint != "com.atproto.repo.uploadBlob" || got.Header.Get("Content-Type") != mailbox.MessageMIMEType || string(got.Body) != string(raw) {
		t.Fatalf("upload request = %#v", got)
	}
	var apply map[string]any
	if err := json.Unmarshal(doer.requests[1].Body, &apply); err != nil {
		t.Fatal(err)
	}
	if apply["space"] != target().SpaceURI || apply["repo"] != rskyDID {
		t.Fatalf("apply binding = %#v", apply)
	}
	var cas map[string]any
	if err := json.Unmarshal(doer.requests[2].Body, &cas); err != nil {
		t.Fatal(err)
	}
	if cas["swapRecord"] != "c2" {
		t.Fatalf("CAS body = %#v", cas)
	}
}

func TestClientRejectsTargetMismatchBeforeNetwork(t *testing.T) {
	doer := &scriptedDoer{}
	client := newTestClient(t, doer)
	bad := target()
	bad.RepoDID = "did:plc:other"
	if _, err := client.UploadBlob(context.Background(), bad, []byte("x"), "application/octet-stream"); !errors.Is(err, repository.ErrTarget) {
		t.Fatalf("error = %v", err)
	}
	if len(doer.requests) != 0 {
		t.Fatal("target mismatch reached network")
	}
}

func TestClientMapsProviderErrorsWithoutBodyLeak(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   error
	}{
		{400, `{"error":"RecordExists","message":"sensitive provider detail"}`, repository.ErrExists},
		{400, `{"error":"InvalidSwap","message":"sensitive provider detail"}`, repository.ErrConflict},
		{404, `{"error":"BlobNotFound","message":"sensitive provider detail"}`, repository.ErrNotFound},
		{403, `{"error":"Forbidden","message":"sensitive provider detail"}`, repository.ErrUnauthorized},
	} {
		doer := &scriptedDoer{responses: []scriptedResponse{{status: tc.status, body: tc.body}}}
		client := newTestClient(t, doer)
		_, err := client.GetRecord(context.Background(), target(), mailbox.MessageCollection, "rk")
		if !errors.Is(err, tc.want) {
			t.Fatalf("status %d error = %v", tc.status, err)
		}
		if strings.Contains(fmtError(err), "sensitive") {
			t.Fatalf("provider message leaked: %v", err)
		}
	}
}

func TestGetBlobIsBounded(t *testing.T) {
	doer := &scriptedDoer{responses: []scriptedResponse{{status: 200, body: strings.Repeat("x", mailbox.MaxRawMessageBytes+1)}}}
	client := newTestClient(t, doer)
	if _, err := client.GetBlob(context.Background(), target(), "bafkraw"); !errors.Is(err, mailbox.ErrMessageTooLarge) {
		t.Fatalf("error = %v", err)
	}
}

func fmtError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
