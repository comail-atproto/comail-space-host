package happyview

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/repository"
)

const (
	testDID       = "did:plc:happyviewtest"
	testWriterDID = "did:web:adapter.example.test"
	testOrigin    = "http://127.0.0.1:19090"
	testEpoch     = CertifiedEpoch
)

type capturedRequest struct {
	Method   string
	Endpoint string
	URL      string
	Body     []byte
}

type scriptedResponse struct {
	status int
	body   string
}

type scriptedDoer struct {
	mu        sync.Mutex
	requests  []capturedRequest
	responses []scriptedResponse
}

func (d *scriptedDoer) Do(_ context.Context, req *http.Request, endpoint string) (*http.Response, error) {
	var body []byte
	if req.Body != nil {
		body, _ = io.ReadAll(req.Body)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.requests = append(d.requests, capturedRequest{Method: req.Method, Endpoint: endpoint, URL: req.URL.String(), Body: body})
	if len(d.responses) == 0 {
		return nil, errors.New("no scripted response")
	}
	next := d.responses[0]
	d.responses = d.responses[1:]
	return &http.Response{StatusCode: next.status, Body: io.NopCloser(strings.NewReader(next.body)), Request: req, Header: make(http.Header)}, nil
}

func testClient(t *testing.T, doer Doer) *Client {
	t.Helper()
	client, err := New(Config{
		Origin: testOrigin, DID: testDID, Epoch: testEpoch, AllowHTTP: true, AllowWrites: true,
		RequiredWriterDID: testWriterDID,
	}, doer)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func testTarget() repository.Target {
	return repository.Target{ProviderOrigin: testOrigin, SpaceURI: "at://" + testDID + "/space/" + mailbox.MailboxSpaceType + "/primary", RepoDID: testDID, Epoch: testEpoch}
}

func TestEnsureMailboxCreatesPrivateExactSpace(t *testing.T) {
	doer := &scriptedDoer{responses: []scriptedResponse{
		{200, `{"spaces":[]}`},
		{201, `{"uri":"at://did:plc:happyviewtest/space/email.atmos.mailbox/primary"}`},
		{200, privateMailboxSpaceResponse()},
	}}
	client := testClient(t, doer)
	got, err := client.EnsureMailbox(context.Background(), testDID, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if got != testTarget() {
		t.Fatalf("target = %#v", got)
	}
	var body map[string]any
	if err := json.Unmarshal(doer.requests[1].Body, &body); err != nil {
		t.Fatal(err)
	}
	config := body["config"].(map[string]any)
	if config["recordsPublic"] != false || config["membershipPublic"] != false {
		t.Fatalf("space was not private: %#v", config)
	}
}

func TestEnsureMailboxRejectsExistingPublicSpace(t *testing.T) {
	public := strings.Replace(privateMailboxSpaceResponse(), `"records_public":false`, `"records_public":true`, 1)
	doer := &scriptedDoer{responses: []scriptedResponse{
		{200, `{"spaces":[{"uri":"at://did:plc:happyviewtest/space/email.atmos.mailbox/primary","isOwner":true}]}`},
		{200, public},
	}}
	client := testClient(t, doer)
	if _, err := client.EnsureMailbox(context.Background(), testDID, "primary"); !errors.Is(err, repository.ErrTarget) {
		t.Fatalf("error = %v", err)
	}
}

func TestOpenMailboxVerifiesPreprovisionedPrivateSpaceWithoutCreating(t *testing.T) {
	doer := &scriptedDoer{responses: []scriptedResponse{
		{200, privateMailboxSpaceResponse()},
		{200, `{"members":[{"did":"` + testDID + `","access":"write"},{"did":"` + testWriterDID + `","access":"write"}]}`},
	}}
	client := testClient(t, doer)
	target, err := client.OpenMailbox(t.Context(), testDID, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if target != testTarget() || len(doer.requests) != 2 || doer.requests[0].Endpoint != getSpaceNSID || doer.requests[1].Endpoint != listMembersNSID {
		t.Fatalf("target=%#v requests=%#v", target, doer.requests)
	}
}

func TestOpenMailboxRejectsReadOnlyRequiredWriter(t *testing.T) {
	doer := &scriptedDoer{responses: []scriptedResponse{
		{200, privateMailboxSpaceResponse()},
		{200, `{"members":[{"did":"` + testDID + `","access":"write"},{"did":"` + testWriterDID + `","access":"read"}]}`},
	}}
	client := testClient(t, doer)
	if _, err := client.OpenMailbox(t.Context(), testDID, "primary"); !errors.Is(err, repository.ErrUnauthorized) {
		t.Fatalf("read-only writer error = %v", err)
	}
}

func privateMailboxSpaceResponse() string {
	return fmt.Sprintf(`{"uri":%q,"space":{"did":%q,"authority_did":%q,"creator_did":%q,"type":%q,"skey":"primary","mint_policy":"member-list","app_access":{"type":"open"},"config":{"membership_public":false,"records_public":false,"allowedCollections":[%q,%q,%q,%q,%q,%q]}}}`, testTarget().SpaceURI, testDID, testDID, testDID, mailbox.MailboxSpaceType, mailbox.FolderCollection, mailbox.MessageCollection, mailbox.MessageStateCollection, BlobChunkCollection, BlobManifestCollection, BlobIndexCollection)
}

func TestPrivateChunkedBlobRoundTrip(t *testing.T) {
	raw := []byte("Message-ID: <happyview@example.test>\r\nSubject: private\r\n\r\nhello\r\n")
	chunkRKey := chunkKey(raw)
	manifestRKey := manifestKey(raw)
	manifestCID := "bafyreihappyviewmanifest"
	indexRKey := indexKey(manifestCID)

	doer := &scriptedDoer{responses: []scriptedResponse{
		{404, `{"error":"Record not found"}`},
		{200, `{"results":[{"uri":"` + recordURIForDID(testTarget(), testWriterDID, BlobChunkCollection, chunkRKey) + `","cid":"chunk-cid"}]}`},
		{200, `{"rev":"r1","commit":{"hash":"h1"}}`},
		{404, `{"error":"Record not found"}`},
		{200, `{"results":[{"uri":"` + recordURIForDID(testTarget(), testWriterDID, BlobManifestCollection, manifestRKey) + `","cid":"` + manifestCID + `"}]}`},
		{200, `{"rev":"r2","commit":{"hash":"h2"}}`},
		{404, `{"error":"Record not found"}`},
		{200, `{"results":[{"uri":"` + recordURIForDID(testTarget(), testWriterDID, BlobIndexCollection, indexRKey) + `","cid":"index-cid"}]}`},
		{200, `{"rev":"r3","commit":{"hash":"h3"}}`},
		{200, fmt.Sprintf(`{"uri":%q,"cid":"index-cid","value":{"$type":%q,"manifestRKey":%q,"manifestCid":%q}}`, recordURIForDID(testTarget(), testWriterDID, BlobIndexCollection, indexRKey), BlobIndexCollection, manifestRKey, manifestCID)},
		{200, fmt.Sprintf(`{"uri":%q,"cid":%q,"value":{"$type":%q,"sha256":%q,"size":%d,"mimeType":%q,"chunks":[{"rkey":%q,"sha256":%q,"size":%d}]}}`, recordURIForDID(testTarget(), testWriterDID, BlobManifestCollection, manifestRKey), manifestCID, BlobManifestCollection, mailbox.RawSHA256(raw), len(raw), mailbox.MessageMIMEType, chunkRKey, mailbox.RawSHA256(raw), len(raw))},
		{200, fmt.Sprintf(`{"uri":%q,"cid":"chunk-cid","value":{"$type":%q,"sha256":%q,"size":%d,"dataBase64":%q}}`, recordURIForDID(testTarget(), testWriterDID, BlobChunkCollection, chunkRKey), BlobChunkCollection, mailbox.RawSHA256(raw), len(raw), encodeBase64(raw))},
	}}
	client := testClient(t, doer)
	blob, err := client.UploadBlob(context.Background(), testTarget(), raw, mailbox.MessageMIMEType)
	if err != nil {
		t.Fatal(err)
	}
	if blob.Ref.Link != manifestCID || blob.Size != int64(len(raw)) {
		t.Fatalf("blob = %#v", blob)
	}
	got, err := client.GetBlob(context.Background(), testTarget(), manifestCID)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(raw) {
		t.Fatalf("raw = %q", got)
	}
}

func TestApplyWritesUsesAtomicBatchAndReadsCommit(t *testing.T) {
	doer := &scriptedDoer{responses: []scriptedResponse{
		{200, `{"results":[{"uri":"` + recordURIForDID(testTarget(), testWriterDID, mailbox.MessageCollection, "rk") + `","cid":"c1"},{"uri":"` + recordURIForDID(testTarget(), testWriterDID, mailbox.MessageStateCollection, "rk") + `","cid":"c2"}]}`},
		{200, `{"rev":"r4","commit":{"hash":"h4"}}`},
	}}
	client := testClient(t, doer)
	commit, err := client.ApplyWrites(context.Background(), testTarget(), []repository.Write{
		{Action: repository.Create, Collection: mailbox.MessageCollection, RKey: "rk", Value: map[string]any{"x": 1}},
		{Action: repository.Create, Collection: mailbox.MessageStateCollection, RKey: "rk", Value: map[string]any{"x": 2}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if commit.Rev != "r4" || commit.Hash != "h4" || len(commit.Results) != 2 {
		t.Fatalf("commit = %#v", commit)
	}
}

func TestListRecordsScopesDelegatedReadsToServiceWriter(t *testing.T) {
	doer := &scriptedDoer{responses: []scriptedResponse{{200, `{"records":[]}`}}}
	client := testClient(t, doer)
	if _, err := client.ListRecords(t.Context(), testTarget(), mailbox.MessageCollection); err != nil {
		t.Fatal(err)
	}
	if len(doer.requests) != 1 {
		t.Fatalf("requests = %d, want 1", len(doer.requests))
	}
	requestURL := doer.requests[0].URL
	if !strings.Contains(requestURL, "repo="+url.QueryEscape(testWriterDID)) {
		t.Fatalf("delegated list URL does not use service writer: %s", requestURL)
	}
}

func recordURIForDID(target repository.Target, did, collection, rkey string) string {
	return target.SpaceURI + "/" + did + "/" + collection + "/" + rkey
}

func TestTargetMismatchNeverReachesNetwork(t *testing.T) {
	doer := &scriptedDoer{}
	client := testClient(t, doer)
	bad := testTarget()
	bad.RepoDID = "did:plc:attacker"
	if _, err := client.UploadBlob(context.Background(), bad, []byte("x"), mailbox.MessageMIMEType); !errors.Is(err, repository.ErrTarget) {
		t.Fatalf("error = %v", err)
	}
	if len(doer.requests) != 0 {
		t.Fatal("mismatched target reached network")
	}
}
