package officialspaces

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/repository"
	cidlib "github.com/ipfs/go-cid"
	"github.com/multiformats/go-multihash"
)

const (
	testSpaceDID = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"
	testDID      = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"
	testSpaceURI = "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/space/email.atmos.mailbox/primary"
	testCID      = "bafyreid3uyzt4jcdm5b5x7czizehgqbxp4pmztqv55c4n3z7s2xmq2lm2e"
)

func TestNewPinsOfficialAlphaTargetAndAuthLanes(t *testing.T) {
	writer := &scriptedWriterSource{}
	reader := &scriptedSource{}
	client, err := New(Config{
		Origin: "https://SPACES.EXAMPLE:443/", SpaceAuthorityDID: testSpaceDID, RepoDID: testDID, SpaceKey: "primary", Epoch: PinnedEpoch,
	}, writer, reader)
	if err != nil {
		t.Fatal(err)
	}
	if got := client.TransportID(); got != "official-spaces-transport@"+PinnedEpoch {
		t.Fatalf("transport id = %q", got)
	}
	if got := client.target; got.Origin != "https://spaces.example" || got.SpaceURI != testSpaceURI || got.RepoDID != testDID || got.Epoch != PinnedEpoch {
		t.Fatalf("target = %#v", got)
	}

	tests := []struct {
		name   string
		config Config
		writer WriterSource
		reader CredentialSource
	}{
		{name: "missing writer", config: Config{Origin: "https://spaces.example", SpaceAuthorityDID: testSpaceDID, RepoDID: testDID, SpaceKey: "primary", Epoch: PinnedEpoch}, reader: reader},
		{name: "missing reader", config: Config{Origin: "https://spaces.example", SpaceAuthorityDID: testSpaceDID, RepoDID: testDID, SpaceKey: "primary", Epoch: PinnedEpoch}, writer: writer},
		{name: "wrong epoch", config: Config{Origin: "https://spaces.example", SpaceAuthorityDID: testSpaceDID, RepoDID: testDID, SpaceKey: "primary", Epoch: "moving"}, writer: writer, reader: reader},
		{name: "pathful origin", config: Config{Origin: "https://spaces.example/x", SpaceAuthorityDID: testSpaceDID, RepoDID: testDID, SpaceKey: "primary", Epoch: PinnedEpoch}, writer: writer, reader: reader},
		{name: "public HTTP", config: Config{Origin: "http://spaces.example", SpaceAuthorityDID: testSpaceDID, RepoDID: testDID, SpaceKey: "primary", Epoch: PinnedEpoch, AllowHTTP: true}, writer: writer, reader: reader},
		{name: "wildcard key", config: Config{Origin: "https://spaces.example", SpaceAuthorityDID: testSpaceDID, RepoDID: testDID, SpaceKey: "*", Epoch: PinnedEpoch}, writer: writer, reader: reader},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New(test.config, test.writer, test.reader); err == nil {
				t.Fatal("expected constructor rejection")
			}
		})
	}
}

func TestUploadMessageBlobUsesMemberOAuthAndValidatesReceipt(t *testing.T) {
	raw := []byte("From: sender@example.test\r\nTo: user@example.test\r\n\r\nhello\r\n")
	blobCID := testBlobCID(t, raw)
	writer := &scriptedDoer{handle: func(request *http.Request, endpoint string) (*http.Response, error) {
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		if endpoint != uploadBlobEndpoint || request.Method != http.MethodPost || request.URL.String() != "https://spaces.example/xrpc/"+uploadBlobEndpoint ||
			request.Header.Get("Content-Type") != mailbox.MessageMIMEType || request.Header.Get("Cache-Control") != "no-store" || string(body) != string(raw) {
			t.Fatalf("unexpected upload request: endpoint=%q method=%q url=%q headers=%v body=%q", endpoint, request.Method, request.URL, request.Header, body)
		}
		return jsonResponse(request, http.StatusOK, `{"blob":{"$type":"blob","ref":{"$link":"`+blobCID+`"},"mimeType":"message/rfc822","size":`+fmt.Sprint(len(raw))+`}}`), nil
	}}
	source := &scriptedWriterSource{doer: writer}
	client, err := New(Config{
		Origin: "https://spaces.example", SpaceAuthorityDID: testSpaceDID, RepoDID: testDID, SpaceKey: "primary", Epoch: PinnedEpoch,
	}, source, &scriptedSource{})
	if err != nil {
		t.Fatal(err)
	}
	blob, err := client.UploadMessageBlob(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if blob.Ref.Link != blobCID || blob.MIMEType != mailbox.MessageMIMEType || blob.Size != int64(len(raw)) {
		t.Fatalf("blob = %#v", blob)
	}
	if source.acquired != 1 || source.closed != 1 {
		t.Fatalf("acquired=%d closed=%d", source.acquired, source.closed)
	}

	for _, bad := range [][]byte{nil, make([]byte, mailbox.MaxRawMessageBytes+1)} {
		if _, err := client.UploadMessageBlob(context.Background(), bad); err == nil {
			t.Fatal("expected invalid message rejection")
		}
	}
}

func TestUploadMessageBlobRejectsCIDForDifferentBytes(t *testing.T) {
	raw := []byte("synthetic message")
	wrongCID := testBlobCID(t, []byte("different bytes"))
	writer := &scriptedDoer{handle: func(request *http.Request, _ string) (*http.Response, error) {
		return jsonResponse(request, http.StatusOK, `{"blob":{"$type":"blob","ref":{"$link":"`+wrongCID+`"},"mimeType":"message/rfc822","size":`+fmt.Sprint(len(raw))+`}}`), nil
	}}
	client := newTestClient(t, writer, &scriptedSource{})
	if _, err := client.UploadMessageBlob(context.Background(), raw); !errors.Is(err, mailbox.ErrIntegrity) {
		t.Fatalf("error = %v", err)
	}
}

func TestCreateBatchIsCreateOnlyValidateTrueAndChecksOfficialReceipts(t *testing.T) {
	value := json.RawMessage(`{"$type":"email.atmos.message","raw":{"$type":"blob","ref":{"$link":"` + testCID + `"},"mimeType":"message/rfc822","size":1},"sha256":"x","size":1,"deliveryFingerprint":"x","logicalMessageId":"x","initialMailbox":"Inbox"}`)
	writer := &scriptedDoer{handle: func(request *http.Request, endpoint string) (*http.Response, error) {
		if endpoint != applyWritesEndpoint || request.Method != http.MethodPost || request.URL.String() != "https://spaces.example/xrpc/"+applyWritesEndpoint || request.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("unexpected apply request: endpoint=%q method=%q url=%q", endpoint, request.Method, request.URL)
		}
		var input struct {
			Space    string `json:"space"`
			Repo     string `json:"repo"`
			Validate *bool  `json:"validate"`
			Writes   []struct {
				Type       string          `json:"$type"`
				Collection string          `json:"collection"`
				RKey       string          `json:"rkey"`
				Value      json.RawMessage `json:"value"`
			} `json:"writes"`
		}
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			t.Fatal(err)
		}
		if input.Space != testSpaceURI || input.Repo != testDID || input.Validate == nil || !*input.Validate || len(input.Writes) != 1 ||
			input.Writes[0].Type != createType || input.Writes[0].Collection != mailbox.MessageCollection || input.Writes[0].RKey != "one" || string(input.Writes[0].Value) != string(value) {
			t.Fatalf("input = %#v", input)
		}
		return jsonResponse(request, http.StatusOK, `{"results":[{"$type":"com.atproto.space.applyWrites#createResult","uri":"`+testSpaceURI+`/`+testDID+`/email.atmos.message/one","cid":"`+testCID+`","validationStatus":"valid"}]}`), nil
	}}
	client := newTestClient(t, writer, &scriptedSource{})
	results, err := client.CreateBatch(context.Background(), []Create{{Collection: mailbox.MessageCollection, RKey: "one", Value: value}})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].URI != testSpaceURI+"/"+testDID+"/email.atmos.message/one" || results[0].CID != testCID {
		t.Fatalf("results = %#v", results)
	}
}

func TestCreateBatchRejectsUnsafeInputsBeforeMemberOAuth(t *testing.T) {
	writer := &scriptedDoer{handle: func(*http.Request, string) (*http.Response, error) {
		t.Fatal("writer must not be called")
		return nil, nil
	}}
	client := newTestClient(t, writer, &scriptedSource{})
	tests := []struct {
		name    string
		creates []Create
	}{
		{name: "empty"},
		{name: "too many", creates: make([]Create, maxWrites+1)},
		{name: "legacy collection", creates: []Create{{Collection: mailbox.MessageStateCollection, RKey: "one", Value: json.RawMessage(`{"$type":"email.atmos.messageState"}`)}}},
		{name: "invalid key", creates: []Create{{Collection: mailbox.MessageCollection, RKey: "bad/key", Value: json.RawMessage(`{"$type":"email.atmos.message"}`)}}},
		{name: "wrong type", creates: []Create{{Collection: mailbox.MessageCollection, RKey: "one", Value: json.RawMessage(`{"$type":"email.atmos.folderRevision"}`)}}},
		{name: "missing type", creates: []Create{{Collection: mailbox.MessageCollection, RKey: "one", Value: json.RawMessage(`{"value":true}`)}}},
		{name: "invalid JSON", creates: []Create{{Collection: mailbox.MessageCollection, RKey: "one", Value: json.RawMessage(`{`)}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := client.CreateBatch(context.Background(), test.creates); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}

func TestCreateBatchRejectsUntrustedReceiptsWithoutLeakingBodies(t *testing.T) {
	value := json.RawMessage(`{"$type":"email.atmos.message"}`)
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "unknown validation", status: http.StatusOK, body: `{"results":[{"$type":"com.atproto.space.applyWrites#createResult","uri":"` + testSpaceURI + `/` + testDID + `/email.atmos.message/one","cid":"` + testCID + `","validationStatus":"unknown"}]}`},
		{name: "missing validation", status: http.StatusOK, body: `{"results":[{"$type":"com.atproto.space.applyWrites#createResult","uri":"` + testSpaceURI + `/` + testDID + `/email.atmos.message/one","cid":"` + testCID + `"}]}`},
		{name: "wrong result type", status: http.StatusOK, body: `{"results":[{"$type":"com.atproto.space.applyWrites#updateResult","uri":"` + testSpaceURI + `/` + testDID + `/email.atmos.message/one","cid":"` + testCID + `","validationStatus":"valid"}]}`},
		{name: "wrong author", status: http.StatusOK, body: `{"results":[{"$type":"com.atproto.space.applyWrites#createResult","uri":"` + testSpaceURI + `/did:plc:other/email.atmos.message/one","cid":"` + testCID + `","validationStatus":"valid"}]}`},
		{name: "invalid CID", status: http.StatusOK, body: `{"results":[{"$type":"com.atproto.space.applyWrites#createResult","uri":"` + testSpaceURI + `/` + testDID + `/email.atmos.message/one","cid":"not-a-cid","validationStatus":"valid"}]}`},
		{name: "unknown output field", status: http.StatusOK, body: `{"results":[],"secret":"DO-NOT-LEAK"}`},
		{name: "provider error", status: http.StatusBadRequest, body: `{"error":"UnknownLexicon","message":"DO-NOT-LEAK"}`},
		{name: "opaque error code", status: http.StatusBadRequest, body: `{"error":"abc.def:ghi","message":"synthetic"}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			writer := &scriptedDoer{handle: func(request *http.Request, _ string) (*http.Response, error) {
				return jsonResponse(request, test.status, test.body), nil
			}}
			client := newTestClient(t, writer, &scriptedSource{})
			if _, err := client.CreateBatch(context.Background(), []Create{{Collection: mailbox.MessageCollection, RKey: "one", Value: value}}); err == nil {
				t.Fatal("expected receipt rejection")
			} else if strings.Contains(err.Error(), "DO-NOT-LEAK") || strings.Contains(err.Error(), "abc.def:ghi") || strings.Contains(err.Error(), test.body) {
				t.Fatalf("error leaked provider body: %v", err)
			}
		})
	}
}

func TestReadsUseOneFreshCredentialPerOperationAndCloseIt(t *testing.T) {
	blobCID := testBlobCID(t, []byte("x"))
	reader := &scriptedSource{newDoer: func(call int) *scriptedDoer {
		return &scriptedDoer{handle: func(request *http.Request, endpoint string) (*http.Response, error) {
			switch call {
			case 1:
				if endpoint != getRecordEndpoint || request.URL.Query().Get("space") != testSpaceURI || request.URL.Query().Get("repo") != testDID || request.URL.Query().Get("collection") != mailbox.MessageCollection || request.URL.Query().Get("rkey") != "one" {
					t.Fatalf("unexpected getRecord request: %s endpoint=%q", request.URL, endpoint)
				}
				return jsonResponse(request, http.StatusOK, `{"uri":"`+testSpaceURI+`/`+testDID+`/email.atmos.message/one","cid":"`+testCID+`","value":{"$type":"email.atmos.message"}}`), nil
			case 2:
				if endpoint != getBlobEndpoint || request.URL.Query().Get("cid") != blobCID {
					t.Fatalf("unexpected getBlob request: %s endpoint=%q", request.URL, endpoint)
				}
				response := rawResponse(request, http.StatusOK, "message/rfc822", "x")
				return response, nil
			default:
				t.Fatalf("unexpected credential acquisition %d", call)
				return nil, nil
			}
		}}
	}}
	client := newTestClient(t, &scriptedDoer{}, reader)
	record, err := client.InspectRecord(context.Background(), mailbox.MessageCollection, "one")
	if err != nil {
		t.Fatal(err)
	}
	if record.URI != testSpaceURI+"/"+testDID+"/email.atmos.message/one" || record.CID != testCID || string(record.Value) != `{"$type":"email.atmos.message"}` {
		t.Fatalf("record = %#v", record)
	}
	blob, err := client.GetBlob(context.Background(), blobCID)
	if err != nil {
		t.Fatal(err)
	}
	if string(blob) != "x" || reader.acquired != 2 || reader.closed != 2 {
		t.Fatalf("blob=%q acquired=%d closed=%d", blob, reader.acquired, reader.closed)
	}
}

func TestListRecordsAndBlobsExhaustBoundedPagination(t *testing.T) {
	blobCID := testBlobCID(t, []byte("x"))
	reader := &scriptedSource{newDoer: func(call int) *scriptedDoer {
		return &scriptedDoer{handle: func(request *http.Request, endpoint string) (*http.Response, error) {
			cursor := request.URL.Query().Get("cursor")
			switch {
			case call == 1 && endpoint == listRecordsEndpoint && cursor == "":
				return jsonResponse(request, http.StatusOK, `{"cursor":"`+testSpaceURI+`/`+testDID+`/email.atmos.message/one","records":[{"collection":"email.atmos.message","rkey":"one","cid":"`+testCID+`","value":{"$type":"email.atmos.message"}}]}`), nil
			case call == 1 && endpoint == listRecordsEndpoint && cursor == testSpaceURI+"/"+testDID+"/email.atmos.message/one":
				return jsonResponse(request, http.StatusOK, `{"records":[]}`), nil
			case call == 2 && endpoint == listBlobsEndpoint && cursor == "":
				return jsonResponse(request, http.StatusOK, `{"cids":["`+blobCID+`"]}`), nil
			default:
				t.Fatalf("unexpected paged request call=%d endpoint=%q cursor=%q", call, endpoint, cursor)
				return nil, nil
			}
		}}
	}}
	client := newTestClient(t, &scriptedDoer{}, reader)
	records, err := client.InspectRecords(context.Background(), mailbox.MessageCollection, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].URI != testSpaceURI+"/"+testDID+"/email.atmos.message/one" {
		t.Fatalf("records = %#v", records)
	}
	cids, err := client.ListBlobs(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if len(cids) != 1 || cids[0] != blobCID || reader.acquired != 2 || reader.closed != 2 {
		t.Fatalf("cids=%v acquired=%d closed=%d", cids, reader.acquired, reader.closed)
	}
}

func TestInspectRecordsRejectsMissingRequiredInventory(t *testing.T) {
	reader := &scriptedSource{newDoer: func(int) *scriptedDoer {
		return &scriptedDoer{handle: func(request *http.Request, _ string) (*http.Response, error) {
			return jsonResponse(request, http.StatusOK, `{}`), nil
		}}
	}}
	client := newTestClient(t, &scriptedDoer{}, reader)
	if _, err := client.InspectRecords(context.Background(), mailbox.MessageCollection, true); !errors.Is(err, mailbox.ErrIntegrity) {
		t.Fatalf("error = %v", err)
	}
	if reader.closed != 1 {
		t.Fatalf("closed = %d", reader.closed)
	}
}

func TestStreamRepoKeepsCredentialScopedToConsumer(t *testing.T) {
	reader := &scriptedSource{newDoer: func(int) *scriptedDoer {
		return &scriptedDoer{handle: func(request *http.Request, endpoint string) (*http.Response, error) {
			if endpoint != getRepoEndpoint || request.URL.Query().Get("space") != testSpaceURI || request.URL.Query().Get("repo") != testDID || request.URL.Query().Get("excludeValues") != "true" {
				t.Fatalf("unexpected getRepo request: %s endpoint=%q", request.URL, endpoint)
			}
			return rawResponse(request, http.StatusOK, "application/vnd.ipld.car", "synthetic-car"), nil
		}}
	}}
	client := newTestClient(t, &scriptedDoer{}, reader)
	var got string
	err := client.StreamRepo(context.Background(), true, func(input io.Reader) error {
		if reader.closed != 0 {
			t.Fatal("credential closed before CAR consumer returned")
		}
		data, err := io.ReadAll(input)
		got = string(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if got != "synthetic-car" || reader.closed != 1 {
		t.Fatalf("got=%q closed=%d", got, reader.closed)
	}
}

func TestStreamRepoRejectsConsumerThatDoesNotExhaustSnapshot(t *testing.T) {
	reader := &scriptedSource{newDoer: func(int) *scriptedDoer {
		return &scriptedDoer{handle: func(request *http.Request, _ string) (*http.Response, error) {
			return rawResponse(request, http.StatusOK, "application/vnd.ipld.car", "synthetic-car"), nil
		}}
	}}
	client := newTestClient(t, &scriptedDoer{}, reader)
	if err := client.StreamRepo(context.Background(), false, func(io.Reader) error { return nil }); !errors.Is(err, mailbox.ErrIntegrity) {
		t.Fatalf("error = %v", err)
	}
	if reader.closed != 1 {
		t.Fatalf("closed = %d", reader.closed)
	}
}

func TestReadRejectsResponseTargetDriftAndStillClosesCredential(t *testing.T) {
	reader := &scriptedSource{newDoer: func(int) *scriptedDoer {
		return &scriptedDoer{handle: func(request *http.Request, _ string) (*http.Response, error) {
			drifted, _ := http.NewRequest(http.MethodGet, "https://evil.example/xrpc/com.atproto.space.getRecord", nil)
			return jsonResponse(drifted, http.StatusOK, `{"uri":"x","cid":"x","value":{}}`), nil
		}}
	}}
	client := newTestClient(t, &scriptedDoer{}, reader)
	if _, err := client.InspectRecord(context.Background(), mailbox.MessageCollection, "one"); !errors.Is(err, repository.ErrTarget) {
		t.Fatalf("error = %v", err)
	}
	if reader.closed != 1 {
		t.Fatalf("closed = %d", reader.closed)
	}
}

func TestReadClosesCredentialReturnedAlongsideAcquireError(t *testing.T) {
	reader := &scriptedSource{acquireErr: fmt.Errorf("DO-NOT-LEAK: %w", repository.ErrRevoked)}
	client := newTestClient(t, &scriptedDoer{}, reader)
	if _, err := client.InspectRecord(context.Background(), mailbox.MessageCollection, "one"); !errors.Is(err, repository.ErrRevoked) || strings.Contains(err.Error(), "DO-NOT-LEAK") {
		t.Fatalf("error = %v", err)
	}
	if reader.closed != 1 {
		t.Fatalf("closed = %d", reader.closed)
	}
}

func TestWriteClosesCapabilityReturnedAlongsideReauthorizationError(t *testing.T) {
	source := &scriptedWriterSource{
		doer: &scriptedDoer{handle: func(*http.Request, string) (*http.Response, error) {
			t.Fatal("writer must not be used")
			return nil, nil
		}},
		acquireErr: fmt.Errorf("DO-NOT-LEAK: %w", ErrReauthorizationRequired),
	}
	client, err := New(Config{
		Origin: "https://spaces.example", SpaceAuthorityDID: testSpaceDID, RepoDID: testDID, SpaceKey: "primary", Epoch: PinnedEpoch,
	}, source, &scriptedSource{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.UploadMessageBlob(context.Background(), []byte("synthetic")); !errors.Is(err, ErrReauthorizationRequired) || strings.Contains(err.Error(), "DO-NOT-LEAK") {
		t.Fatalf("error = %v", err)
	}
	if source.acquired != 1 || source.closed != 1 {
		t.Fatalf("acquired=%d closed=%d", source.acquired, source.closed)
	}
}

func newTestClient(t *testing.T, writer *scriptedDoer, reader CredentialSource) *Client {
	t.Helper()
	client, err := New(Config{
		Origin: "https://spaces.example", SpaceAuthorityDID: testSpaceDID, RepoDID: testDID, SpaceKey: "primary", Epoch: PinnedEpoch,
	}, &scriptedWriterSource{doer: writer}, reader)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

type scriptedDoer struct {
	handle func(*http.Request, string) (*http.Response, error)
	closed func()
}

func (d *scriptedDoer) Do(_ context.Context, request *http.Request, endpoint string) (*http.Response, error) {
	if d.handle == nil {
		return nil, errors.New("unexpected authenticated request")
	}
	return d.handle(request, endpoint)
}

func (d *scriptedDoer) Close() {
	if d.closed != nil {
		d.closed()
	}
}

type scriptedSource struct {
	newDoer    func(int) *scriptedDoer
	acquireErr error
	acquired   int
	closed     int
}

func (s *scriptedSource) AcquireReader(_ context.Context, target Target) (ScopedDoer, error) {
	if target.Origin != "https://spaces.example" || target.SpaceURI != testSpaceURI || target.RepoDID != testDID || target.Epoch != PinnedEpoch {
		return nil, repository.ErrTarget
	}
	s.acquired++
	if s.newDoer == nil {
		return &scriptedDoer{closed: func() { s.closed++ }}, s.acquireErr
	}
	doer := s.newDoer(s.acquired)
	doer.closed = func() { s.closed++ }
	return doer, s.acquireErr
}

type scriptedWriterSource struct {
	doer       *scriptedDoer
	acquireErr error
	acquired   int
	closed     int
}

func (s *scriptedWriterSource) AcquireWriter(_ context.Context, target Target) (ScopedDoer, error) {
	if target.Origin != "https://spaces.example" || target.SpaceURI != testSpaceURI || target.RepoDID != testDID || target.Epoch != PinnedEpoch {
		return nil, repository.ErrTarget
	}
	s.acquired++
	doer := s.doer
	if doer == nil {
		doer = &scriptedDoer{}
	}
	doer.closed = func() { s.closed++ }
	return doer, s.acquireErr
}

func jsonResponse(request *http.Request, status int, body string) *http.Response {
	return rawResponse(request, status, "application/json", body)
}

func rawResponse(request *http.Request, status int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {contentType}},
		Request:    request,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func testBlobCID(t *testing.T, data []byte) string {
	t.Helper()
	value, err := (cidlib.Prefix{Version: 1, Codec: cidlib.Raw, MhType: multihash.SHA2_256, MhLength: 32}).Sum(data)
	if err != nil {
		t.Fatal(err)
	}
	return value.String()
}
