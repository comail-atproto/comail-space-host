package officialspaces

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"sort"
	"testing"

	"github.com/bluesky-social/indigo/atproto/atcrypto"
	"github.com/bluesky-social/indigo/atproto/syntax"
	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/repository"
)

func TestStreamMessageBlobsUsesOneExactReaderAndEphemeralBuffers(t *testing.T) {
	raw := [][]byte{[]byte("synthetic one"), []byte("synthetic two")}
	cids := []string{testBlobCID(t, raw[0]), testBlobCID(t, raw[1])}
	blobs := map[string][]byte{cids[0]: raw[0], cids[1]: raw[1]}
	sort.Strings(cids)
	fixture := newRepoFixture(t)
	reader := &scriptedSource{newDoer: func(int) *scriptedDoer {
		calls := 0
		return &scriptedDoer{handle: func(request *http.Request, endpoint string) (*http.Response, error) {
			switch calls {
			case 0, 3:
				if endpoint != getLatestCommitEndpoint {
					t.Fatalf("call=%d endpoint=%q", calls, endpoint)
				}
				calls++
				return jsonResponse(request, http.StatusOK, fixture.latestJSON), nil
			case 1, 2:
				blobIndex := calls - 1
				if endpoint != getBlobEndpoint || request.URL.Query().Get("cid") != cids[blobIndex] {
					t.Fatalf("call=%d endpoint=%q URL=%s", calls, endpoint, request.URL)
				}
				response := rawBytesResponse(request, http.StatusOK, mailbox.MessageMIMEType, blobs[cids[blobIndex]])
				calls++
				return response, nil
			default:
				t.Fatalf("unexpected call=%d", calls)
				return nil, nil
			}
		}}
	}}
	client := newTestClient(t, &scriptedDoer{}, reader)
	client.repoKeys = staticRepoKeyResolver{key: fixture.publicKey}
	source := syntheticBlobSource(client, fixture)
	var received [][]byte
	var borrowed []byte
	err := client.StreamSourceMessageBlobs(context.Background(), source, cids, func(index int, gotCID string, data []byte) error {
		if index != len(received) || gotCID != cids[index] {
			t.Fatalf("index=%d CID=%q", index, gotCID)
		}
		borrowed = data
		received = append(received, bytes.Clone(data))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if reader.acquired != 1 || reader.closed != 1 || !bytes.Equal(received[0], blobs[cids[0]]) || !bytes.Equal(received[1], blobs[cids[1]]) {
		t.Fatalf("acquired=%d closed=%d received=%q", reader.acquired, reader.closed, received)
	}
	if !bytes.Equal(borrowed, make([]byte, len(borrowed))) {
		t.Fatal("borrowed blob buffer was not cleared after callback")
	}
}

func TestStreamMessageBlobsRejectsTargetContentAndConsumerFailure(t *testing.T) {
	raw := []byte("synthetic blob")
	cid := testBlobCID(t, raw)
	fixture := newRepoFixture(t)
	reader := &scriptedSource{newDoer: func(int) *scriptedDoer {
		calls := 0
		return &scriptedDoer{handle: func(request *http.Request, endpoint string) (*http.Response, error) {
			calls++
			if calls == 1 || calls == 3 {
				return jsonResponse(request, http.StatusOK, fixture.latestJSON), nil
			}
			if endpoint != getBlobEndpoint {
				t.Fatalf("endpoint=%q", endpoint)
			}
			return rawBytesResponse(request, http.StatusOK, mailbox.MessageMIMEType, raw), nil
		}}
	}}
	client := newTestClient(t, &scriptedDoer{}, reader)
	client.repoKeys = staticRepoKeyResolver{key: fixture.publicKey}
	source := syntheticBlobSource(client, fixture)

	for _, mutate := range []func(*Target){
		func(target *Target) { target.Origin = "https://other.example" },
		func(target *Target) { target.SpaceURI += "-other" },
		func(target *Target) { target.RepoDID = "did:plc:cccccccccccccccccccccccc" },
		func(target *Target) { target.Epoch = "other" },
	} {
		wrongTarget := syntheticBlobSource(client, fixture)
		mutate(&wrongTarget.target)
		wrongTarget.seal = wrongTarget.snapshotSeal()
		if err := client.StreamSourceMessageBlobs(context.Background(), wrongTarget, []string{cid}, func(int, string, []byte) error { return nil }); !errors.Is(err, repository.ErrTarget) {
			t.Fatalf("wrong target error=%v", err)
		}
	}
	if reader.acquired != 0 {
		t.Fatalf("reader acquired for wrong target: %d", reader.acquired)
	}

	secret := errors.New("secret-record-key")
	if err := client.StreamSourceMessageBlobs(context.Background(), source, []string{cid}, func(int, string, []byte) error { return secret }); err == nil || errors.Is(err, secret) || err.Error() == secret.Error() {
		t.Fatalf("consumer error was not redacted: %v", err)
	}

	badReader := &scriptedSource{newDoer: func(int) *scriptedDoer {
		calls := 0
		return &scriptedDoer{handle: func(request *http.Request, _ string) (*http.Response, error) {
			calls++
			if calls == 1 {
				return jsonResponse(request, http.StatusOK, fixture.latestJSON), nil
			}
			return rawBytesResponse(request, http.StatusOK, mailbox.MessageMIMEType, []byte("substituted")), nil
		}}
	}}
	badClient := newTestClient(t, &scriptedDoer{}, badReader)
	badClient.repoKeys = staticRepoKeyResolver{key: fixture.publicKey}
	badSource := syntheticBlobSource(badClient, fixture)
	called := false
	if err := badClient.StreamSourceMessageBlobs(context.Background(), badSource, []string{cid}, func(int, string, []byte) error {
		called = true
		return nil
	}); !errors.Is(err, mailbox.ErrIntegrity) || called {
		t.Fatalf("substituted blob error=%v called=%t", err, called)
	}
}

func TestStreamMessageBlobsRejectsStaleSourceAndAggregateLimit(t *testing.T) {
	raw := []byte("synthetic blob")
	blobCID := testBlobCID(t, raw)
	fixture := newRepoFixture(t)
	reader := &scriptedSource{newDoer: func(int) *scriptedDoer {
		calls := 0
		return &scriptedDoer{handle: func(request *http.Request, _ string) (*http.Response, error) {
			calls++
			if calls == 1 || calls == 3 {
				return jsonResponse(request, http.StatusOK, fixture.latestJSON), nil
			}
			return rawBytesResponse(request, http.StatusOK, mailbox.MessageMIMEType, raw), nil
		}}
	}}
	client := newTestClient(t, &scriptedDoer{}, reader)
	client.repoKeys = staticRepoKeyResolver{key: fixture.publicKey}
	stale := syntheticBlobSource(client, fixture)
	stale.repoHash[0] ^= 0xff
	stale.seal = stale.snapshotSeal()
	called := false
	if err := client.StreamSourceMessageBlobs(context.Background(), stale, []string{blobCID}, func(int, string, []byte) error {
		called = true
		return nil
	}); !errors.Is(err, ErrSnapshotVerification) || called {
		t.Fatalf("stale source error=%v called=%t", err, called)
	}

	current := syntheticBlobSource(client, fixture)
	if err := client.streamSourceMessageBlobs(context.Background(), current, []string{blobCID}, int64(len(raw)-1), func(int, string, []byte) error {
		called = true
		return nil
	}); !errors.Is(err, mailbox.ErrMessageTooLarge) {
		t.Fatalf("aggregate limit error=%v", err)
	}
	if reader.acquired != 2 || reader.closed != 2 {
		t.Fatalf("acquired=%d closed=%d", reader.acquired, reader.closed)
	}
}

func TestStreamMessageBlobsRejectsPDSMoveBeforeCredentialAcquisition(t *testing.T) {
	fixture := newRepoFixture(t)
	reader := &scriptedSource{}
	client := newTestClient(t, &scriptedDoer{}, reader)
	client.repoKeys = wrongHostRepoKeyResolver{staticRepoKeyResolver{key: fixture.publicKey}}
	source := syntheticBlobSource(client, fixture)
	if err := client.StreamSourceMessageBlobs(
		context.Background(), source, []string{testBlobCID(t, []byte("x"))},
		func(int, string, []byte) error { return nil },
	); !errors.Is(err, repository.ErrTarget) {
		t.Fatalf("moved PDS error=%v", err)
	}
	if reader.acquired != 0 {
		t.Fatalf("reader acquired after PDS move: %d", reader.acquired)
	}
}

func TestStreamMessageBlobsRejectsMalformedInputAndCancellation(t *testing.T) {
	reader := &scriptedSource{}
	client := newTestClient(t, &scriptedDoer{}, reader)
	fixture := newRepoFixture(t)
	client.repoKeys = staticRepoKeyResolver{key: fixture.publicKey}
	source := syntheticBlobSource(client, fixture)
	consume := func(int, string, []byte) error { return nil }
	if err := client.StreamSourceMessageBlobs(context.Background(), source, []string{"not-a-cid"}, consume); !errors.Is(err, mailbox.ErrInvalidRecord) {
		t.Fatalf("malformed CID error=%v", err)
	}
	if err := client.StreamSourceMessageBlobs(context.Background(), source, nil, nil); !errors.Is(err, mailbox.ErrInvalidRecord) {
		t.Fatalf("nil consumer error=%v", err)
	}
	cids := []string{testBlobCID(t, []byte("one")), testBlobCID(t, []byte("two"))}
	sort.Strings(cids)
	if err := client.StreamSourceMessageBlobs(context.Background(), source, []string{cids[1], cids[0]}, consume); !errors.Is(err, mailbox.ErrInvalidRecord) {
		t.Fatalf("unsorted CIDs error=%v", err)
	}
	if err := client.StreamSourceMessageBlobs(context.Background(), source, []string{cids[0], cids[0]}, consume); !errors.Is(err, mailbox.ErrInvalidRecord) {
		t.Fatalf("duplicate CIDs error=%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := client.StreamSourceMessageBlobs(ctx, source, []string{testBlobCID(t, []byte("x"))}, consume); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled error=%v", err)
	}
	if reader.acquired != 0 {
		t.Fatalf("reader acquired for invalid input: %d", reader.acquired)
	}
}

func TestStreamMessageBlobsRejectsPDSMoveAfterSourceAcquisitionBeforeBlobAuthentication(t *testing.T) {
	fixture := newRepoFixture(t)
	reader := &scriptedSource{newDoer: func(acquisition int) *scriptedDoer {
		if acquisition != 1 {
			t.Fatalf("unexpected credential acquisition=%d", acquisition)
		}
		calls := 0
		return &scriptedDoer{handle: func(request *http.Request, endpoint string) (*http.Response, error) {
			calls++
			switch calls {
			case 1, 3:
				return jsonResponse(request, http.StatusOK, fixture.latestJSON), nil
			case 2:
				if endpoint != getRepoEndpoint {
					t.Fatalf("endpoint=%q", endpoint)
				}
				return rawBytesResponse(request, http.StatusOK, "application/vnd.ipld.car", fixture.car), nil
			default:
				t.Fatalf("unexpected call=%d", calls)
				return nil, nil
			}
		}}
	}}
	client := newTestClient(t, &scriptedDoer{}, reader)
	resolver := &switchingRepoResolver{staticRepoKeyResolver: staticRepoKeyResolver{key: fixture.publicKey}}
	client.repoKeys = resolver
	source, err := client.ReadSourceAuthenticatedRepository(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	resolver.moved = true
	err = client.StreamSourceMessageBlobs(
		context.Background(), source, []string{testBlobCID(t, []byte("synthetic"))},
		func(int, string, []byte) error { return nil },
	)
	if !errors.Is(err, repository.ErrTarget) || reader.acquired != 1 || reader.closed != 1 {
		t.Fatalf("error=%v acquired=%d closed=%d", err, reader.acquired, reader.closed)
	}
}

func TestStreamMessageBlobsRejectsInvalidResponsesAndClosesReader(t *testing.T) {
	validRaw := []byte("synthetic expected blob")
	oversized := bytes.Repeat([]byte{'x'}, int(mailbox.MaxRawMessageBytes)+1)
	tests := []struct {
		name        string
		blobCID     string
		contentType string
		body        []byte
		want        error
	}{
		{name: "wrong media type", blobCID: testBlobCID(t, validRaw), contentType: "application/octet-stream", body: validRaw, want: mailbox.ErrIntegrity},
		{name: "empty", blobCID: testBlobCID(t, validRaw), contentType: mailbox.MessageMIMEType, body: nil, want: mailbox.ErrIntegrity},
		{name: "oversized", blobCID: testBlobCID(t, oversized), contentType: mailbox.MessageMIMEType, body: oversized, want: mailbox.ErrMessageTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newRepoFixture(t)
			reader := &scriptedSource{newDoer: func(int) *scriptedDoer {
				calls := 0
				return &scriptedDoer{handle: func(request *http.Request, endpoint string) (*http.Response, error) {
					calls++
					if calls == 1 {
						return jsonResponse(request, http.StatusOK, fixture.latestJSON), nil
					}
					if calls != 2 || endpoint != getBlobEndpoint {
						t.Fatalf("call=%d endpoint=%q", calls, endpoint)
					}
					return rawBytesResponse(request, http.StatusOK, test.contentType, test.body), nil
				}}
			}}
			client := newTestClient(t, &scriptedDoer{}, reader)
			client.repoKeys = staticRepoKeyResolver{key: fixture.publicKey}
			source := syntheticBlobSource(client, fixture)
			called := false
			err := client.StreamSourceMessageBlobs(context.Background(), source, []string{test.blobCID}, func(int, string, []byte) error {
				called = true
				return nil
			})
			if !errors.Is(err, test.want) || called || reader.acquired != 1 || reader.closed != 1 {
				t.Fatalf("error=%v called=%t acquired=%d closed=%d", err, called, reader.acquired, reader.closed)
			}
		})
	}
}

func TestStreamMessageBlobsHonorsCancellationBetweenRequests(t *testing.T) {
	raw := [][]byte{[]byte("synthetic one"), []byte("synthetic two")}
	cids := []string{testBlobCID(t, raw[0]), testBlobCID(t, raw[1])}
	blobs := map[string][]byte{cids[0]: raw[0], cids[1]: raw[1]}
	sort.Strings(cids)
	fixture := newRepoFixture(t)
	reader := &scriptedSource{newDoer: func(int) *scriptedDoer {
		calls := 0
		return &scriptedDoer{handle: func(request *http.Request, endpoint string) (*http.Response, error) {
			calls++
			switch calls {
			case 1:
				return jsonResponse(request, http.StatusOK, fixture.latestJSON), nil
			case 2:
				if endpoint != getBlobEndpoint || request.URL.Query().Get("cid") != cids[0] {
					t.Fatalf("endpoint=%q URL=%s", endpoint, request.URL)
				}
				return rawBytesResponse(request, http.StatusOK, mailbox.MessageMIMEType, blobs[cids[0]]), nil
			default:
				t.Fatalf("unexpected call=%d", calls)
				return nil, nil
			}
		}}
	}}
	client := newTestClient(t, &scriptedDoer{}, reader)
	client.repoKeys = staticRepoKeyResolver{key: fixture.publicKey}
	ctx, cancel := context.WithCancel(context.Background())
	visits := 0
	err := client.StreamSourceMessageBlobs(ctx, syntheticBlobSource(client, fixture), cids, func(int, string, []byte) error {
		visits++
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) || visits != 1 || reader.acquired != 1 || reader.closed != 1 {
		t.Fatalf("error=%v visits=%d acquired=%d closed=%d", err, visits, reader.acquired, reader.closed)
	}
}

func syntheticBlobSource(client *Client, fixture repoFixture) *SourceAuthenticatedRepository {
	source := &SourceAuthenticatedRepository{
		target: client.target, revision: fixture.commit.Revision, snapshotID: "synthetic-snapshot",
		commitCID: "synthetic-commit", indexCID: "synthetic-index",
		repoHash: append([]byte(nil), fixture.commit.Hash...),
	}
	source.seal = source.snapshotSeal()
	return source
}

type switchingRepoResolver struct {
	staticRepoKeyResolver
	moved bool
}

func (r *switchingRepoResolver) ResolveRepoSource(ctx context.Context, did syntax.DID, force bool) (string, atcrypto.PublicKey, error) {
	host, key, err := r.staticRepoKeyResolver.ResolveRepoSource(ctx, did, force)
	if r.moved {
		host = "https://moved.example"
	}
	return host, key, err
}
