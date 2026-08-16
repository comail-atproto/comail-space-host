package memory

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/comail-atproto/comail-pds-lab/internal/mailbox"
	"github.com/comail-atproto/comail-pds-lab/internal/repository"
)

const alice = "did:plc:alice"

func createPair(t *testing.T, ctx context.Context, repo repository.Repository, target repository.Target, raw []byte) mailbox.MessagePair {
	t.Helper()
	blob, err := repo.UploadBlob(ctx, target, raw, mailbox.MessageMIMEType)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := mailbox.NewMessagePair(mailbox.ImportedMessage{RecipientDID: alice, Raw: raw, Mailbox: "INBOX"}, blob)
	if err != nil {
		t.Fatal(err)
	}
	return pair
}

func TestRepositoryRoundTripAndCAS(t *testing.T) {
	ctx := context.Background()
	backend := NewBackend()
	repo := backend.OwnerSession(alice)
	target, err := repo.EnsureMailbox(ctx, alice, "primary")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: sender@example.com\r\n\r\nhello\r\n")
	pair := createPair(t, ctx, repo, target, raw)
	commit, err := repo.ApplyWrites(ctx, target, []repository.Write{
		{Action: repository.Create, Collection: mailbox.MessageCollection, RKey: pair.RKey, Value: pair.Message},
		{Action: repository.Create, Collection: mailbox.MessageStateCollection, RKey: pair.RKey, Value: pair.State},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(commit.Results) != 2 || commit.Results[0].CID == "" || commit.Rev == "" {
		t.Fatalf("commit = %#v", commit)
	}
	record, err := repo.GetRecord(ctx, target, mailbox.MessageCollection, pair.RKey)
	if err != nil {
		t.Fatal(err)
	}
	gotRaw, err := repo.GetBlob(ctx, target, pair.Message.Raw.Ref.Link)
	if err != nil {
		t.Fatal(err)
	}
	var got mailbox.MessageRecord
	if err := json.Unmarshal(record.Value, &got); err != nil {
		t.Fatal(err)
	}
	if err := mailbox.ValidateStoredMessage(alice, pair.RKey, got, gotRaw); err != nil {
		t.Fatal(err)
	}
	stateRecord, err := repo.GetRecord(ctx, target, mailbox.MessageStateCollection, pair.RKey)
	if err != nil {
		t.Fatal(err)
	}
	pair.State.Keywords = []string{"$seen"}
	pair.State.Revision++
	updated, err := repo.PutRecordCAS(ctx, target, mailbox.MessageStateCollection, pair.RKey, pair.State, stateRecord.CID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.CID == stateRecord.CID {
		t.Fatal("CAS update did not change record CID")
	}
	if _, err := repo.PutRecordCAS(ctx, target, mailbox.MessageStateCollection, pair.RKey, pair.State, stateRecord.CID); !errors.Is(err, repository.ErrConflict) {
		t.Fatalf("stale CAS error = %v", err)
	}
}

func TestApplyWritesIsAtomic(t *testing.T) {
	ctx := context.Background()
	repo := NewBackend().OwnerSession(alice)
	target, err := repo.EnsureMailbox(ctx, alice, "primary")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("Subject: atomic\r\n\r\nbody\r\n")
	pair := createPair(t, ctx, repo, target, raw)
	missingBlob := pair.Message
	missingBlob.Raw.Ref.Link = "bafk-missing"
	_, err = repo.ApplyWrites(ctx, target, []repository.Write{
		{Action: repository.Create, Collection: mailbox.MessageCollection, RKey: pair.RKey, Value: pair.Message},
		{Action: repository.Create, Collection: mailbox.MessageCollection, RKey: pair.RKey + "-bad", Value: missingBlob},
	})
	if err == nil {
		t.Fatal("batch with missing blob succeeded")
	}
	if records, err := repo.ListRecords(ctx, target, mailbox.MessageCollection); err != nil || len(records) != 0 {
		t.Fatalf("partial batch was visible: records=%d err=%v", len(records), err)
	}
}

func TestBlobAccessIsReferenceAndSpaceBound(t *testing.T) {
	ctx := context.Background()
	backend := NewBackend()
	owner := backend.OwnerSession(alice)
	primary, err := owner.EnsureMailbox(ctx, alice, "primary")
	if err != nil {
		t.Fatal(err)
	}
	secondary, err := owner.EnsureMailbox(ctx, alice, "secondary")
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("Subject: isolated\r\n\r\nprivate\r\n")
	pair := createPair(t, ctx, owner, primary, raw)
	if _, err := owner.ApplyWrites(ctx, primary, []repository.Write{{Action: repository.Create, Collection: mailbox.MessageCollection, RKey: pair.RKey, Value: pair.Message}}); err != nil {
		t.Fatal(err)
	}
	primaryReader := backend.SpaceCredentialSession("did:web:comail.at", primary.SpaceURI)
	secondaryReader := backend.SpaceCredentialSession("did:web:comail.at", secondary.SpaceURI)
	if got, err := primaryReader.GetBlob(ctx, primary, pair.Message.Raw.Ref.Link); err != nil || string(got) != string(raw) {
		t.Fatalf("authorized blob read: len=%d err=%v", len(got), err)
	}
	if _, err := secondaryReader.GetBlob(ctx, secondary, pair.Message.Raw.Ref.Link); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("known CID escaped into another space: %v", err)
	}
	if _, err := secondaryReader.GetBlob(ctx, primary, pair.Message.Raw.Ref.Link); !errors.Is(err, repository.ErrUnauthorized) {
		t.Fatalf("wrong-space credential opened primary: %v", err)
	}
	unreferenced, err := owner.UploadBlob(ctx, primary, []byte("orphan"), "application/octet-stream")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := primaryReader.GetBlob(ctx, primary, unreferenced.Ref.Link); !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("unreferenced blob was served: %v", err)
	}
}

func TestWrongRepoAndRevokedSessionFailClosed(t *testing.T) {
	ctx := context.Background()
	backend := NewBackend()
	owner := backend.OwnerSession(alice)
	target, err := owner.EnsureMailbox(ctx, alice, "primary")
	if err != nil {
		t.Fatal(err)
	}
	bob := backend.OwnerSession("did:plc:bob")
	if _, err := bob.UploadBlob(ctx, target, []byte("x"), "application/octet-stream"); !errors.Is(err, repository.ErrUnauthorized) {
		t.Fatalf("wrong repo upload error = %v", err)
	}
	owner.Revoke()
	if _, err := owner.ListRecords(ctx, target, mailbox.MessageCollection); !errors.Is(err, repository.ErrRevoked) {
		t.Fatalf("revoked read error = %v", err)
	}
}
