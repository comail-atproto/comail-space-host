package mailboxstate

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/memory"
	"github.com/comail-atproto/comail-space-host/internal/repository"
)

func TestApplyPersistsConflictSafeMailboxState(t *testing.T) {
	ctx := context.Background()
	did := "did:plc:stateauthority"
	repo := memory.NewBackend().OwnerSession(did)
	target, rkey := seedMessage(t, repo, did)
	now := time.Date(2026, 8, 16, 20, 0, 0, 0, time.UTC)

	updated, err := Apply(ctx, repo, target, Mutation{
		MessageRKey: rkey, ExpectedRevision: 1, OperationID: "op-read-1", Operation: MarkRead, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if updated.Revision != 2 || updated.UpdatedAt != now.Format(time.RFC3339Nano) || !contains(updated.Keywords, "$seen") {
		t.Fatalf("updated state = %#v", updated)
	}

	_, err = Apply(ctx, repo, target, Mutation{
		MessageRKey: rkey, ExpectedRevision: 1, OperationID: "op-flag-stale", Operation: Flag, Now: now.Add(time.Second),
	})
	if !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("stale update error = %v", err)
	}

	updated, err = Apply(ctx, repo, target, Mutation{
		MessageRKey: rkey, ExpectedRevision: 2, OperationID: "op-move-1", Operation: Move, Mailbox: "Archive", Now: now.Add(2 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.MailboxIDs) != 1 || updated.MailboxIDs[0] != mailbox.FolderRKey("Archive") || updated.Revision != 3 {
		t.Fatalf("moved state = %#v", updated)
	}

	updated, err = Apply(ctx, repo, target, Mutation{
		MessageRKey: rkey, ExpectedRevision: 3, OperationID: "op-delete-1", Operation: Tombstone, Now: now.Add(3 * time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !updated.Tombstone || updated.DeletePending || updated.Revision != 4 {
		t.Fatalf("tombstone state = %#v", updated)
	}
	replayed, err := Apply(ctx, repo, target, Mutation{
		MessageRKey: rkey, ExpectedRevision: 3, OperationID: "op-delete-1", Operation: Tombstone, Now: now.Add(4 * time.Second),
	})
	if err != nil || replayed.Revision != 4 || replayed.UpdatedAt != updated.UpdatedAt {
		t.Fatalf("idempotent replay = %#v, %v", replayed, err)
	}
}

func TestApplyRejectsUnknownFolderAndInvalidMutation(t *testing.T) {
	ctx := context.Background()
	did := "did:plc:stateinvalid"
	repo := memory.NewBackend().OwnerSession(did)
	target, rkey := seedMessage(t, repo, did)

	for _, mutation := range []Mutation{
		{MessageRKey: rkey, ExpectedRevision: 1, OperationID: "op-a", Operation: Move, Mailbox: "Missing", Now: time.Now()},
		{MessageRKey: rkey, ExpectedRevision: 1, OperationID: "op-b", Operation: "surprise", Now: time.Now()},
		{MessageRKey: "other", ExpectedRevision: 1, OperationID: "op-c", Operation: MarkRead, Now: time.Now()},
		{MessageRKey: rkey, ExpectedRevision: 1, Operation: MarkRead, Now: time.Now()},
	} {
		if _, err := Apply(ctx, repo, target, mutation); err == nil {
			t.Fatalf("accepted mutation %#v", mutation)
		}
	}
}

func TestApplyMapsRepositoryCASConflict(t *testing.T) {
	ctx := context.Background()
	did := "did:plc:stateconflict"
	base := memory.NewBackend().OwnerSession(did)
	target, rkey := seedMessage(t, base, did)
	repo := &conflictingRepository{Repository: base}

	_, err := Apply(ctx, repo, target, Mutation{
		MessageRKey: rkey, ExpectedRevision: 1, OperationID: "op-conflict", Operation: MarkRead, Now: time.Now(),
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("CAS conflict error = %v", err)
	}
}

type conflictingRepository struct{ repository.Repository }

func (r *conflictingRepository) PutRecordCAS(context.Context, repository.Target, string, string, any, string) (repository.Record, error) {
	return repository.Record{}, repository.ErrConflict
}

func seedMessage(t *testing.T, repo repository.Repository, did string) (repository.Target, string) {
	t.Helper()
	ctx := context.Background()
	target, err := repo.EnsureMailbox(ctx, did, "primary")
	if err != nil {
		t.Fatal(err)
	}
	inbox := mailbox.NewFolder("INBOX", "inbox", mailbox.StableUIDValidity(did, "INBOX"))
	archive := mailbox.NewFolder("Archive", "archive", mailbox.StableUIDValidity(did, "Archive"))
	if _, err := repo.ApplyWrites(ctx, target, []repository.Write{
		{Action: repository.Create, Collection: mailbox.FolderCollection, RKey: inbox.RKey, Value: inbox.Record},
		{Action: repository.Create, Collection: mailbox.FolderCollection, RKey: archive.RKey, Value: archive.Record},
	}); err != nil {
		t.Fatal(err)
	}
	raw := []byte("From: sender@example.test\r\nSubject: state\r\n\r\nbody\r\n")
	blob, err := repo.UploadBlob(ctx, target, raw, mailbox.MessageMIMEType)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := mailbox.NewMessagePair(mailbox.ImportedMessage{RecipientDID: did, Raw: raw, Mailbox: "INBOX"}, blob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ApplyWrites(ctx, target, []repository.Write{
		{Action: repository.Create, Collection: mailbox.MessageCollection, RKey: pair.RKey, Value: pair.Message},
		{Action: repository.Create, Collection: mailbox.MessageStateCollection, RKey: pair.RKey, Value: pair.State},
	}); err != nil {
		t.Fatal(err)
	}
	stored, err := repo.GetRecord(ctx, target, mailbox.MessageStateCollection, pair.RKey)
	if err != nil {
		t.Fatal(err)
	}
	var state mailbox.MessageStateRecord
	if json.Unmarshal(stored.Value, &state) != nil || state.Revision != 1 {
		t.Fatalf("seeded state = %#v", state)
	}
	return target, pair.RKey
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestReplaceCommitsExactPortableStateAndReplaysIdempotently(t *testing.T) {
	did := "did:plc:statereplace"
	repo := memory.NewBackend().OwnerSession(did)
	target, rkey := seedMessage(t, repo, did)
	replacement := Replacement{
		MessageRKey: rkey, ExpectedRevision: 1, OperationID: "jmap-change-1",
		Mailbox: "Archive", Keywords: []string{"$seen", "$flagged"}, Now: time.Unix(10, 0),
	}
	first, err := Replace(t.Context(), repo, target, replacement)
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision != 2 || first.LastOperation != replacement.OperationID || len(first.MailboxIDs) != 1 || first.MailboxIDs[0] != mailbox.FolderRKey("Archive") || len(first.Keywords) != 2 {
		t.Fatalf("first=%#v", first)
	}
	replayed, err := Replace(t.Context(), repo, target, replacement)
	if err != nil || replayed.Revision != first.Revision {
		t.Fatalf("replayed=%#v err=%v", replayed, err)
	}
	replacement.OperationID = "stale-other"
	if _, err := Replace(t.Context(), repo, target, replacement); !errors.Is(err, ErrStaleRevision) {
		t.Fatalf("stale error=%v", err)
	}
}
