package projection

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/comail-atproto/comail-space-host/internal/mailbox"
	"github.com/comail-atproto/comail-space-host/internal/mailboxstate"
	"github.com/comail-atproto/comail-space-host/internal/memory"
	"github.com/comail-atproto/comail-space-host/internal/migrate"
	"github.com/comail-atproto/comail-space-host/internal/repository"
	"github.com/comail-atproto/comail-space-host/internal/sqliteimport"
	"github.com/comail-atproto/comail-space-host/internal/synthetic"

	_ "modernc.org/sqlite"
)

func TestRebuildFreshProjectionFromPermissionedSpace(t *testing.T) {
	dir := t.TempDir()
	did := "did:plc:projectiontest"
	sourcePath := filepath.Join(dir, "source.sqlite")
	if err := synthetic.CreateSnapshot(sourcePath, did, "primary"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := sqliteimport.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	repo := memory.NewBackend().OwnerSession(did)
	migration, err := migrate.Run(context.Background(), snapshot, repo, migrate.Options{RecipientDID: did, SpaceKey: "primary", Commit: true})
	if err != nil {
		t.Fatal(err)
	}
	projectionPath := filepath.Join(dir, "fresh", "mailbox.sqlite")
	report, err := Rebuild(context.Background(), repo, migration.Target, projectionPath)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed() || report.Messages != 3 || report.Folders != 2 || report.States != 3 || report.TotalBytes == 0 || report.ManifestSHA256 == "" {
		t.Fatalf("report = %#v", report)
	}
	info, err := os.Stat(projectionPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("projection mode = %o", info.Mode().Perm())
	}
	db, err := sql.Open("sqlite", "file:"+projectionPath+"?mode=ro&immutable=1")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var uid, uidValidity int
	if err := db.QueryRow(`SELECT uid, uid_validity FROM message_mailboxes WHERE mailbox='INBOX' ORDER BY uid LIMIT 1`).Scan(&uid, &uidValidity); err != nil {
		t.Fatal(err)
	}
	if uid != 1 || uidValidity != 101 {
		t.Fatalf("projection identity uid=%d uidValidity=%d", uid, uidValidity)
	}
	if _, err := os.Stat(sourcePath); err != nil {
		t.Fatalf("source snapshot changed: %v", err)
	}
}

func TestRebuildRefusesExistingDestinationAndOrphanState(t *testing.T) {
	ctx := context.Background()
	did := "did:plc:projectionorphan"
	repo := memory.NewBackend().OwnerSession(did)
	target, err := repo.EnsureMailbox(ctx, did, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ApplyWrites(ctx, target, []repository.Write{{
		Action: repository.Create, Collection: mailbox.MessageStateCollection, RKey: "orphan",
		Value: mailbox.MessageStateRecord{Type: mailbox.MessageStateCollection, Message: "orphan", MailboxIDs: []string{"x"}, Revision: 1, UpdatedAt: "1970-01-01T00:00:00Z"},
	}}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "projection.sqlite")
	if _, err := Rebuild(ctx, repo, target, path); err == nil {
		t.Fatal("orphan state was accepted")
	}
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Rebuild(ctx, repo, target, path); err == nil {
		t.Fatal("existing destination was overwritten")
	}
}

func TestRebuildAllocatesPerFolderUIDsForMultiMailboxMessage(t *testing.T) {
	ctx := context.Background()
	did := "did:plc:projectionmultimailbox"
	repo := memory.NewBackend().OwnerSession(did)
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
	raw := []byte("Message-ID: <multi@example.test>\r\n\r\nbody\r\n")
	blob, err := repo.UploadBlob(ctx, target, raw, mailbox.MessageMIMEType)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := mailbox.NewMessagePair(mailbox.ImportedMessage{RecipientDID: did, SourceKey: "vandelay:1", Raw: raw, Mailboxes: []string{"INBOX", "Archive"}}, blob)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ApplyWrites(ctx, target, []repository.Write{
		{Action: repository.Create, Collection: mailbox.MessageCollection, RKey: pair.RKey, Value: pair.Message},
		{Action: repository.Create, Collection: mailbox.MessageStateCollection, RKey: pair.RKey, Value: pair.State},
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "multi.sqlite")
	report, err := Rebuild(ctx, repo, target, path)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed() || report.Messages != 1 {
		t.Fatalf("report = %#v", report)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var memberships, distinctUIDValidity int
	if err := db.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT uid_validity) FROM message_mailboxes WHERE rkey=?`, pair.RKey).Scan(&memberships, &distinctUIDValidity); err != nil {
		t.Fatal(err)
	}
	if memberships != 2 || distinctUIDValidity != 2 {
		t.Fatalf("memberships=%d uidvalidity=%d", memberships, distinctUIDValidity)
	}
}

func TestRebuildVerifiesButOmitsTombstonedMessage(t *testing.T) {
	ctx := context.Background()
	did := "did:plc:projectiontombstone"
	repo := memory.NewBackend().OwnerSession(did)
	target, err := repo.EnsureMailbox(ctx, did, "primary")
	if err != nil {
		t.Fatal(err)
	}
	inbox := mailbox.NewFolder("INBOX", "inbox", mailbox.StableUIDValidity(did, "INBOX"))
	if _, err := repo.ApplyWrites(ctx, target, []repository.Write{{Action: repository.Create, Collection: mailbox.FolderCollection, RKey: inbox.RKey, Value: inbox.Record}}); err != nil {
		t.Fatal(err)
	}
	raw := []byte("Subject: deleted\r\n\r\nbody\r\n")
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
	if _, err := mailboxstate.Apply(ctx, repo, target, mailboxstate.Mutation{
		MessageRKey: pair.RKey, ExpectedRevision: 1, OperationID: "delete-once", Operation: mailboxstate.Tombstone, Now: time.Unix(1, 0),
	}); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "tombstone.sqlite")
	report, err := Rebuild(ctx, repo, target, path)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed() || report.Messages != 1 || report.States != 1 || report.Tombstones != 1 {
		t.Fatalf("report = %#v", report)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&immutable=1")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var visible int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&visible); err != nil {
		t.Fatal(err)
	}
	if visible != 0 {
		t.Fatalf("visible projected messages = %d", visible)
	}
}
