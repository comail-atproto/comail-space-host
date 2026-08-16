package projection

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/comail-atproto/comail-pds-lab/internal/mailbox"
	"github.com/comail-atproto/comail-pds-lab/internal/memory"
	"github.com/comail-atproto/comail-pds-lab/internal/migrate"
	"github.com/comail-atproto/comail-pds-lab/internal/repository"
	"github.com/comail-atproto/comail-pds-lab/internal/sqliteimport"
	"github.com/comail-atproto/comail-pds-lab/internal/synthetic"

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
	if err := db.QueryRow(`SELECT uid, uid_validity FROM messages WHERE mailbox='INBOX' ORDER BY uid LIMIT 1`).Scan(&uid, &uidValidity); err != nil {
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
