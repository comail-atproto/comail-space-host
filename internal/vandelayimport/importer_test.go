package vandelayimport

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/comail-atproto/comail-pds-lab/internal/mailbox"
	"github.com/comail-atproto/comail-pds-lab/internal/memory"
	"github.com/comail-atproto/comail-pds-lab/internal/migrate"
	"github.com/comail-atproto/comail-pds-lab/internal/sqliteimport"
	"lukechampine.com/blake3"

	_ "modernc.org/sqlite"
)

const fixtureDID = "did:plc:vandelayimporttest"

func fixture(t *testing.T, corruptHash bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "archive.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE sources (id INTEGER PRIMARY KEY, kind TEXT NOT NULL, session_url TEXT NOT NULL, account_id TEXT NOT NULL, account_name TEXT, username TEXT NOT NULL);
CREATE TABLE blobs (id INTEGER PRIMARY KEY, hash BLOB NOT NULL UNIQUE, data BLOB NOT NULL);
CREATE TABLE mailboxes (id INTEGER PRIMARY KEY, name TEXT NOT NULL, parent_id INTEGER, role TEXT, sort_order INTEGER NOT NULL DEFAULT 0, is_subscribed INTEGER NOT NULL DEFAULT 1);
CREATE TABLE emails (id INTEGER PRIMARY KEY, blob_id INTEGER NOT NULL, received_at TEXT NOT NULL, mailbox_ids TEXT NOT NULL, keywords TEXT NOT NULL DEFAULT '[]', message_match TEXT NOT NULL DEFAULT '{}');
CREATE TABLE sync_id_jmap (source_id INTEGER NOT NULL, type_name TEXT NOT NULL, jmap_id TEXT NOT NULL, local_id INTEGER NOT NULL, PRIMARY KEY(source_id,type_name,jmap_id));
INSERT INTO sources VALUES(1,'jmap','https://mail.example/jmap','account-1','operator@example.test','operator@example.test');
INSERT INTO mailboxes VALUES(10,'INBOX',NULL,'inbox',0,1),(11,'Projects',NULL,NULL,1,1),(12,'Alpha',11,NULL,1,1);`)
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte("Message-ID: <vandelay@example.test>\r\nDate: Tue, 14 Nov 2023 22:13:20 +0000\r\nSubject: fixture\r\n\r\nprivate fixture body\r\n")
	hash := blake3.Sum256(raw)
	if corruptHash {
		hash[0] ^= 0xff
	}
	if _, err := db.Exec(`INSERT INTO blobs VALUES(1,?,?)`, hash[:], raw); err != nil {
		t.Fatal(err)
	}
	mailboxes, _ := json.Marshal([]int64{10, 12})
	keywords, _ := json.Marshal([]string{"$seen", "$flagged"})
	if _, err := db.Exec(`INSERT INTO emails VALUES(20,1,'2023-11-14T22:13:21Z',?,?, '{}')`, string(mailboxes), string(keywords)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO emails VALUES(21,1,'2023-11-14T22:13:22Z','[11]','["$seen"]','{}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sync_id_jmap VALUES(1,'Email','E-stable-20',20),(1,'Email','E-stable-21',21)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOpenInspectAndStreamVandelayArchive(t *testing.T) {
	snapshot, err := Open(fixture(t, false))
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	inv, err := snapshot.Inspect(context.Background(), fixtureDID, "primary")
	if err != nil {
		t.Fatal(err)
	}
	if inv.Folders != 3 || inv.LiveMessages != 2 || inv.LiveBytes == 0 || inv.Space.User != fixtureDID {
		t.Fatalf("inventory = %#v", inv)
	}
	folders, err := snapshot.Folders(context.Background(), inv.Space)
	if err != nil {
		t.Fatal(err)
	}
	if len(folders) != 3 || folders[2].Name != "Projects/Alpha" || folders[0].Folder.Record.UIDValidity == 0 {
		t.Fatalf("folders = %#v", folders)
	}
	var got sqliteimport.SourceMessage
	var streamed int
	if err := snapshot.Stream(context.Background(), inv.Space, func(src sqliteimport.SourceMessage) error {
		streamed++
		if src.LegacyRKey == "jmap:E-stable-20" {
			got = src
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if streamed != 2 || got.Imported.MessageID != "<vandelay@example.test>" || len(got.Imported.Mailboxes) != 2 || got.Imported.Mailboxes[1] != "Projects/Alpha" {
		t.Fatalf("message = %#v", got.Imported)
	}
	if got.Imported.RecipientDID != fixtureDID || len(got.Imported.Raw) == 0 {
		t.Fatal("message binding or canonical bytes missing")
	}
}

func TestMigrationPreservesDistinctEmailsWithIdenticalBytes(t *testing.T) {
	snapshot, err := Open(fixture(t, false))
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	repo := memory.NewBackend().OwnerSession(fixtureDID)
	report, err := migrate.Run(context.Background(), snapshot, repo, migrate.Options{RecipientDID: fixtureDID, SpaceKey: "primary", Commit: true})
	if err != nil {
		t.Fatal(err)
	}
	if report.CreatedMessages != 2 || !report.Verification.Passed() || len(report.Fingerprints) != 2 || report.Fingerprints[0] == report.Fingerprints[1] {
		t.Fatalf("report = %#v", report)
	}
}

func TestStreamRejectsCorruptContentAddress(t *testing.T) {
	snapshot, err := Open(fixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	inv, err := snapshot.Inspect(context.Background(), fixtureDID, "primary")
	if err != nil {
		t.Fatal(err)
	}
	err = snapshot.Stream(context.Background(), inv.Space, func(sqliteimport.SourceMessage) error { return nil })
	if !errors.Is(err, mailbox.ErrIntegrity) {
		t.Fatalf("error = %v", err)
	}
}

func TestOpenRejectsNonEmptySidecar(t *testing.T) {
	path := fixture(t, false)
	if err := os.WriteFile(path+"-wal", []byte("unsafe"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Open(path)
	if !errors.Is(err, ErrInconsistentArchive) {
		t.Fatalf("error = %v", err)
	}
}

func TestStreamRejectsJMAPEmailWithoutStableSourceID(t *testing.T) {
	path := fixture(t, false)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM sync_id_jmap WHERE local_id=21`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	snapshot, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	inv, err := snapshot.Inspect(context.Background(), fixtureDID, "primary")
	if err != nil {
		t.Fatal(err)
	}
	err = snapshot.Stream(context.Background(), inv.Space, func(sqliteimport.SourceMessage) error { return nil })
	if !errors.Is(err, ErrInvalidArchive) {
		t.Fatalf("error = %v", err)
	}
}
