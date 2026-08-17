package sqliteimport

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/comail-atproto/comail-space-host/internal/mailbox"

	_ "modernc.org/sqlite"
)

const fixtureSchema = `
CREATE TABLE spaces (
  space_id INTEGER PRIMARY KEY, owner TEXT NOT NULL, type TEXT NOT NULL,
  key TEXT NOT NULL, user TEXT NOT NULL, modseq INTEGER NOT NULL
);
CREATE TABLE collections (
  coll_id INTEGER PRIMARY KEY, space_id INTEGER NOT NULL, name TEXT NOT NULL,
  uid_validity INTEGER NOT NULL, next_uid INTEGER NOT NULL
);
CREATE TABLE messages (
  coll_id INTEGER NOT NULL, rkey TEXT NOT NULL, uid INTEGER NOT NULL,
  modseq INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, raw BLOB,
  message_id TEXT, subject TEXT, from_addr TEXT, to_json TEXT, date INTEGER,
  blobs_json TEXT, flags_json TEXT, in_reply_to TEXT, references_ids TEXT,
  PRIMARY KEY(coll_id, rkey)
);`

func buildFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mailbox-snapshot.sqlite")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(fixtureSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO spaces VALUES
    (1,'did:plc:alice','email.atmos.mailbox','primary','did:plc:alice',99),
    (2,'did:plc:bob','email.atmos.mailbox','primary','did:plc:bob',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO collections VALUES
    (10,1,'INBOX',77,42),
    (11,1,'Archive',78,9),
    (20,2,'INBOX',88,1)`); err != nil {
		t.Fatal(err)
	}
	raw := []byte("Message-ID: <one@example.com>\r\nDate: Fri, 15 Aug 2026 12:00:00 -0400\r\nSubject: synthetic\r\n\r\nhello\r\n")
	flags, _ := json.Marshal(map[string]bool{"Seen": true, "Flagged": true, "Answered": false, "Draft": false, "Deleted": true})
	if _, err := db.Exec(`INSERT INTO messages
    (coll_id,rkey,uid,modseq,deleted,raw,message_id,subject,from_addr,to_json,date,blobs_json,flags_json,in_reply_to,references_ids)
    VALUES (10,'legacy-one',42,90,0,?,'one@example.com','synthetic','sender@example.com','["alice@example.com"]',?,'[]',?,'parent@example.com','root@example.com parent@example.com')`,
		raw, time.Date(2026, 8, 15, 16, 0, 0, 0, time.UTC).Unix(), string(flags)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO messages
    (coll_id,rkey,uid,modseq,deleted,raw,message_id,subject,from_addr,to_json,date,blobs_json,flags_json,in_reply_to,references_ids)
    VALUES (11,'expunged',9,91,1,X'01','gone','','','[]',0,'[]','{}','','')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func fileHash(t *testing.T, path string) [32]byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(b)
}

func TestInspectAndStreamSnapshotWithoutMutation(t *testing.T) {
	ctx := context.Background()
	path := buildFixture(t)
	before := fileHash(t, path)
	snapshot, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	inv, err := snapshot.Inspect(ctx, "did:plc:alice", "primary")
	if err != nil {
		t.Fatal(err)
	}
	if inv.LiveMessages != 1 || inv.ExpungedMessages != 1 || inv.Folders != 2 || inv.LiveBytes == 0 {
		t.Fatalf("inventory = %#v", inv)
	}
	if inv.Space.Owner != "did:plc:alice" || inv.Space.ModSeq != 99 {
		t.Fatalf("space = %#v", inv.Space)
	}
	var got []SourceMessage
	if err := snapshot.Stream(ctx, inv.Space, func(message SourceMessage) error {
		got = append(got, message)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("messages = %d", len(got))
	}
	message := got[0]
	if message.LegacyRKey != "legacy-one" || message.Imported.UID != 42 || message.Imported.UIDValidity != 77 || message.Imported.ModSeq != 90 {
		t.Fatalf("identity = %#v", message)
	}
	if message.Imported.Mailbox != "INBOX" || message.Role != "inbox" || !message.Imported.DeletePending {
		t.Fatalf("mailbox mapping = %#v", message)
	}
	if len(message.Imported.Keywords) != 2 || message.Imported.Keywords[0] != "$flagged" || message.Imported.Keywords[1] != "$seen" {
		t.Fatalf("keywords = %#v", message.Imported.Keywords)
	}
	if message.Imported.MessageDate.UTC().Format(time.RFC3339) != "2026-08-15T16:00:00Z" {
		t.Fatalf("date = %s", message.Imported.MessageDate)
	}
	if message.Imported.DeliveredAt.IsZero() == false {
		t.Fatal("legacy snapshot invented a delivery timestamp")
	}
	if after := fileHash(t, path); after != before {
		t.Fatal("snapshot changed while being inspected")
	}
}

func TestOpenRefusesWALSidecar(t *testing.T) {
	path := buildFixture(t)
	if err := os.WriteFile(path+"-wal", []byte("not checkpointed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); !errors.Is(err, ErrInconsistentSnapshot) {
		t.Fatalf("Open error = %v", err)
	}
}

func TestExactMailboxSelectionFailsClosed(t *testing.T) {
	snapshot, err := Open(buildFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	defer snapshot.Close()
	for _, tc := range []struct {
		did string
		key string
	}{
		{"did:plc:alice", "missing"},
		{"did:plc:mallory", "primary"},
		{"", "primary"},
	} {
		if _, err := snapshot.Inspect(context.Background(), tc.did, tc.key); !errors.Is(err, ErrMailboxNotFound) && !errors.Is(err, ErrInvalidSource) {
			t.Fatalf("Inspect(%q,%q) error = %v", tc.did, tc.key, err)
		}
	}
}

func TestStreamRejectsOversizeMessage(t *testing.T) {
	path := buildFixture(t)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	large := make([]byte, mailbox.MaxRawMessageBytes+1)
	if _, err := db.Exec(`UPDATE messages SET raw=? WHERE rkey='legacy-one'`, large); err != nil {
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
	inv, err := snapshot.Inspect(context.Background(), "did:plc:alice", "primary")
	if err != nil {
		t.Fatal(err)
	}
	if inv.OversizeMessages != 1 {
		t.Fatalf("oversize count = %d", inv.OversizeMessages)
	}
	err = snapshot.Stream(context.Background(), inv.Space, func(SourceMessage) error { return nil })
	if !errors.Is(err, mailbox.ErrMessageTooLarge) {
		t.Fatalf("Stream error = %v", err)
	}
}
