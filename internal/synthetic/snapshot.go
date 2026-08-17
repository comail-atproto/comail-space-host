package synthetic

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/comail-atproto/comail-space-host/internal/mailbox"

	_ "modernc.org/sqlite"
)

// CreateSnapshot creates a deterministic, non-sensitive Comail SQLite
// snapshot. It is create-only so a proof cannot overwrite operator data.
func CreateSnapshot(path, did, spaceKey string) error {
	if !filepath.IsAbs(path) || !strings.HasPrefix(did, "did:") || spaceKey == "" {
		return errors.New("synthetic: absolute path, DID, and space key are required")
	}
	if _, err := os.Lstat(path); err == nil {
		return os.ErrExist
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = db.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := db.Exec(`PRAGMA journal_mode=DELETE;
CREATE TABLE spaces (space_id INTEGER PRIMARY KEY, owner TEXT NOT NULL, type TEXT NOT NULL, key TEXT NOT NULL, user TEXT NOT NULL, modseq INTEGER NOT NULL);
CREATE TABLE collections (coll_id INTEGER PRIMARY KEY, space_id INTEGER NOT NULL, name TEXT NOT NULL, uid_validity INTEGER NOT NULL, next_uid INTEGER NOT NULL);
CREATE TABLE messages (coll_id INTEGER NOT NULL, rkey TEXT NOT NULL, uid INTEGER NOT NULL, modseq INTEGER NOT NULL, deleted INTEGER NOT NULL DEFAULT 0, raw BLOB, message_id TEXT, subject TEXT, from_addr TEXT, to_json TEXT, date INTEGER, blobs_json TEXT, flags_json TEXT, in_reply_to TEXT, references_ids TEXT, PRIMARY KEY(coll_id,rkey));`); err != nil {
		return err
	}
	if _, err := db.Exec(`INSERT INTO spaces VALUES(1,?,?,?,?,20)`, did, mailbox.MailboxSpaceType, spaceKey, did); err != nil {
		return err
	}
	if _, err := db.Exec(`INSERT INTO collections VALUES(10,1,'INBOX',101,3),(11,1,'Archive',202,2)`); err != nil {
		return err
	}
	rows := []struct {
		collection int
		rkey       string
		uid        int
		modseq     int
		deleted    int
		raw        string
		messageID  string
		flags      string
	}{
		{10, "legacy-a", 1, 18, 0, "Message-ID: <a@synthetic.invalid>\r\nSubject: first synthetic message\r\n\r\nalpha\r\n", "a@synthetic.invalid", `{"Seen":true}`},
		{10, "legacy-b", 2, 19, 0, "Message-ID: <b@synthetic.invalid>\r\nSubject: second synthetic message\r\n\r\nbeta\r\n", "b@synthetic.invalid", `{"Flagged":true}`},
		{11, "legacy-c", 1, 20, 0, "Message-ID: <c@synthetic.invalid>\r\nSubject: archived synthetic message\r\n\r\ngamma\r\n", "c@synthetic.invalid", `{}`},
		{11, "expunged", 2, 21, 1, "Message-ID: <gone@synthetic.invalid>\r\n\r\nnot migrated\r\n", "gone@synthetic.invalid", `{}`},
	}
	for _, row := range rows {
		if _, err := db.Exec(`INSERT INTO messages VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			row.collection, row.rkey, row.uid, row.modseq, row.deleted, []byte(row.raw), row.messageID,
			"synthetic", "sender@synthetic.invalid", `[]`, time.Unix(1_700_000_000, 0).Unix(), `[]`, row.flags, "", ""); err != nil {
			return fmt.Errorf("synthetic: insert %s: %w", row.rkey, err)
		}
	}
	if err := db.Close(); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	ok = true
	return nil
}
