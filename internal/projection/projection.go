package projection

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/comail-atproto/comail-pds-lab/internal/mailbox"
	"github.com/comail-atproto/comail-pds-lab/internal/repository"

	_ "modernc.org/sqlite"
)

type Mismatch struct {
	Kind string `json:"kind"`
	Key  string `json:"key"`
}

type Report struct {
	Version        int               `json:"version"`
	Target         repository.Target `json:"target"`
	Folders        int               `json:"folders"`
	Messages       int               `json:"messages"`
	States         int               `json:"states"`
	TotalBytes     int64             `json:"totalBytes"`
	ManifestSHA256 string            `json:"manifestSha256"`
	Mismatches     []Mismatch        `json:"mismatches,omitempty"`
}

func (r Report) Passed() bool {
	return len(r.Mismatches) == 0 && r.Messages == r.States && r.ManifestSHA256 != ""
}

type decodedMessage struct {
	record repository.Record
	value  mailbox.MessageRecord
	state  mailbox.MessageStateRecord
}

// Rebuild creates a brand-new disposable SQLite projection using only records
// and referenced blobs read from target. The destination is create-only and is
// removed on any integrity or persistence error.
func Rebuild(ctx context.Context, repo repository.Repository, target repository.Target, destination string) (Report, error) {
	report := Report{Version: 1, Target: target}
	if repo == nil || !filepath.IsAbs(destination) {
		return report, errors.New("projection: repository and absolute destination are required")
	}
	if err := target.ValidateFor(target.RepoDID); err != nil {
		return report, err
	}
	if _, err := os.Lstat(destination); err == nil {
		return report, fmt.Errorf("projection: destination exists: %w", os.ErrExist)
	} else if !errors.Is(err, os.ErrNotExist) {
		return report, err
	}

	folderRecords, err := repo.ListRecords(ctx, target, mailbox.FolderCollection)
	if err != nil {
		return report, fmt.Errorf("projection: list folders: %w", err)
	}
	folders := make(map[string]mailbox.FolderRecord, len(folderRecords))
	for _, record := range folderRecords {
		var folder mailbox.FolderRecord
		if err := json.Unmarshal(record.Value, &folder); err != nil || folder.Type != mailbox.FolderCollection || folder.Name == "" || record.RKey != mailbox.FolderRKey(folder.Name) {
			report.Mismatches = append(report.Mismatches, Mismatch{Kind: "folder-integrity", Key: record.RKey})
			continue
		}
		folders[record.RKey] = folder
	}
	report.Folders = len(folderRecords)

	stateRecords, err := repo.ListRecords(ctx, target, mailbox.MessageStateCollection)
	if err != nil {
		return report, fmt.Errorf("projection: list states: %w", err)
	}
	states := make(map[string]mailbox.MessageStateRecord, len(stateRecords))
	for _, record := range stateRecords {
		var state mailbox.MessageStateRecord
		if err := json.Unmarshal(record.Value, &state); err != nil || state.Type != mailbox.MessageStateCollection || state.Message != record.RKey || state.Revision == 0 || len(state.MailboxIDs) != 1 {
			report.Mismatches = append(report.Mismatches, Mismatch{Kind: "state-integrity", Key: record.RKey})
			continue
		}
		folder, ok := folders[state.MailboxIDs[0]]
		if !ok {
			report.Mismatches = append(report.Mismatches, Mismatch{Kind: "state-folder", Key: record.RKey})
			continue
		}
		if state.Projection.UID == 0 || state.Projection.UIDValidity != folder.UIDValidity {
			report.Mismatches = append(report.Mismatches, Mismatch{Kind: "projection-identity", Key: record.RKey})
			continue
		}
		states[record.RKey] = state
	}
	report.States = len(stateRecords)

	messageRecords, err := repo.ListRecords(ctx, target, mailbox.MessageCollection)
	if err != nil {
		return report, fmt.Errorf("projection: list messages: %w", err)
	}
	messages := make([]decodedMessage, 0, len(messageRecords))
	seenMessages := make(map[string]bool, len(messageRecords))
	for _, record := range messageRecords {
		var message mailbox.MessageRecord
		if err := json.Unmarshal(record.Value, &message); err != nil {
			report.Mismatches = append(report.Mismatches, Mismatch{Kind: "message-record", Key: record.RKey})
			continue
		}
		state, ok := states[record.RKey]
		if !ok {
			report.Mismatches = append(report.Mismatches, Mismatch{Kind: "missing-state", Key: record.RKey})
			continue
		}
		seenMessages[record.RKey] = true
		messages = append(messages, decodedMessage{record: record, value: message, state: state})
	}
	for rkey := range states {
		if !seenMessages[rkey] {
			report.Mismatches = append(report.Mismatches, Mismatch{Kind: "orphan-state", Key: rkey})
		}
	}
	report.Messages = len(messageRecords)
	sortMismatches(report.Mismatches)
	if len(report.Mismatches) > 0 {
		return report, fmt.Errorf("%w: projection record graph is inconsistent", mailbox.ErrIntegrity)
	}

	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return report, err
	}
	db, err := sql.Open("sqlite", destination)
	if err != nil {
		return report, err
	}
	complete := false
	defer func() {
		_ = db.Close()
		if !complete {
			_ = os.Remove(destination)
			_ = os.Remove(destination + "-wal")
			_ = os.Remove(destination + "-shm")
		}
	}()
	if err := createSchema(db, target); err != nil {
		return report, err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return report, err
	}
	defer tx.Rollback() //nolint:errcheck
	for rkey, folder := range folders {
		if _, err := tx.ExecContext(ctx, `INSERT INTO folders(rkey,name,role,uid_validity,revision,updated_at) VALUES(?,?,?,?,?,?)`,
			rkey, folder.Name, folder.Role, folder.UIDValidity, folder.Revision, folder.UpdatedAt); err != nil {
			return report, fmt.Errorf("projection: insert folder: %w", err)
		}
	}
	sort.Slice(messages, func(i, j int) bool { return messages[i].record.RKey < messages[j].record.RKey })
	manifest := sha256.New()
	for _, item := range messages {
		raw, err := repo.GetBlob(ctx, target, item.value.Raw.Ref.Link)
		if err != nil {
			return report, fmt.Errorf("projection: fetch referenced blob: %w", err)
		}
		if err := mailbox.ValidateStoredMessage(target.RepoDID, item.record.RKey, item.value, raw); err != nil {
			return report, err
		}
		folder := folders[item.state.MailboxIDs[0]]
		keywords, _ := json.Marshal(item.state.Keywords)
		references, _ := json.Marshal(item.value.References)
		if _, err := tx.ExecContext(ctx, `INSERT INTO messages(
rkey,raw,sha256,size,mailbox,keywords_json,delete_pending,uid,uid_validity,modseq,
source_message_id,message_date,in_reply_to,references_json
) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			item.record.RKey, raw, item.value.SHA256, item.value.Size, folder.Name, string(keywords), item.state.DeletePending,
			item.state.Projection.UID, item.state.Projection.UIDValidity, item.state.Projection.ModSeq,
			item.value.SourceMessageID, item.value.MessageDate, item.value.InReplyTo, string(references)); err != nil {
			return report, fmt.Errorf("projection: insert message: %w", err)
		}
		report.TotalBytes += int64(len(raw))
		_, _ = manifest.Write([]byte(item.record.RKey + "\x00" + item.value.SHA256 + "\x00"))
		stateJSON, _ := json.Marshal(item.state)
		_, _ = manifest.Write(stateJSON)
		_, _ = manifest.Write([]byte{0})
	}
	if err := tx.Commit(); err != nil {
		return report, err
	}
	if err := db.Close(); err != nil {
		return report, err
	}
	if err := os.Chmod(destination, 0o600); err != nil {
		return report, err
	}
	report.ManifestSHA256 = hex.EncodeToString(manifest.Sum(nil))
	complete = true
	return report, nil
}

func createSchema(db *sql.DB, target repository.Target) error {
	if _, err := db.Exec(`PRAGMA journal_mode=DELETE;
PRAGMA foreign_keys=ON;
CREATE TABLE projection_meta (provider_origin TEXT NOT NULL, space_uri TEXT NOT NULL, repo_did TEXT NOT NULL, epoch TEXT NOT NULL);
CREATE TABLE folders (rkey TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, role TEXT NOT NULL, uid_validity INTEGER NOT NULL, revision INTEGER NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE messages (
  rkey TEXT PRIMARY KEY, raw BLOB NOT NULL, sha256 TEXT NOT NULL, size INTEGER NOT NULL,
  mailbox TEXT NOT NULL, keywords_json TEXT NOT NULL, delete_pending INTEGER NOT NULL,
  uid INTEGER NOT NULL, uid_validity INTEGER NOT NULL, modseq INTEGER NOT NULL,
  source_message_id TEXT NOT NULL, message_date TEXT NOT NULL, in_reply_to TEXT NOT NULL,
  references_json TEXT NOT NULL, UNIQUE(mailbox,uid)
);`); err != nil {
		return err
	}
	_, err := db.Exec(`INSERT INTO projection_meta VALUES(?,?,?,?)`, target.ProviderOrigin, target.SpaceURI, target.RepoDID, target.Epoch)
	return err
}

func sortMismatches(items []Mismatch) {
	sort.Slice(items, func(i, j int) bool {
		return strings.Compare(items[i].Kind+"\x00"+items[i].Key, items[j].Kind+"\x00"+items[j].Key) < 0
	})
}
