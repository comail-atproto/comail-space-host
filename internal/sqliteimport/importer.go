package sqliteimport

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/comail-atproto/comail-pds-lab/internal/mailbox"

	_ "modernc.org/sqlite"
)

var (
	ErrInconsistentSnapshot = errors.New("sqliteimport: snapshot has SQLite sidecars and may be inconsistent")
	ErrMailboxNotFound      = errors.New("sqliteimport: exact mailbox not found")
	ErrInvalidSource        = errors.New("sqliteimport: invalid source snapshot")
)

type Snapshot struct {
	path           string
	db             *sql.DB
	messageColumns map[string]bool
}

type Space struct {
	ID     int64  `json:"-"`
	Owner  string `json:"owner"`
	Type   string `json:"type"`
	Key    string `json:"key"`
	User   string `json:"user"`
	ModSeq uint64 `json:"modSeq"`
}

type Inventory struct {
	Space            Space `json:"space"`
	Folders          int   `json:"folders"`
	LiveMessages     int   `json:"liveMessages"`
	ExpungedMessages int   `json:"expungedMessages"`
	OversizeMessages int   `json:"oversizeMessages"`
	LiveBytes        int64 `json:"liveBytes"`
}

type SourceFolder struct {
	Name        string
	Role        string
	UIDValidity uint32
	NextUID     uint32
	Folder      mailbox.Folder
}

type SourceMessage struct {
	LegacyRKey string
	Role       string
	Imported   mailbox.ImportedMessage
}

func Open(path string) (*Snapshot, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("%w: snapshot path is required", ErrInvalidSource)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve snapshot: %v", ErrInvalidSource, err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return nil, fmt.Errorf("%w: absolute snapshot path: %v", ErrInvalidSource, err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: snapshot must be a regular file", ErrInvalidSource)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if sidecar, err := os.Stat(resolved + suffix); err == nil && sidecar.Size() > 0 {
			return nil, fmt.Errorf("%w: %s exists", ErrInconsistentSnapshot, filepath.Base(resolved+suffix))
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: inspect sidecar: %v", ErrInvalidSource, err)
		}
	}
	u := &url.URL{Scheme: "file", Path: filepath.ToSlash(resolved)}
	dsn := u.String() + "?mode=ro&immutable=1&_pragma=query_only(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("%w: open read-only: %v", ErrInvalidSource, err)
	}
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("%w: ping: %v", ErrInvalidSource, err)
	}
	snapshot := &Snapshot{path: resolved, db: db}
	if err := snapshot.validateSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return snapshot, nil
}

func (s *Snapshot) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *Snapshot) Path() string { return s.path }

func (s *Snapshot) Inspect(ctx context.Context, did, spaceKey string) (Inventory, error) {
	if !strings.HasPrefix(did, "did:") || !validSpaceKey(spaceKey) {
		return Inventory{}, fmt.Errorf("%w: exact DID and space key are required", ErrInvalidSource)
	}
	var inv Inventory
	err := s.db.QueryRowContext(ctx, `
SELECT space_id, owner, type, key, user, modseq
FROM spaces
WHERE owner=? AND user=? AND type=? AND key=?`,
		did, did, mailbox.MailboxSpaceType, spaceKey,
	).Scan(&inv.Space.ID, &inv.Space.Owner, &inv.Space.Type, &inv.Space.Key, &inv.Space.User, &inv.Space.ModSeq)
	if errors.Is(err, sql.ErrNoRows) {
		return Inventory{}, ErrMailboxNotFound
	}
	if err != nil {
		return Inventory{}, fmt.Errorf("inspect mailbox: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM collections WHERE space_id=?`, inv.Space.ID).Scan(&inv.Folders); err != nil {
		return Inventory{}, fmt.Errorf("count folders: %w", err)
	}
	if err := s.db.QueryRowContext(ctx, `
SELECT
  COALESCE(SUM(CASE WHEN m.deleted=0 THEN 1 ELSE 0 END),0),
  COALESCE(SUM(CASE WHEN m.deleted<>0 THEN 1 ELSE 0 END),0),
  COALESCE(SUM(CASE WHEN m.deleted=0 AND length(m.raw)>? THEN 1 ELSE 0 END),0),
  COALESCE(SUM(CASE WHEN m.deleted=0 THEN length(m.raw) ELSE 0 END),0)
FROM collections c
LEFT JOIN messages m ON m.coll_id=c.coll_id
WHERE c.space_id=?`, mailbox.MaxRawMessageBytes, inv.Space.ID,
	).Scan(&inv.LiveMessages, &inv.ExpungedMessages, &inv.OversizeMessages, &inv.LiveBytes); err != nil {
		return Inventory{}, fmt.Errorf("inspect messages: %w", err)
	}
	return inv, nil
}

func (s *Snapshot) Folders(ctx context.Context, space Space) ([]SourceFolder, error) {
	if err := validateSpace(space); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT name, uid_validity, next_uid
FROM collections
WHERE space_id=?
ORDER BY name`, space.ID)
	if err != nil {
		return nil, fmt.Errorf("list folders: %w", err)
	}
	defer rows.Close()
	var folders []SourceFolder
	for rows.Next() {
		var name string
		var uidValidity, nextUID uint32
		if err := rows.Scan(&name, &uidValidity, &nextUID); err != nil {
			return nil, fmt.Errorf("scan folder: %w", err)
		}
		role := folderRole(name)
		folders = append(folders, SourceFolder{
			Name: name, Role: role, UIDValidity: uidValidity, NextUID: nextUID,
			Folder: mailbox.NewFolder(name, role, uidValidity),
		})
	}
	return folders, rows.Err()
}

func (s *Snapshot) Stream(ctx context.Context, space Space, visit func(SourceMessage) error) error {
	if visit == nil {
		return fmt.Errorf("%w: message visitor is required", ErrInvalidSource)
	}
	if err := validateSpace(space); err != nil {
		return err
	}
	inReplyExpr := "''"
	if s.messageColumns["in_reply_to"] {
		inReplyExpr = "COALESCE(m.in_reply_to,'')"
	}
	referencesExpr := "''"
	if s.messageColumns["references_ids"] {
		referencesExpr = "COALESCE(m.references_ids,'')"
	}
	query := fmt.Sprintf(`
SELECT c.name, c.uid_validity, m.rkey, m.uid, m.modseq, m.raw,
       COALESCE(m.message_id,''), m.date,
       COALESCE(m.to_json,'[]'), COALESCE(m.blobs_json,'[]'),
       COALESCE(m.flags_json,'{}'), %s, %s
FROM collections c
JOIN messages m ON m.coll_id=c.coll_id
WHERE c.space_id=? AND m.deleted=0
ORDER BY c.name, m.uid`, inReplyExpr, referencesExpr)
	rows, err := s.db.QueryContext(ctx, query, space.ID)
	if err != nil {
		return fmt.Errorf("stream messages: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			mailboxName, legacyRKey, messageID string
			uid, uidValidity                   uint32
			modSeq                             uint64
			raw                                []byte
			unixDate                           int64
			toJSON, blobsJSON, flagsJSON       string
			inReplyTo, references              string
		)
		if err := rows.Scan(
			&mailboxName, &uidValidity, &legacyRKey, &uid, &modSeq, &raw,
			&messageID, &unixDate, &toJSON, &blobsJSON, &flagsJSON,
			&inReplyTo, &references,
		); err != nil {
			return fmt.Errorf("scan message: %w", err)
		}
		if len(raw) == 0 {
			return fmt.Errorf("%w: %s/%s has empty RFC 5322 bytes", ErrInvalidSource, mailboxName, legacyRKey)
		}
		if len(raw) > mailbox.MaxRawMessageBytes {
			return fmt.Errorf("%w: %s/%s is %d bytes", mailbox.ErrMessageTooLarge, mailboxName, legacyRKey, len(raw))
		}
		if !json.Valid([]byte(toJSON)) || !json.Valid([]byte(blobsJSON)) || !json.Valid([]byte(flagsJSON)) {
			return fmt.Errorf("%w: %s/%s has malformed JSON columns", ErrInvalidSource, mailboxName, legacyRKey)
		}
		var flags legacyFlags
		if err := json.Unmarshal([]byte(flagsJSON), &flags); err != nil {
			return fmt.Errorf("%w: decode flags for %s/%s: %v", ErrInvalidSource, mailboxName, legacyRKey, err)
		}
		keywords := flags.keywords()
		imported := mailbox.ImportedMessage{
			RecipientDID:  space.User,
			SourceKey:     "legacy:" + legacyRKey,
			Raw:           append([]byte(nil), raw...),
			Mailbox:       mailboxName,
			MessageID:     messageID,
			InReplyTo:     strings.TrimSpace(inReplyTo),
			References:    strings.Fields(references),
			Keywords:      keywords,
			DeletePending: flags.Deleted,
			UID:           uid,
			UIDValidity:   uidValidity,
			ModSeq:        modSeq,
		}
		if unixDate > 0 {
			imported.MessageDate = time.Unix(unixDate, 0).UTC()
		}
		if err := visit(SourceMessage{LegacyRKey: legacyRKey, Role: folderRole(mailboxName), Imported: imported}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *Snapshot) validateSchema() error {
	required := map[string][]string{
		"spaces":      {"space_id", "owner", "type", "key", "user", "modseq"},
		"collections": {"coll_id", "space_id", "name", "uid_validity", "next_uid"},
		"messages": {
			"coll_id", "rkey", "uid", "modseq", "deleted", "raw", "message_id",
			"to_json", "date", "blobs_json", "flags_json",
		},
	}
	for table, columns := range required {
		found, err := tableColumns(s.db, table)
		if err != nil {
			return fmt.Errorf("%w: inspect %s schema: %v", ErrInvalidSource, table, err)
		}
		for _, column := range columns {
			if !found[column] {
				return fmt.Errorf("%w: %s.%s is missing", ErrInvalidSource, table, column)
			}
		}
		if table == "messages" {
			s.messageColumns = found
		}
	}
	return nil
}

func tableColumns(db *sql.DB, table string) (map[string]bool, error) {
	switch table {
	case "spaces", "collections", "messages":
	default:
		return nil, fmt.Errorf("refuse unknown schema table %q", table)
	}
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]bool)
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &colType, &notNull, &defaultValue, &primaryKey); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

type legacyFlags struct {
	Seen     bool
	Flagged  bool
	Answered bool
	Draft    bool
	Deleted  bool
}

func (f legacyFlags) keywords() []string {
	var values []string
	if f.Seen {
		values = append(values, "$seen")
	}
	if f.Flagged {
		values = append(values, "$flagged")
	}
	if f.Answered {
		values = append(values, "$answered")
	}
	if f.Draft {
		values = append(values, "$draft")
	}
	sort.Strings(values)
	return values
}

func folderRole(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "inbox":
		return "inbox"
	case "archive", "all mail":
		return "archive"
	case "drafts", "draft":
		return "drafts"
	case "sent", "sent items", "sent mail":
		return "sent"
	case "junk", "spam":
		return "junk"
	case "trash", "deleted items":
		return "trash"
	case "important":
		return "important"
	default:
		return ""
	}
}

func validSpaceKey(key string) bool {
	if key == "" || len(key) > 512 || strings.ContainsAny(key, "/?# ") {
		return false
	}
	return true
}

func validateSpace(space Space) error {
	if space.ID <= 0 || !strings.HasPrefix(space.Owner, "did:") || space.Owner != space.User || space.Type != mailbox.MailboxSpaceType || !validSpaceKey(space.Key) {
		return fmt.Errorf("%w: invalid exact space binding", ErrInvalidSource)
	}
	return nil
}
