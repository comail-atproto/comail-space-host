package vandelayimport

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/comail-atproto/comail-pds-lab/internal/mailbox"
	"github.com/comail-atproto/comail-pds-lab/internal/sqliteimport"
	"lukechampine.com/blake3"

	_ "modernc.org/sqlite"
)

var (
	ErrInconsistentArchive = errors.New("vandelayimport: archive has SQLite sidecars and may be inconsistent")
	ErrInvalidArchive      = errors.New("vandelayimport: invalid archive")
)

type Snapshot struct {
	path string
	db   *sql.DB
}

type folderRow struct {
	id     int64
	name   string
	parent *int64
	role   string
	path   string
}

func Open(path string) (*Snapshot, error) {
	resolved, err := filepath.EvalSymlinks(strings.TrimSpace(path))
	if err != nil {
		return nil, fmt.Errorf("%w: resolve archive: %v", ErrInvalidArchive, err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		return nil, fmt.Errorf("%w: absolute archive: %v", ErrInvalidArchive, err)
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: archive must be a regular file", ErrInvalidArchive)
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if sidecar, statErr := os.Stat(resolved + suffix); statErr == nil && sidecar.Size() > 0 {
			return nil, fmt.Errorf("%w: %s exists", ErrInconsistentArchive, filepath.Base(resolved+suffix))
		} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: inspect sidecar: %v", ErrInvalidArchive, statErr)
		}
	}
	u := &url.URL{Scheme: "file", Path: filepath.ToSlash(resolved)}
	db, err := sql.Open("sqlite", u.String()+"?mode=ro&immutable=1&_pragma=query_only(1)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("%w: open read-only: %v", ErrInvalidArchive, err)
	}
	db.SetMaxOpenConns(1)
	s := &Snapshot{path: resolved, db: db}
	if err := s.validateSchema(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Snapshot) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}
func (s *Snapshot) Path() string { return s.path }

func (s *Snapshot) Inspect(ctx context.Context, did, spaceKey string) (sqliteimport.Inventory, error) {
	var inv sqliteimport.Inventory
	if !strings.HasPrefix(did, "did:") || strings.TrimSpace(spaceKey) == "" {
		return inv, fmt.Errorf("%w: exact DID and space key required", ErrInvalidArchive)
	}
	var sources int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sources`).Scan(&sources); err != nil || sources != 1 {
		return inv, fmt.Errorf("%w: expected exactly one source account", ErrInvalidArchive)
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM mailboxes`).Scan(&inv.Folders); err != nil {
		return inv, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(length(b.data)),0), COALESCE(SUM(CASE WHEN length(b.data)>? THEN 1 ELSE 0 END),0) FROM emails e JOIN blobs b ON b.id=e.blob_id`, mailbox.MaxRawMessageBytes).Scan(&inv.LiveMessages, &inv.LiveBytes, &inv.OversizeMessages); err != nil {
		return inv, err
	}
	inv.Space = sqliteimport.Space{ID: 1, Owner: did, Type: mailbox.MailboxSpaceType, Key: spaceKey, User: did, ModSeq: 1}
	return inv, nil
}

func (s *Snapshot) Folders(ctx context.Context, space sqliteimport.Space) ([]sqliteimport.SourceFolder, error) {
	rows, byID, err := s.folderRows(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]sqliteimport.SourceFolder, 0, len(rows))
	seenPaths := map[string]bool{}
	for _, row := range rows {
		path, err := resolvePath(row.id, byID, nil)
		if err != nil {
			return nil, err
		}
		if len(path) > 255 || len(row.role) > 64 || seenPaths[path] {
			return nil, fmt.Errorf("%w: invalid or duplicate mailbox path", ErrInvalidArchive)
		}
		seenPaths[path] = true
		uidValidity := mailbox.StableUIDValidity(space.User, path)
		out = append(out, sqliteimport.SourceFolder{Name: path, Role: row.role, UIDValidity: uidValidity, NextUID: 1, Folder: mailbox.NewFolder(path, row.role, uidValidity)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Snapshot) Stream(ctx context.Context, space sqliteimport.Space, visit func(sqliteimport.SourceMessage) error) error {
	if visit == nil {
		return fmt.Errorf("%w: message visitor required", ErrInvalidArchive)
	}
	_, byID, err := s.folderRows(ctx)
	if err != nil {
		return err
	}
	sourceKeys, err := s.emailSourceKeys(ctx)
	if err != nil {
		return err
	}
	var sourceKind string
	if err := s.db.QueryRowContext(ctx, `SELECT kind FROM sources`).Scan(&sourceKind); err != nil {
		return fmt.Errorf("%w: read source kind", ErrInvalidArchive)
	}
	requireStableJMAPID := strings.EqualFold(strings.TrimSpace(sourceKind), "jmap")
	rows, err := s.db.QueryContext(ctx, `SELECT e.id,b.hash,b.data,e.received_at,e.mailbox_ids,e.keywords FROM emails e JOIN blobs b ON b.id=e.blob_id ORDER BY e.id`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var storedHash, raw []byte
		var receivedAt, mailboxJSON, keywordJSON string
		if err := rows.Scan(&id, &storedHash, &raw, &receivedAt, &mailboxJSON, &keywordJSON); err != nil {
			return err
		}
		hash := blake3.Sum256(raw)
		if len(storedHash) != len(hash) || !equalBytes(storedHash, hash[:]) {
			return fmt.Errorf("%w: blob hash mismatch for archive email %d", mailbox.ErrIntegrity, id)
		}
		if len(raw) == 0 || len(raw) > mailbox.MaxRawMessageBytes {
			return fmt.Errorf("%w: invalid message size for archive email %d", ErrInvalidArchive, id)
		}
		var folderIDs []int64
		var keywords []string
		if json.Unmarshal([]byte(mailboxJSON), &folderIDs) != nil || len(folderIDs) == 0 || json.Unmarshal([]byte(keywordJSON), &keywords) != nil {
			return fmt.Errorf("%w: malformed membership for archive email %d", ErrInvalidArchive, id)
		}
		paths := make([]string, 0, len(folderIDs))
		seen := map[string]bool{}
		for _, folderID := range folderIDs {
			path, pathErr := resolvePath(folderID, byID, nil)
			if pathErr != nil {
				return pathErr
			}
			if !seen[path] {
				seen[path] = true
				paths = append(paths, path)
			}
		}
		sort.Strings(paths)
		delivered, err := time.Parse(time.RFC3339Nano, receivedAt)
		if err != nil {
			return fmt.Errorf("%w: invalid received_at for archive email %d", ErrInvalidArchive, id)
		}
		messageID, messageDate, inReplyTo, references, err := headerMetadata(raw)
		if err != nil {
			return fmt.Errorf("%w: malformed RFC 5322 message for archive email %d", ErrInvalidArchive, id)
		}
		sourceKey := sourceKeys[id]
		if sourceKey == "" && requireStableJMAPID {
			return fmt.Errorf("%w: JMAP archive email %d lacks a stable source id", ErrInvalidArchive, id)
		}
		if sourceKey == "" {
			sourceKey = fmt.Sprintf("vandelay-local:%d", id)
		}
		imported := mailbox.ImportedMessage{RecipientDID: space.User, SourceKey: sourceKey, Raw: append([]byte(nil), raw...), Mailbox: paths[0], Mailboxes: paths, MessageID: messageID, MessageDate: messageDate, InReplyTo: inReplyTo, References: references, Keywords: keywords, DeliveredAt: delivered}
		if err := visit(sqliteimport.SourceMessage{LegacyRKey: sourceKey, Imported: imported}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *Snapshot) emailSourceKeys(ctx context.Context) (map[int64]string, error) {
	out := map[int64]string{}
	var present int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sync_id_jmap'`).Scan(&present); err != nil {
		return nil, err
	}
	if present == 0 {
		return out, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT local_id,jmap_id FROM sync_id_jmap WHERE type_name='Email' ORDER BY local_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var localID int64
		var jmapID string
		if err := rows.Scan(&localID, &jmapID); err != nil {
			return nil, err
		}
		jmapID = strings.TrimSpace(jmapID)
		if jmapID == "" {
			return nil, fmt.Errorf("%w: empty JMAP email source id", ErrInvalidArchive)
		}
		key := "jmap:" + jmapID
		if len(key) > 512 {
			return nil, fmt.Errorf("%w: JMAP email source id is too long", ErrInvalidArchive)
		}
		if out[localID] != "" {
			return nil, fmt.Errorf("%w: duplicate JMAP source mapping", ErrInvalidArchive)
		}
		out[localID] = key
	}
	return out, rows.Err()
}

func (s *Snapshot) validateSchema() error {
	for table, columns := range map[string][]string{"sources": {"id", "kind", "session_url", "account_id", "account_name", "username"}, "blobs": {"id", "hash", "data"}, "mailboxes": {"id", "name", "parent_id", "role", "sort_order", "is_subscribed"}, "emails": {"id", "blob_id", "received_at", "mailbox_ids", "keywords", "message_match"}} {
		rows, err := s.db.Query(`SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			return fmt.Errorf("%w: inspect %s schema", ErrInvalidArchive, table)
		}
		got := map[string]bool{}
		for rows.Next() {
			var name string
			if rows.Scan(&name) != nil {
				_ = rows.Close()
				return ErrInvalidArchive
			}
			got[name] = true
		}
		_ = rows.Close()
		for _, column := range columns {
			if !got[column] {
				return fmt.Errorf("%w: missing %s.%s", ErrInvalidArchive, table, column)
			}
		}
	}
	return nil
}

func (s *Snapshot) folderRows(ctx context.Context) ([]folderRow, map[int64]folderRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,parent_id,COALESCE(role,'') FROM mailboxes ORDER BY id`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var out []folderRow
	byID := map[int64]folderRow{}
	for rows.Next() {
		var r folderRow
		var parent sql.NullInt64
		if err := rows.Scan(&r.id, &r.name, &parent, &r.role); err != nil {
			return nil, nil, err
		}
		r.name = strings.TrimSpace(r.name)
		if r.name == "" {
			return nil, nil, fmt.Errorf("%w: empty mailbox name", ErrInvalidArchive)
		}
		if parent.Valid {
			p := parent.Int64
			r.parent = &p
		}
		out = append(out, r)
		byID[r.id] = r
	}
	return out, byID, rows.Err()
}

func resolvePath(id int64, byID map[int64]folderRow, stack map[int64]bool) (string, error) {
	r, ok := byID[id]
	if !ok {
		return "", fmt.Errorf("%w: unknown mailbox id %d", ErrInvalidArchive, id)
	}
	if stack == nil {
		stack = map[int64]bool{}
	}
	if stack[id] {
		return "", fmt.Errorf("%w: mailbox parent cycle", ErrInvalidArchive)
	}
	stack[id] = true
	defer delete(stack, id)
	if r.parent == nil {
		return r.name, nil
	}
	parent, err := resolvePath(*r.parent, byID, stack)
	if err != nil {
		return "", err
	}
	return parent + "/" + r.name, nil
}

func headerMetadata(raw []byte) (string, time.Time, string, []string, error) {
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return "", time.Time{}, "", nil, err
	}
	messageID := strings.TrimSpace(m.Header.Get("Message-ID"))
	inReplyTo := strings.TrimSpace(m.Header.Get("In-Reply-To"))
	references := strings.Fields(m.Header.Get("References"))
	date, _ := mail.ParseDate(m.Header.Get("Date"))
	return messageID, date.UTC(), inReplyTo, references, nil
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}
